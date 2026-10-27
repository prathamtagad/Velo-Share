/**
 * Velo - Production-Grade P2P File Transfer (PeerJS / WebRTC)
 * 
 * Features:
 * - STUN/TURN ICE Traversal with custom credential support
 * - Resilient PeerJS Signaling with exponential backoff & collision recovery
 * - Explicit Connection State Machine (idle, connecting, connected, disconnected, failed, closing)
 * - Race-proof duplicate connection prevention & deterministic tie-breaking
 * - Globally unique UUIDs for transfers, speed tests, and tokens
 * - Per-peer transfer isolation (multi-peer broadcasts with independent progress/errors)
 * - Binary chunk framing (44-byte header with sequence numbers and UUIDs)
 * - SHA-256 cryptographic file integrity verification
 * - Full Acknowledgement Protocol (START -> CHUNKS -> END -> VERIFY -> ACK -> COMPLETE)
 * - Event-driven DataChannel backpressure & flow control
 * - Queue deadlock elimination with strict try/finally cleanup
 * - True transfer cancellation with FileReader abort & peer notification
 * - Safe broadcast peer selection (zero selected peers never sends to everyone)
 * - Per-peer isolated speed tests
 * - 100% XSS-hardened DOM manipulation (zero unsafe innerHTML with untrusted data)
 * - Dynamic origin share links & QR codes
 * - Comprehensive console diagnostics (velo.getDiagnostics())
 */

// ==================== PROTOCOL CONSTANTS ====================

const ProtocolConstants = {
    MAGIC_0: 0x56, // 'V'
    MAGIC_1: 0x4C, // 'L'
    // v2: consent handshake (file-accept), mandatory sha256, v4-strict UUIDs,
    // exact chunk-length bounds. v1 peers cannot interoperate with v2 peers.
    VERSION: 2,
    UUID_LENGTH: 36,
    HEADER_SIZE: 44, // 2 (magic) + 1 (ver) + 1 (uuidLen) + 36 (uuid) + 4 (seq Uint32)
    MAX_FILE_SIZE: 2 * 1024 * 1024 * 1024, // 2GB protocol ceiling (see README for per-mode limits)
    DEFAULT_CHUNK_SIZE: 512 * 1024, // 512KB
    MIN_CHUNK_SIZE: 128 * 1024, // 128KB
    MAX_CHUNK_SIZE: 1024 * 1024, // 1MB
    BACKPRESSURE_HIGH_WATERMARK: 1024 * 1024, // 1MB
    BACKPRESSURE_LOW_WATERMARK: 256 * 1024, // 256KB
    CONNECTION_TIMEOUT_MS: 15000,
    SPEED_TEST_TIMEOUT_MS: 10000,
    MAX_RECONNECT_ATTEMPTS: 5,
    MAX_TEXT_SHARE_CHARS: 50000,
    MAX_CONCURRENT_RECEIVES: 3,        // per peer
    MAX_ACTIVE_RECEIVES_TOTAL: 8,      // global across all peers
    MAX_AGGREGATE_RECEIVE_BUFFER: 512 * 1024 * 1024, // total bytes buffered across receives
    MAX_CONNECTIONS: 16,               // concurrent peer connections
    MAX_QUEUED_FILES: 50,
    RECEIVE_IDLE_TIMEOUT_MS: 30000,    // no chunk progress for 30s -> stall cleanup
    CONSENT_TIMEOUT_MS: 60000,         // unanswered incoming-file consent -> auto-decline
    FILE_ACCEPT_TIMEOUT_MS: 60000,     // sender gives up on receivers that never accept
    TEXT_SHARE_LINK_TTL_MS: 10 * 60000, // one-time text share link validity
    CONTROL_MSG_LIMIT: 150,            // JSON control messages per rate window per peer
    CHUNK_MSG_LIMIT: 4000,             // binary chunks per rate window per peer
    PING_MSG_LIMIT: 12,                // speed-test pings per rate window per peer
    RATE_WINDOW_MS: 5000,
    RATE_LIMIT_STRIKES: 3,             // consecutive flooded windows -> disconnect peer
    MAX_INBOUND_PER_MINUTE: 10,        // inbound connection attempts per minute
    ACK_TIMEOUT_MIN_MS: 30000,     // 30 seconds minimum
    ACK_TIMEOUT_MAX_MS: 300000,    // 5 minutes maximum
    ACK_TIMEOUT_THROUGHPUT_ESTIMATE: 15 * 1024 * 1024  // 15 MB/s assumed baseline
};

// ==================== BINARY CHUNK FRAMING ====================

/**
 * Packs a file slice into a binary framed chunk.
 * 
 * Header layout (44 bytes):
 * [0..1] Magic bytes: 0x56, 0x4C ('VL')
 * [2]    Version: 0x01
 * [3]    UUID length: 36
 * [4..39] Transfer UUID (ASCII)
 * [40..43] Sequence Number (Uint32 Big-Endian)
 * [44..] Payload bytes
 */
function packChunk(transferId, sequenceNumber, payloadBuffer) {
    const payloadBytes = payloadBuffer instanceof Uint8Array 
        ? payloadBuffer 
        : new Uint8Array(payloadBuffer);
    
    const buffer = new Uint8Array(ProtocolConstants.HEADER_SIZE + payloadBytes.byteLength);
    const view = new DataView(buffer.buffer);

    // Magic & version
    buffer[0] = ProtocolConstants.MAGIC_0;
    buffer[1] = ProtocolConstants.MAGIC_1;
    buffer[2] = ProtocolConstants.VERSION;
    buffer[3] = ProtocolConstants.UUID_LENGTH;

    // UUID (36 ASCII bytes)
    for (let i = 0; i < 36; i++) {
        buffer[4 + i] = transferId.charCodeAt(i) || 0;
    }

    // Sequence number (Uint32 Big-Endian)
    view.setUint32(40, sequenceNumber, false);

    // Payload
    buffer.set(payloadBytes, ProtocolConstants.HEADER_SIZE);

    return buffer.buffer;
}

/**
 * Unpacks a binary framed chunk.
 * Returns null if the header is invalid.
 */
function unpackChunk(arrayBuffer) {
    if (!arrayBuffer || arrayBuffer.byteLength < ProtocolConstants.HEADER_SIZE) {
        return null;
    }

    const buffer = arrayBuffer instanceof Uint8Array 
        ? arrayBuffer 
        : new Uint8Array(arrayBuffer);
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

    // Verify magic & version
    if (buffer[0] !== ProtocolConstants.MAGIC_0 || 
        buffer[1] !== ProtocolConstants.MAGIC_1 || 
        buffer[2] !== ProtocolConstants.VERSION ||
        buffer[3] !== ProtocolConstants.UUID_LENGTH) {
        return null;
    }

    // Extract UUID
    let transferId = '';
    for (let i = 0; i < 36; i++) {
        transferId += String.fromCharCode(buffer[4 + i]);
    }

    // Extract sequence number
    const sequenceNumber = view.getUint32(40, false);

    // Extract payload slice
    const payload = new Uint8Array(buffer.buffer, buffer.byteOffset + ProtocolConstants.HEADER_SIZE, buffer.byteLength - ProtocolConstants.HEADER_SIZE);

    return {
        transferId,
        sequenceNumber,
        payload
    };
}

// ==================== CRYPTOGRAPHIC INTEGRITY ====================

/**
 * Computes SHA-256 hex digest for a Blob or ArrayBuffer using Web Crypto.
 */
async function computeSha256(data) {
    let arrayBuffer;
    if (typeof Blob !== 'undefined' && data instanceof Blob) {
        arrayBuffer = await data.arrayBuffer();
    } else if (ArrayBuffer.isView(data)) {
        arrayBuffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
    } else if (data instanceof ArrayBuffer) {
        arrayBuffer = data;
    } else {
        throw new Error('Unsupported data type for SHA-256 calculation');
    }

    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ==================== UNIQUE ID GENERATOR ====================

/**
 * Cryptographically secure random integers in [0, max).
 * Used everywhere identifiers are generated; Math.random must never be used.
 */
function randomInt(max) {
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        // Rejection sampling to avoid modulo bias
        const limit = Math.floor(0xFFFFFFFF / max) * max;
        const buf = new Uint32Array(1);
        do {
            crypto.getRandomValues(buf);
        } while (buf[0] >= limit);
        return buf[0] % max;
    }
    return Math.floor(Math.random() * max); // Last-resort fallback (non-CSPRNG)
}

function generateUuid() {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) {
        return crypto.randomUUID();
    }
    // RFC4122 v4 compliant fallback using a CSPRNG
    const hex = '0123456789abcdef';
    let out = '';
    for (let i = 0; i < 36; i++) {
        if (i === 8 || i === 13 || i === 18 || i === 23) {
            out += '-';
        } else if (i === 14) {
            out += '4';
        } else if (i === 19) {
            out += hex[(randomInt(16) & 0x3) | 0x8];
        } else {
            out += hex[randomInt(16)];
        }
    }
    return out;
}

// 32-char unambiguous alphabet; ~10 chars gives ~50 bits of entropy.
const PEER_ID_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const PEER_ID_RANDOM_CHARS = 10;

function generatePeerId() {
    let id = 'VELO-';
    for (let i = 0; i < PEER_ID_RANDOM_CHARS; i++) {
        id += PEER_ID_ALPHABET.charAt(randomInt(PEER_ID_ALPHABET.length));
    }
    return id;
}

// ==================== METADATA VALIDATION ====================

// RFC 4122 v4: version nibble must be '4', variant nibble must be 8/9/a/b
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256_REGEX = /^[0-9a-f]{64}$/;

/**
 * Validates incoming file-start metadata from a remote peer.
 * Returns { valid: true, sanitized: {...} } or { valid: false, error: '...', reason: '...' }.
 * All numeric fields must be real JS numbers (no string coercion) and sha256 is mandatory.
 */
function validateFileStartMetadata(data) {
    if (!data || typeof data !== 'object') {
        return { valid: false, error: 'Missing metadata object', reason: 'Missing metadata object' };
    }

    // transferId: standard v4 UUID (version + variant enforced)
    if (typeof data.transferId !== 'string' || !UUID_REGEX.test(data.transferId)) {
        const msg = 'Invalid or missing transferId (must be UUID v4)';
        return { valid: false, error: msg, reason: msg };
    }

    // name: non-empty string, bounded length
    if (typeof data.name !== 'string' || data.name.length === 0 || data.name.length > 512) {
        const msg = 'Invalid filename';
        return { valid: false, error: msg, reason: msg };
    }

    // size: must BE a number (no coercion), finite, non-negative safe integer, bounded
    const size = data.size;
    if (typeof size !== 'number' || !Number.isFinite(size) || size < 0 ||
        size > ProtocolConstants.MAX_FILE_SIZE || !Number.isSafeInteger(size)) {
        const msg = `Invalid file size: ${data.size}`;
        return { valid: false, error: msg, reason: msg };
    }

    // chunkSize: must BE a number, finite, positive safe integer, within protocol bounds
    const chunkSize = data.chunkSize;
    if (typeof chunkSize !== 'number' || !Number.isFinite(chunkSize) ||
        chunkSize < ProtocolConstants.MIN_CHUNK_SIZE ||
        chunkSize > ProtocolConstants.MAX_CHUNK_SIZE || !Number.isSafeInteger(chunkSize)) {
        const msg = `Invalid chunkSize: ${data.chunkSize}`;
        return { valid: false, error: msg, reason: msg };
    }

    // totalChunks: must BE a number, must match Math.ceil(size / chunkSize)
    const totalChunks = data.totalChunks;
    const expectedChunks = size === 0 ? 1 : Math.ceil(size / chunkSize);
    if (typeof totalChunks !== 'number' || !Number.isSafeInteger(totalChunks) ||
        totalChunks < 1 || totalChunks !== expectedChunks) {
        const msg = `totalChunks mismatch: got ${totalChunks}, expected ${expectedChunks}`;
        return { valid: false, error: msg, reason: msg };
    }

    // sha256: MANDATORY — exact 64-character lowercase hex string.
    // A transfer without a verifiable digest is rejected outright (fail closed).
    if (typeof data.sha256 !== 'string' || !SHA256_REGEX.test(data.sha256.toLowerCase())) {
        const msg = 'Missing or malformed SHA-256 digest (mandatory for all transfers)';
        return { valid: false, error: msg, reason: msg };
    }
    const sha256 = data.sha256.toLowerCase();

    return {
        valid: true,
        error: null,
        reason: null,
        sanitized: {
            transferId: data.transferId,
            name: sanitizeFilename(data.name),
            size,
            chunkSize,
            totalChunks,
            sha256
        }
    };
}

/**
 * Computes an adaptive ACK timeout based on file size.
 * Larger files get proportionally longer timeouts.
 * Range: [ACK_TIMEOUT_MIN_MS, ACK_TIMEOUT_MAX_MS]
 */
function computeAdaptiveAckTimeout(fileSize) {
    if (!Number.isFinite(fileSize) || fileSize <= 0) {
        return ProtocolConstants.ACK_TIMEOUT_MIN_MS;
    }
    const estimatedTransferTimeSec = fileSize / ProtocolConstants.ACK_TIMEOUT_THROUGHPUT_ESTIMATE;
    const computedMs = ProtocolConstants.ACK_TIMEOUT_MIN_MS + (estimatedTransferTimeSec * 1000);
    return Math.min(ProtocolConstants.ACK_TIMEOUT_MAX_MS, Math.max(ProtocolConstants.ACK_TIMEOUT_MIN_MS, Math.round(computedMs)));
}

// ==================== SANITIZATION & DOM HELPERS ====================

const WINDOWS_RESERVED_NAMES = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/;
const MAX_FILENAME_LENGTH = 200;

/**
 * Produces a safe download filename:
 * - strips control characters (0x00-0x1F, 0x7F)
 * - replaces path separators and Windows-illegal characters
 * - strips leading dots (traversal / hidden files) and trailing dots/spaces (Windows)
 * - guards Windows reserved device names
 * - ordinary ".." inside a name is preserved (harmless once separators are gone)
 * - truncates long names while preserving the extension
 */
function sanitizeFilename(filename) {
    if (typeof filename !== 'string') return 'unknown_file';

    let name = filename
        .replace(/[\x00-\x1F\x7F]/g, '')
        .replace(/[/\\<>:"|?*]/g, '_')
        .trim();

    name = name.replace(/^\.+/, '').replace(/[. ]+$/, '') || 'unnamed_file';

    if (WINDOWS_RESERVED_NAMES.test(name.split('.')[0].toUpperCase())) {
        name = '_' + name;
    }

    if (name.length > MAX_FILENAME_LENGTH) {
        const dot = name.lastIndexOf('.');
        const ext = dot > 0 ? name.slice(dot) : '';
        name = name.slice(0, MAX_FILENAME_LENGTH - ext.length) + ext;
    }

    return name;
}

/**
 * Unicode-aware username sanitizer. Keeps letters/numbers from any script
 * (e.g. Hindi, Japanese), whitespace, dashes and underscores; strips control
 * characters and everything else. Non-string input never throws.
 */
function sanitizeUsername(raw) {
    if (typeof raw !== 'string') return 'Peer';
    return raw
        .replace(/[\x00-\x1F\x7F]/g, '')
        .replace(/[^\p{L}\p{N}\s\-_]/gu, '')
        .trim()
        .slice(0, 32) || 'Peer';
}

function sanitizeText(text) {
    if (typeof text !== 'string') return String(text ?? '');
    return text.slice(0, ProtocolConstants.MAX_TEXT_SHARE_CHARS);
}

// ==================== LOGGER & OBSERVABILITY ====================

class VeloLogger {
    constructor() {
        this.debugEnabled = false;
        try {
            const params = new URLSearchParams(window.location.search);
            this.debugEnabled = params.has('debug') || localStorage.getItem('velo_debug') === 'true';
        } catch (e) {}
    }

    log(...args) {
        if (this.debugEnabled) {
            console.log(`[Velo ${new Date().toISOString().slice(11, 19)}]`, ...args);
        }
    }

    info(...args) {
        console.info(`[Velo]`, ...args);
    }

    warn(...args) {
        console.warn(`[Velo]`, ...args);
    }

    error(...args) {
        console.error(`[Velo ERROR]`, ...args);
    }
}

const logger = new VeloLogger();

// ==================== MAIN VELO APPLICATION ====================

class VeloApp {
    constructor() {
        logger.info('Initializing VeloApp...');

        this.peer = null;
        this.myPeerId = null;
        this.myUsername = '';
        this.isHost = false;

        // Signaling lifecycle
        this.signalingState = 'uninitialized'; // 'uninitialized' | 'connecting' | 'open' | 'disconnected' | 'closed'
        this.reconnectAttempts = 0;
        this.reconnectTimer = null;
        this.peerGeneration = 0; // Epoch counter to ignore stale PeerJS callbacks

        // Connections maps:
        // peerId -> { conn, username, state, connectedAt, peerConnection, candidateType }
        this.connections = new Map();
        // peerId -> { conn, timeoutId, startedAt }
        this.pendingConnections = new Map();

        // Multi-Peer File Transfer State
        // transferId -> { id, file, name, size, totalChunks, chunkSize, sha256, queueId, peers: Map<peerId, { status, transferred, ackReceived, error, lastUpdate, lastBytes }> }
        this.activeSends = new Map();

        // Receiver Transfer State
        // compositeKey (peerId:transferId) -> { transferId, peerId, name, size, totalChunks, chunkSize, sha256, chunks: Array<Uint8Array>, receivedBytes, receivedChunks: Set<number>, startTime, lastUpdate, lastBytes }
        this.activeReceives = new Map();

        // Queue Management
        this.queuedFiles = []; // { id, file, status: 'pending'|'sending'|'completed'|'failed'|'cancelled', priority, addedAt }
        this.isSending = false;
        this.isPaused = false;
        this.queueIdCounter = 0;

        // Multi-Peer Broadcasting Selection
        this.selectedPeers = new Set();
        this.broadcastMode = 'all'; // 'all' | 'selected'

        // Per-Peer Speed Tests
        // peerId -> { testId, pingResolve, uploadResolve, expectingTestData, timer }
        this.activeSpeedTests = new Map();
        this.peerSpeedResults = new Map(); // peerId -> { latency, uploadSpeed, downloadSpeed, timestamp }

        // Adaptive Chunk Sizing & Stats
        this.currentChunkSize = ProtocolConstants.DEFAULT_CHUNK_SIZE;
        this.totalBytesTransferred = 0;
        this.peakSpeed = 0;
        this.speedInterval = null;

        // Housekeeping sweep (receive idle timeout + consent expiry)
        this.sweepInterval = null;

        // Consent / abuse controls
        // compositeKey -> { peerId, transferId, meta, requestedAt }
        this.pendingConsents = new Map();
        this.blockedPeers = new Set(); // persisted (best-effort) in localStorage
        // peerId -> { windowStart, controlCount, chunkCount, pingCount, strikes }
        this.rateLimits = new Map();
        this.inboundAttemptTimestamps = []; // inbound connection rate limiting

        // Text Sharing
        // Direct sends are fire-and-forget to the current target set — never
        // retained for future peers.
        // activeTextLink: one-time token for link-based sharing:
        // { token, text, expiresAt, used }
        this.activeTextLink = null;
        this.textShareTokenFromUrl = null;

        // Audio Context (lazy init)
        this.audioCtx = null;

        this.loadBlockedPeers();
        this.initElements();
        this.bindEvents();
        this.initNewFeatures();

        // Expose debug instance on window
        window.velo = this;
        window.veloDiagnostics = () => this.getDiagnostics();
    }

    // ==================== UI INITIALIZATION ====================

    initElements() {
        // Screens
        this.landingScreen = document.getElementById('landingScreen');
        this.roomScreen = document.getElementById('roomScreen');

        // Host / Join Inputs
        this.hostNameInput = document.getElementById('hostNameInput');
        this.hostBtn = document.getElementById('hostBtn');
        this.joinNameInput = document.getElementById('joinNameInput');
        this.peerIdInput = document.getElementById('peerIdInput');
        this.joinBtn = document.getElementById('joinBtn');

        // Room Elements
        this.myPeerIdDisplay = document.getElementById('myPeerId');
        this.copyPeerIdBtn = document.getElementById('copyPeerId');
        this.connectionStatus = document.getElementById('connectionStatus');
        this.disconnectBtn = document.getElementById('disconnectBtn');
        this.peerList = document.getElementById('peerList');

        // Stats
        this.liveSpeedEl = document.getElementById('liveSpeed');
        this.peakSpeedEl = document.getElementById('peakSpeedStat');
        this.queueStatsEl = document.getElementById('queueStats');

        // Transfer Area
        this.dropZone = document.getElementById('dropZone');
        this.fileInput = document.getElementById('fileInput');
        this.transferQueue = document.getElementById('transferQueue');
        this.toastContainer = document.getElementById('toastContainer');

        // Control Buttons
        this.pauseQueueBtn = document.getElementById('pauseQueueBtn');
        this.clearQueueBtn = document.getElementById('clearQueueBtn');
        this.showQrBtn = document.getElementById('showQrBtn');
        this.shareBtn = document.getElementById('shareBtn');
        this.shareTextBtn = document.getElementById('shareTextBtn');
        this.networkSettingsBtn = document.getElementById('networkSettingsBtn');
        this.landingNetworkBtn = document.getElementById('landingNetworkBtn');
    }

    bindEvents() {
        // Host
        if (this.hostBtn) {
            this.hostBtn.addEventListener('click', () => this.startHosting());
        }
        if (this.hostNameInput) {
            this.hostNameInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') this.startHosting();
            });
        }

        // Join
        if (this.joinBtn) {
            this.joinBtn.addEventListener('click', () => this.joinPeer());
        }
        if (this.peerIdInput) {
            this.peerIdInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') this.joinPeer();
            });
            this.peerIdInput.addEventListener('input', (e) => {
                e.target.value = e.target.value.toUpperCase();
            });
        }

        // Room Header
        if (this.copyPeerIdBtn) {
            this.copyPeerIdBtn.addEventListener('click', () => {
                if (!this.myPeerId) return;
                navigator.clipboard.writeText(this.myPeerId)
                    .then(() => this.showToast('Peer ID copied to clipboard!', 'success'))
                    .catch(() => this.showToast('Failed to copy ID', 'error'));
            });
        }

        if (this.disconnectBtn) {
            this.disconnectBtn.addEventListener('click', () => this.disconnect());
        }

        // Drop Zone & File Input
        if (this.dropZone) {
            this.dropZone.addEventListener('click', () => this.fileInput && this.fileInput.click());
            this.dropZone.addEventListener('dragover', (e) => {
                e.preventDefault();
                this.dropZone.classList.add('dragover');
            });
            this.dropZone.addEventListener('dragleave', (e) => {
                e.preventDefault();
                this.dropZone.classList.remove('dragover');
            });
            this.dropZone.addEventListener('drop', (e) => {
                e.preventDefault();
                this.dropZone.classList.remove('dragover');
                if (e.dataTransfer && e.dataTransfer.files) {
                    this.handleFiles(e.dataTransfer.files);
                }
            });
        }

        if (this.fileInput) {
            this.fileInput.addEventListener('change', (e) => {
                if (e.target.files && e.target.files.length > 0) {
                    this.handleFiles(e.target.files);
                }
                e.target.value = '';
            });
        }

        // Queue Controls
        if (this.pauseQueueBtn) {
            this.pauseQueueBtn.addEventListener('click', () => {
                if (this.isPaused) {
                    this.resumeQueue();
                    this.pauseQueueBtn.textContent = '⏸️';
                    this.pauseQueueBtn.title = 'Pause Queue';
                } else {
                    this.pauseQueue();
                    this.pauseQueueBtn.textContent = '▶️';
                    this.pauseQueueBtn.title = 'Resume Queue';
                }
            });
        }

        if (this.clearQueueBtn) {
            this.clearQueueBtn.addEventListener('click', () => this.clearQueue());
        }

        // QR Code & Share Buttons
        if (this.showQrBtn) {
            this.showQrBtn.addEventListener('click', () => this.showQrCode());
        }
        if (this.shareBtn) {
            this.shareBtn.addEventListener('click', () => this.showShareModal());
        }
        if (this.shareTextBtn) {
            this.shareTextBtn.addEventListener('click', () => this.showTextShareModal());
        }

        // Network Settings
        if (this.networkSettingsBtn) {
            this.networkSettingsBtn.addEventListener('click', () => this.showNetworkSettingsModal());
        }
        if (this.landingNetworkBtn) {
            this.landingNetworkBtn.addEventListener('click', () => this.showNetworkSettingsModal());
        }
    }

    initNewFeatures() {
        // Register Service Worker
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js')
                .then(reg => logger.log('Service Worker registered:', reg.scope))
                .catch(err => logger.warn('Service Worker registration failed:', err));
        }

        // Load profile and URL params
        this.loadProfile();
        this.checkUrlParams();
    }

    checkUrlParams() {
        const params = new URLSearchParams(window.location.search);
        const joinId = params.get('join');
        const textShareToken = params.get('t');

        this.textShareTokenFromUrl = textShareToken ? textShareToken.trim() : null;

        if (joinId && this.peerIdInput) {
            this.peerIdInput.value = joinId.trim().toUpperCase();
            if (this.joinNameInput && !this.joinNameInput.value) {
                this.joinNameInput.focus();
                this.showToast(`Enter your name to connect to ${joinId}`, 'info');
            }
        }
    }

    saveProfile() {
        try {
            localStorage.setItem('velo_username', this.myUsername);
        } catch (e) {}
    }

    loadProfile() {
        try {
            const saved = localStorage.getItem('velo_username');
            if (saved) {
                if (this.hostNameInput) this.hostNameInput.value = saved;
                if (this.joinNameInput) this.joinNameInput.value = saved;
            }
        } catch (e) {}
    }

    // ==================== PEER INITIALIZATION & SIGNALING ====================

    startHosting() {
        const username = this.hostNameInput ? this.hostNameInput.value.trim() : '';
        if (!username) {
            this.showToast('Please enter your name to start hosting', 'error');
            return;
        }

        this.myUsername = username;
        this.saveProfile();
        this.isHost = true;
        this.initPeer();
    }

    joinPeer() {
        const username = this.joinNameInput ? this.joinNameInput.value.trim() : '';
        const targetPeerId = this.peerIdInput ? this.peerIdInput.value.trim().toUpperCase() : '';

        if (!username) {
            this.showToast('Please enter your name', 'error');
            return;
        }
        if (!targetPeerId) {
            this.showToast('Please enter a target Peer ID', 'error');
            return;
        }

        this.myUsername = username;
        this.saveProfile();
        this.isHost = false;
        this.initPeer(targetPeerId);
    }

    /**
     * Initializes the PeerJS instance with robust ICE configuration.
     * Uses generation/epoch tracking so callbacks from destroyed instances are ignored.
     */
    initPeer(targetPeerIdToConnect = null) {
        if (this.peer && !this.peer.destroyed) {
            this.peer.destroy();
            this.peer = null;
        }

        const gen = ++this.peerGeneration;

        const myId = generatePeerId();
        const iceConfig = window.VeloConfig ? window.VeloConfig.getIceConfig() : {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' }
            ]
        };

        logger.info('Initializing PeerJS with ID:', myId, 'ICE servers count:', iceConfig.iceServers.length, 'generation:', gen);

        this.signalingState = 'connecting';
        this.updateStatus('connecting');

        try {
            this.peer = new Peer(myId, {
                debug: logger.debugEnabled ? 2 : 1,
                config: iceConfig
            });
        } catch (err) {
            logger.error('Failed to construct PeerJS instance:', err);
            this.showToast('Failed to initialize P2P engine. Check browser settings.', 'error');
            return;
        }

        // ==================== PEER SIGNALING EVENTS ====================

        this.peer.on('open', (id) => {
            if (this.peerGeneration !== gen) { logger.log('Ignoring stale open callback from generation', gen); return; }
            logger.info('PeerJS signaling OPEN with ID:', id);
            this.myPeerId = id;
            this.signalingState = 'open';
            this.reconnectAttempts = 0;

            if (this.reconnectTimer) {
                clearTimeout(this.reconnectTimer);
                this.reconnectTimer = null;
            }

            if (this.myPeerIdDisplay) {
                this.myPeerIdDisplay.textContent = id;
            }

            this.showRoomScreen();
            this.updateStatus(this.connections.size > 0 ? 'connected' : 'ready');
            this.startSpeedTracking();

            // Auto-connect to target if specified in Join flow
            if (targetPeerIdToConnect) {
                this.connectToPeer(targetPeerIdToConnect);
            }
        });

        this.peer.on('connection', (conn) => {
            if (this.peerGeneration !== gen) { logger.log('Ignoring stale connection callback from generation', gen); return; }
            logger.info('Incoming peer connection request from:', conn.peer);
            this.handleIncomingConnection(conn);
        });

        this.peer.on('disconnected', () => {
            if (this.peerGeneration !== gen) { logger.log('Ignoring stale disconnected callback from generation', gen); return; }
            logger.warn('PeerJS signaling disconnected from server.');
            this.signalingState = 'disconnected';
            this.updateStatus(this.connections.size > 0 ? 'connected' : 'disconnected');
            this.attemptSignalingReconnect();
        });

        this.peer.on('close', () => {
            if (this.peerGeneration !== gen) { logger.log('Ignoring stale close callback from generation', gen); return; }
            logger.warn('PeerJS signaling permanently closed.');
            this.signalingState = 'closed';
            this.updateStatus('disconnected');
        });

        this.peer.on('error', (err) => {
            if (this.peerGeneration !== gen) { logger.log('Ignoring stale error callback from generation', gen); return; }
            logger.error('PeerJS Signaling Error:', err.type, err.message);

            if (err.type === 'unavailable-id') {
                logger.warn('Peer ID collision occurred. Retrying with a new ID...');
                this.showToast('ID collision detected. Generating new ID...', 'info');
                setTimeout(() => this.initPeer(targetPeerIdToConnect), 300);
                return;
            }

            if (err.type === 'peer-unavailable') {
                this.showToast('Peer not found. Verify the ID or ensure the user is online.', 'error');
                // Clean up any pending connection with this target
                if (targetPeerIdToConnect && this.pendingConnections.has(targetPeerIdToConnect)) {
                    this.cleanupPendingConnection(targetPeerIdToConnect);
                }
                return;
            }

            if (err.type === 'network' || err.type === 'server-error' || err.type === 'socket-error') {
                this.showToast('Signaling network error. Will retry connecting...', 'error');
                this.attemptSignalingReconnect();
                return;
            }

            if (err.type === 'webrtc') {
                this.showToast('WebRTC negotiation failure. Network may require TURN relay.', 'error');
                return;
            }

            this.showToast(`Connection error: ${err.type || 'unknown'}`, 'error');
        });
    }

    /**
     * Bounded exponential backoff signaling reconnection.
     */
    attemptSignalingReconnect() {
        if (!this.peer || this.peer.destroyed || this.signalingState === 'open') return;

        if (this.reconnectAttempts >= ProtocolConstants.MAX_RECONNECT_ATTEMPTS) {
            logger.warn('Max signaling reconnection attempts reached.');
            this.showToast('Signaling server unreachable. Active peer connections remain active.', 'error');
            return;
        }

        const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 16000);
        this.reconnectAttempts++;

        logger.info(`Scheduling signaling reconnect attempt ${this.reconnectAttempts} in ${delay}ms...`);
        if (this.reconnectTimer) clearTimeout(this.reconnectTimer);

        this.reconnectTimer = setTimeout(() => {
            if (this.peer && !this.peer.destroyed && this.signalingState === 'disconnected') {
                logger.info('Attempting peer.reconnect()...');
                this.peer.reconnect();
            }
        }, delay);
    }

    // ==================== CONNECTION STATE MACHINE & RACE RESOLUTION ====================

    /**
     * Connects to a target peer with timeout and duplicate prevention.
     */
    connectToPeer(peerId) {
        const targetId = (peerId || '').trim().toUpperCase();
        if (!targetId) return;

        // Guard: no live signaling channel to dial out with
        if (!this.peer || this.peer.destroyed) {
            this.showToast('Not connected to the signaling service. Host or join first.', 'error');
            return;
        }
        if (this.signalingState !== 'open') {
            this.showToast('Signaling not ready yet. Wait for a connection or re-host.', 'error');
            return;
        }

        if (targetId === this.myPeerId) {
            this.showToast('Cannot connect to your own Peer ID', 'error');
            return;
        }

        // Peer ID is a routing address, NOT authorization: a blocked peer is
        // refused here and inbound alike.
        if (this.blockedPeers.has(targetId)) {
            this.showToast(`${targetId} is blocked. Unblock it before connecting.`, 'error');
            return;
        }

        // Connection cap
        if (this.connections.size + this.pendingConnections.size >= ProtocolConstants.MAX_CONNECTIONS) {
            this.showToast(`Connection limit reached (${ProtocolConstants.MAX_CONNECTIONS} peers max).`, 'error');
            return;
        }

        // 1. Check if already connected
        if (this.connections.has(targetId)) {
            this.showToast(`Already connected to ${targetId}`, 'info');
            return;
        }

        // 2. Check if a connection is already pending
        if (this.pendingConnections.has(targetId)) {
            this.showToast(`Connection attempt to ${targetId} is already in progress`, 'info');
            return;
        }

        logger.info('Initiating outbound connection to:', targetId);
        this.showToast(`Connecting to ${targetId}...`, 'info');

        // Establish connection with reliable DataChannel semantics
        const conn = this.peer.connect(targetId, {
            reliable: true,
            metadata: {
                username: this.myUsername,
                textShareToken: this.textShareTokenFromUrl
            }
        });

        // Setup 15-second connection timeout
        const timeoutId = setTimeout(() => {
            logger.warn(`Connection timeout expired for peer: ${targetId}`);
            if (this.pendingConnections.has(targetId)) {
                this.cleanupPendingConnection(targetId);
                this.showToast(`Connection to ${targetId} timed out. The user may be offline or blocked by firewall.`, 'error');
            }
        }, ProtocolConstants.CONNECTION_TIMEOUT_MS);

        this.pendingConnections.set(targetId, {
            conn,
            timeoutId,
            startedAt: Date.now()
        });

        this.setupConnectionHandlers(conn, false);
    }

    /**
     * Handles an incoming connection request with tie-breaker resolution.
     */
    handleIncomingConnection(conn) {
        const remotePeerId = conn.peer;
        logger.info('Evaluating incoming connection from:', remotePeerId);

        // 0. Blocked peers are closed immediately (Peer ID is not authorization)
        if (this.blockedPeers.has(remotePeerId)) {
            logger.warn(`Refusing inbound connection from blocked peer ${remotePeerId}.`);
            try { conn.close(); } catch (e) {}
            return;
        }

        // 1. Inbound connection rate limiting (flood protection)
        const now = Date.now();
        this.inboundAttemptTimestamps = this.inboundAttemptTimestamps.filter(t => now - t < 60000);
        if (this.inboundAttemptTimestamps.length >= ProtocolConstants.MAX_INBOUND_PER_MINUTE) {
            logger.warn(`Inbound connection rate limit hit (${ProtocolConstants.MAX_INBOUND_PER_MINUTE}/min). Dropping ${remotePeerId}.`);
            try { conn.close(); } catch (e) {}
            return;
        }
        this.inboundAttemptTimestamps.push(now);

        // 2. Concurrent connection cap
        if (this.connections.size + this.pendingConnections.size >= ProtocolConstants.MAX_CONNECTIONS) {
            logger.warn(`Connection cap (${ProtocolConstants.MAX_CONNECTIONS}) reached. Dropping inbound from ${remotePeerId}.`);
            try { conn.close(); } catch (e) {}
            return;
        }

        // 3. Existing connection: replace it only if it is stale/dead, otherwise
        //    reject the duplicate.
        if (this.connections.has(remotePeerId)) {
            const existing = this.connections.get(remotePeerId);
            const stale = !existing.conn ||
                existing.conn.open === false ||
                (existing.peerConnection && ['failed', 'closed', 'disconnected'].includes(existing.peerConnection.connectionState));

            if (stale) {
                logger.warn(`Replacing stale connection for ${remotePeerId} with refreshed inbound connection.`);
                try { existing.conn.close(); } catch (e) {}
                this.connections.delete(remotePeerId);
            } else {
                logger.warn(`Duplicate connection received from ${remotePeerId}. Closing redundant instance.`);
                try { conn.close(); } catch (e) {}
                return;
            }
        }

        // 2. Simultaneous cross-connection collision detection (both peers called connect at the same time)
        if (this.pendingConnections.has(remotePeerId)) {
            logger.info(`Simultaneous connection collision detected with ${remotePeerId}. Running tie-breaker...`);

            // Deterministic winner: lexicographical comparison of peer IDs
            const iWin = (this.myPeerId || '').localeCompare(remotePeerId) > 0;

            if (iWin) {
                // We keep our outbound connection; reject this inbound connection
                logger.info(`Tie-breaker: My ID wins. Keeping outbound connection to ${remotePeerId}.`);
                conn.close();
                return;
            } else {
                // Remote ID wins; cancel our outbound pending connection and accept this inbound connection
                logger.info(`Tie-breaker: Remote ID wins. Yielding to inbound connection from ${remotePeerId}.`);
                this.cleanupPendingConnection(remotePeerId);
            }
        }

        this.setupConnectionHandlers(conn, true);
    }

    cleanupPendingConnection(peerId) {
        const pending = this.pendingConnections.get(peerId);
        if (pending) {
            clearTimeout(pending.timeoutId);
            try {
                pending.conn.close();
            } catch (e) {}
            this.pendingConnections.delete(peerId);
        }
    }

    /**
     * Configures listeners for a WebRTC DataConnection.
     */
    setupConnectionHandlers(conn, isIncoming) {
        const remotePeerId = conn.peer;

        conn.on('open', () => {
            // A newer connection may have replaced this one while it was
            // negotiating; don't resurrect state for a superseded conn.
            const current = this.connections.get(remotePeerId);
            if (current && current.conn !== conn) {
                logger.warn(`Ignoring open for superseded connection with ${remotePeerId}.`);
                try { conn.close(); } catch (e) {}
                return;
            }

            logger.info(`DataConnection OPEN with: ${remotePeerId} (${isIncoming ? 'inbound' : 'outbound'})`);

            // Clear pending tracking
            if (this.pendingConnections.has(remotePeerId)) {
                clearTimeout(this.pendingConnections.get(remotePeerId).timeoutId);
                this.pendingConnections.delete(remotePeerId);
            }

            // Inspect WebRTC PeerConnection for ICE state diagnostics
            let candidateType = 'unknown';
            const pc = conn.peerConnection;
            if (pc) {
                pc.addEventListener('iceconnectionstatechange', () => {
                    logger.log(`[ICE State: ${remotePeerId}] ${pc.iceConnectionState}`);
                    this.updatePeerDiagnosticState(remotePeerId);
                });
                pc.addEventListener('connectionstatechange', () => {
                    logger.log(`[Connection State: ${remotePeerId}] ${pc.connectionState}`);
                });
            }

            // Type-safe sanitization: a non-string username must not throw here
            const cleanUsername = sanitizeUsername(conn.metadata?.username ?? 'Peer');

            this.connections.set(remotePeerId, {
                conn,
                username: cleanUsername,
                state: 'connected',
                connectedAt: Date.now(),
                peerConnection: pc,
                candidateType: candidateType
            });

            this.updatePeerList();
            this.updateStatus('connected');
            this.playSound('connect');
            this.showToast(`${cleanUsername} connected!`, 'success');

            // Send handshake
            conn.send({
                type: 'handshake',
                username: this.myUsername
            });

            // Deliver one-time link-based text share if this peer presented the
            // exact, unexpired, unused token.
            const receiverToken = typeof conn.metadata?.textShareToken === 'string' ? conn.metadata.textShareToken : null;
            this.deliverTextLinkIfMatched(remotePeerId, receiverToken);

            // Process transfer queue in case files were pending
            this.processTransferQueue();
        });

        conn.on('data', (data) => {
            this.handleData(remotePeerId, data);
        });

        conn.on('close', () => {
            // Only tear down if THIS conn is still the registered one; a stale
            // conn closing must not nuke its replacement.
            const current = this.connections.get(remotePeerId);
            const pending = this.pendingConnections.get(remotePeerId);
            if (current && current.conn === conn) {
                logger.info(`DataConnection CLOSED for peer: ${remotePeerId}`);
                this.handlePeerDisconnect(remotePeerId);
            } else if (pending && pending.conn === conn) {
                this.cleanupPendingConnection(remotePeerId);
            }
        });

        conn.on('error', (err) => {
            logger.error(`DataConnection ERROR with peer ${remotePeerId}:`, err);
            const current = this.connections.get(remotePeerId);
            const pending = this.pendingConnections.get(remotePeerId);
            if (current && current.conn === conn) {
                this.handlePeerDisconnect(remotePeerId, err);
            } else if (pending && pending.conn === conn) {
                this.cleanupPendingConnection(remotePeerId);
            }
        });
    }

    handlePeerDisconnect(peerId, error = null) {
        // Idempotency guard: duplicate close/error events (or stale conns) must
        // not produce duplicate toasts or re-clean live state.
        if (!this.connections.has(peerId) && !this.pendingConnections.has(peerId)) {
            logger.log(`handlePeerDisconnect(${peerId}) called with no registered connection; ignoring.`);
            return;
        }

        // Clean up pending if any
        this.cleanupPendingConnection(peerId);

        const peerInfo = this.connections.get(peerId);
        const username = peerInfo?.username || peerId;

        // Remove from active connections
        this.connections.delete(peerId);
        this.selectedPeers.delete(peerId);
        this.rateLimits.delete(peerId);

        // Auto-decline any pending file consents from this peer
        this.pendingConsents.forEach((consent, key) => {
            if (consent.peerId === peerId) this.declineIncomingTransfer(key, 'Sender disconnected');
        });

        // Clean up any active speed test for this peer
        this.cleanupSpeedTest(peerId, 'Peer disconnected');

        // Handle active send transfers to this peer
        this.activeSends.forEach((transfer, transferId) => {
            const peerState = transfer.peers.get(peerId);
            if (peerState && (peerState.status === 'sending' || peerState.status === 'awaiting-accept')) {
                peerState.status = 'failed';
                peerState.error = 'Peer disconnected during transfer';
                logger.warn(`Transfer ${transferId} to peer ${peerId} failed due to disconnect.`);
            }

            // If all peers for this transfer are finished/failed, complete it
            this.checkTransferCompletion(transferId);
        });

        // Handle active receive transfers from this peer
        this.activeReceives.forEach((receive, key) => {
            if (receive.peerId === peerId) {
                logger.warn(`Receive transfer ${receive.transferId} aborted because sender ${peerId} disconnected.`);
                this.cleanupReceive(key, 'Sender disconnected');
            }
        });

        this.updatePeerList();
        this.updateStatus(this.connections.size > 0 ? 'connected' : 'ready');
        this.showToast(`${username} disconnected`, 'info');
    }

    updatePeerDiagnosticState(peerId) {
        const info = this.connections.get(peerId);
        if (!info || !info.peerConnection) return;

        // Query stats for candidate type (direct vs relay)
        if (info.peerConnection.getStats) {
            info.peerConnection.getStats().then(stats => {
                stats.forEach(report => {
                    if (report.type === 'candidate-pair' && report.state === 'succeeded') {
                        const localCandidate = stats.get(report.localCandidateId);
                        if (localCandidate) {
                            info.candidateType = localCandidate.candidateType; // 'host' | 'srflx' | 'relay'
                        }
                    }
                });
            }).catch(() => {});
        }
    }

    disconnect() {
        logger.info('User initiated disconnect. Closing all connections.');
        this.stopSpeedTracking();
        this.stopSweeping();

        // Invalidate any in-flight PeerJS callbacks
        this.peerGeneration++;
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }

        this.pendingConnections.forEach(pending => {
            clearTimeout(pending.timeoutId);
            try { pending.conn.close(); } catch (e) {}
        });
        this.pendingConnections.clear();

        // Notify peers and settle consent state BEFORE closing their conns
        this.pendingConsents.forEach((_, key) => this.declineIncomingTransfer(key, 'Disconnecting'));
        this.activeSends.forEach((transfer) => {
            if (!transfer.isCancelled) {
                this.notifyPeersOfSendFailure(transfer, 'Sender disconnected');
            }
        });

        this.connections.forEach(({ conn }) => {
            try { conn.close(); } catch (e) {}
        });
        this.connections.clear();

        // Reset transfer & queue state
        this.activeSends.forEach((transfer) => {
            transfer.reader = null;
            transfer.file = null;
        });
        this.activeSends.clear();
        this.activeReceives.forEach((_, key) => this.cleanupReceive(key, 'Disconnecting'));
        this.activeSpeedTests.clear();
        this.rateLimits.clear();
        this.queuedFiles.forEach(item => {
            if (item.status === 'pending' || item.status === 'sending') item.status = 'cancelled';
            item.file = null;
        });
        this.queuedFiles = [];
        this.isSending = false;
        this.isPaused = false;
        this.selectedPeers.clear();
        this.activeTextLink = null;

        if (this.peer) {
            this.peer.destroy();
            this.peer = null;
        }

        this.myPeerId = null;
        this.signalingState = 'closed';
        if (this.myPeerIdDisplay) this.myPeerIdDisplay.textContent = '...';
        if (this.transferQueue) this.transferQueue.textContent = '';
        this.updateQueueUI();
        this.updatePeerList();
        this.showLandingScreen();
    }

    // ==================== PROTOCOL DATA DISPATCHER ====================

    /**
     * Per-peer sliding-window rate limiter. Returns true if the message is
     * allowed; false if it must be dropped. Gross flooding accrues strikes and
     * eventually disconnects the peer.
     */
    checkRateLimit(peerId, kind) {
        const now = Date.now();
        let budget = this.rateLimits.get(peerId);
        if (!budget || now - budget.windowStart >= ProtocolConstants.RATE_WINDOW_MS) {
            budget = budget && budget.strikes > 0
                ? { windowStart: now, controlCount: 0, chunkCount: 0, pingCount: 0, strikes: budget.strikes - 1 }
                : { windowStart: now, controlCount: 0, chunkCount: 0, pingCount: 0, strikes: budget ? budget.strikes : 0 };
            this.rateLimits.set(peerId, budget);
        }

        if (kind === 'chunk') {
            budget.chunkCount++;
            if (budget.chunkCount > ProtocolConstants.CHUNK_MSG_LIMIT) return false;
            return true;
        }

        if (kind === 'ping') {
            budget.pingCount++;
            budget.controlCount++;
            if (budget.pingCount > ProtocolConstants.PING_MSG_LIMIT) return false;
            if (budget.controlCount > ProtocolConstants.CONTROL_MSG_LIMIT) return false;
            return true;
        }

        budget.controlCount++;
        if (budget.controlCount > ProtocolConstants.CONTROL_MSG_LIMIT) return false;
        return true;
    }

    enforceRateLimitStrikes(peerId) {
        const budget = this.rateLimits.get(peerId);
        if (!budget) return;
        const flooded = budget.controlCount > ProtocolConstants.CONTROL_MSG_LIMIT ||
            budget.chunkCount > ProtocolConstants.CHUNK_MSG_LIMIT;
        if (flooded) {
            budget.strikes++;
            if (budget.strikes >= ProtocolConstants.RATE_LIMIT_STRIKES) {
                logger.warn(`Peer ${peerId} disconnected: persistent protocol message flood.`);
                this.showToast(`${peerId} disconnected (message flood)`, 'error');
                const info = this.connections.get(peerId);
                try { info?.conn?.close(); } catch (e) {}
                this.handlePeerDisconnect(peerId);
            }
        }
    }

    handleData(peerId, data) {
        // 1. Handle Binary Chunk
        if (data instanceof ArrayBuffer || data instanceof Uint8Array) {
            if (!this.checkRateLimit(peerId, 'chunk')) {
                logger.warn(`Rate limit: dropping binary payload from ${peerId}`);
                this.enforceRateLimitStrikes(peerId);
                return;
            }

            const unpacked = unpackChunk(data);
            if (unpacked) {
                this.receiveFileChunkFramed(peerId, unpacked);
                return;
            }

            // Check if speed test data
            const speedTest = this.activeSpeedTests.get(peerId);
            if (speedTest && speedTest.expectingTestData) {
                this.handleSpeedTestDataReceived(peerId, data);
                return;
            }

            logger.warn(`Received unrecognized binary payload (${data.byteLength} bytes) from ${peerId}`);
            return;
        }

        // 2. Validate Structured JSON Message
        if (!data || typeof data !== 'object' || typeof data.type !== 'string') {
            logger.warn('Received invalid non-object protocol message from:', peerId);
            return;
        }

        const isPing = data.type === 'speed-test-ping';
        if (!this.checkRateLimit(peerId, isPing ? 'ping' : 'control')) {
            logger.warn(`Rate limit: dropping '${data.type}' from ${peerId}`);
            this.enforceRateLimitStrikes(peerId);
            return;
        }

        switch (data.type) {
            case 'handshake':
                this.handleHandshake(peerId, data);
                break;

            case 'file-start':
                this.receiveFileStart(peerId, data);
                break;

            case 'file-accept':
                this.handleFileAccept(peerId, data);
                break;

            case 'file-end':
                this.receiveFileEnd(peerId, data);
                break;

            case 'file-complete-ack':
                this.handleFileCompleteAck(peerId, data);
                break;

            case 'file-error':
                this.handleFileError(peerId, data);
                break;

            case 'file-cancel':
                this.handleFileCancel(peerId, data);
                break;

            case 'text-share':
                this.handleTextShare(peerId, data);
                break;

            case 'text-share-miss':
                if (this.textShareTokenFromUrl && data.token === this.textShareTokenFromUrl) {
                    this.textShareTokenFromUrl = null;
                }
                this.showToast('Text share expired or token mismatched.', 'error');
                break;

            // Speed Test Messages
            case 'speed-test-ping':
                this.handleSpeedTestPing(peerId, data);
                break;

            case 'speed-test-pong':
                this.handleSpeedTestPong(peerId, data);
                break;

            case 'speed-test-data':
                this.handleSpeedTestDataHeader(peerId, data);
                break;

            case 'speed-test-result':
                this.handleSpeedTestResult(peerId, data);
                break;

            default:
                logger.warn(`Unknown protocol message type: ${data.type}`);
        }
    }

    handleHandshake(peerId, data) {
        const peerInfo = this.connections.get(peerId);
        if (peerInfo) {
            peerInfo.username = sanitizeUsername(data.username);
            this.updatePeerList();
        }
    }

    // ==================== FILE TRANSFER: SENDER ====================

    handleFiles(fileList) {
        if (this.connections.size === 0) {
            this.showToast('No peers connected! Connect to a peer before sending files.', 'error');
            return;
        }

        const files = Array.from(fileList);
        for (const file of files) {
            if (file.size > ProtocolConstants.MAX_FILE_SIZE) {
                this.showToast(`File "${file.name}" exceeds the 2GB browser limit.`, 'error');
                continue;
            }
            this.queueFileForSending(file);
        }
    }

    queueFileForSending(file, priority = 0) {
        // DoS protection: limit pending queue size
        const pendingCount = this.queuedFiles.filter(i => i.status === 'pending').length;
        if (pendingCount >= ProtocolConstants.MAX_QUEUED_FILES) {
            this.showToast(`Queue is full (max ${ProtocolConstants.MAX_QUEUED_FILES} files). Wait for current transfers to complete.`, 'error');
            return null;
        }

        const queueItem = {
            id: ++this.queueIdCounter,
            file: file,
            status: 'pending',
            priority: priority,
            addedAt: Date.now()
        };

        this.queuedFiles.push(queueItem);
        this.queuedFiles.sort((a, b) => b.priority - a.priority);
        this.updateQueueUI();
        this.processTransferQueue();
        return queueItem.id;
    }

    processTransferQueue() {
        if (this.isSending || this.isPaused || this.queuedFiles.length === 0) return;

        const nextItem = this.queuedFiles.find(item => item.status === 'pending');
        if (!nextItem) return;

        nextItem.status = 'sending';
        this.updateQueueUI();
        this.sendFile(nextItem.file, nextItem.id);
    }

    getTargetConnections() {
        if (this.broadcastMode === 'all') {
            return Array.from(this.connections.values());
        }
        if (this.broadcastMode === 'selected') {
            if (this.selectedPeers.size === 0) {
                // Correct semantics: 0 selected peers returns EMPTY list, never all!
                return [];
            }
            return Array.from(this.connections.entries())
                .filter(([peerId]) => this.selectedPeers.has(peerId))
                .map(([, val]) => val);
        }
        return [];
    }

    async sendFile(file, queueId = null) {
        this.isSending = true;

        try {
            const targetConnections = this.getTargetConnections();
            if (targetConnections.length === 0) {
                this.showToast('No peers selected. Select at least one peer or choose "Send to All".', 'error');
                this.isSending = false;
                if (queueId) {
                    const item = this.queuedFiles.find(i => i.id === queueId);
                    if (item) item.status = 'pending';
                    this.updateQueueUI();
                }
                return;
            }

            const transferId = generateUuid();
            const safeName = sanitizeFilename(file.name);
            const chunkSize = this.currentChunkSize;
            const totalChunks = Math.ceil(file.size / chunkSize) || 1;
            const now = Date.now();

            // 1. Compute SHA-256 Checksum before or during transfer
            this.showToast(`Preparing ${safeName}...`, 'info');
            let sha256Hex = '';
            try {
                sha256Hex = await computeSha256(file);
            } catch (err) {
                logger.error('Failed to compute SHA-256 for file:', err);
                this.showToast(`Failed to compute file checksum for "${safeName}"`, 'error');
                this.isSending = false;
                if (queueId) {
                    const item = this.queuedFiles.find(i => i.id === queueId);
                    if (item) item.status = 'failed';
                    this.updateQueueUI();
                }
                setTimeout(() => this.processTransferQueue(), 50);
                return;
            }

            // Initialize Per-Peer Transfer Tracking.
            // Peers start in 'awaiting-accept': no chunks flow until the
            // receiver explicitly consents via file-accept.
            const peersMap = new Map();
            targetConnections.forEach(({ conn }) => {
                peersMap.set(conn.peer, {
                    status: 'awaiting-accept', // 'awaiting-accept' | 'sending' | 'complete' | 'failed'
                    accepted: false,
                    endSent: false,
                    transferred: 0,
                    ackReceived: false,
                    error: null,
                    lastUpdate: now,
                    lastBytes: 0
                });
            });

            const transferRecord = {
                id: transferId,
                file,
                name: safeName,
                size: file.size,
                totalChunks,
                chunkSize,
                sha256: sha256Hex,
                queueId,
                reader: null,
                isCancelled: false,
                peers: peersMap,
                startTime: now,
                lastUiUpdate: 0
            };

            this.activeSends.set(transferId, transferRecord);
            this.addTransferToUI(transferId, safeName, file.size, 'send');

            // 2. Send Control Header (file-start) to all target peers
            targetConnections.forEach(({ conn }) => {
                try {
                    conn.send({
                        type: 'file-start',
                        transferId,
                        name: safeName,
                        size: file.size,
                        totalChunks,
                        chunkSize,
                        sha256: sha256Hex
                    });
                } catch (err) {
                    logger.error(`Failed to send file-start to ${conn.peer}:`, err);
                    const peerState = peersMap.get(conn.peer);
                    if (peerState) {
                        peerState.status = 'failed';
                        peerState.error = err.message;
                    }
                }
            });

            // Consent deadline: receivers that never answer are failed so the
            // transfer cannot hang forever before any byte is read.
            transferRecord.acceptTimeoutId = setTimeout(() => {
                peersMap.forEach((peerState) => {
                    if (peerState.status === 'awaiting-accept') {
                        peerState.status = 'failed';
                        peerState.error = 'Receiver did not respond to consent request';
                    }
                });
                const anyLive = Array.from(peersMap.values()).some(p => p.status !== 'failed');
                if (!anyLive) {
                    this.finalizeSendTransfer(transferId, false, 'No receiver accepted the transfer');
                } else {
                    this.checkTransferCompletion(transferId);
                }
            }, ProtocolConstants.FILE_ACCEPT_TIMEOUT_MS);

            // 3. Sequential Chunk Streaming with Backpressure.
            // Chunks are sent ONLY to peers that accepted (status 'sending');
            // one slow or silent peer never blocks the others.
            const reader = new FileReader();
            transferRecord.reader = reader;
            let chunkIndex = 0;
            let offset = 0;
            let readInFlight = false;
            let pollScheduled = false;

            const acceptedPeers = () => Array.from(peersMap.entries()).filter(([, p]) => p.status === 'sending');
            const hasAwaitingPeers = () => Array.from(peersMap.values()).some(p => p.status === 'awaiting-accept');

            const sendFileEndFooter = () => {
                logger.info(`Finished streaming all chunks for ${transferId}. Sending file-end.`);
                peersMap.forEach((peerState, peerId) => {
                    if (peerState.status !== 'sending') return;
                    const connObj = this.connections.get(peerId);
                    if (connObj && connObj.conn) {
                        try {
                            connObj.conn.send({
                                type: 'file-end',
                                transferId,
                                totalChunks,
                                sha256: sha256Hex
                            });
                            // file-end sent: only now is a file-complete-ack legal
                            peerState.endSent = true;
                        } catch (err) {
                            peerState.status = 'failed';
                            peerState.error = err.message;
                        }
                    }
                });

                this.setTransferVerifyingUI(transferId);

                const ackTimeout = computeAdaptiveAckTimeout(file.size);
                logger.info(`ACK timeout for ${transferId}: ${ackTimeout}ms (file size: ${file.size} bytes)`);
                transferRecord.ackTimeoutId = setTimeout(() => {
                    peersMap.forEach((peerState) => {
                        if (peerState.status === 'sending' && !peerState.ackReceived) {
                            peerState.status = 'failed';
                            peerState.error = 'Receiver verification ACK timed out';
                        }
                    });
                    this.checkTransferCompletion(transferId);
                }, ackTimeout);
            };

            const dispatchChunk = (sliceBuffer) => {
                const framedChunk = packChunk(transferId, chunkIndex, sliceBuffer);

                peersMap.forEach((peerState, peerId) => {
                    if (peerState.status !== 'sending') return;

                    const connObj = this.connections.get(peerId);
                    if (!connObj || !connObj.conn) {
                        peerState.status = 'failed';
                        peerState.error = 'Peer connection lost';
                        return;
                    }

                    try {
                        connObj.conn.send(framedChunk);
                        peerState.transferred += sliceBuffer.byteLength;
                    } catch (err) {
                        logger.error(`Error sending chunk ${chunkIndex} to ${peerId}:`, err);
                        peerState.status = 'failed';
                        peerState.error = err.message;
                    }
                });

                offset += sliceBuffer.byteLength;
                chunkIndex++;
                this.totalBytesTransferred += sliceBuffer.byteLength;

                const progress = file.size > 0 ? Math.min(1, offset / file.size) : 1;
                const nowTime = Date.now();
                if (nowTime - transferRecord.lastUiUpdate > 150 || progress >= 1) {
                    transferRecord.lastUiUpdate = nowTime;
                    this.updateTransferUI(transferId, progress);
                }
            };

            const sendNextChunk = () => {
                if (transferRecord.isCancelled) {
                    logger.info(`Transfer ${transferId} was cancelled by sender.`);
                    return;
                }

                // One FileReader read at a time; kicks from handleFileAccept or
                // poll timers must not double-queue reads.
                if (readInFlight) return;

                let activePeers = acceptedPeers();
                if (activePeers.length === 0) {
                    // Nothing accepted yet: park while consent is pending; the
                    // consent timeout or handleFileAccept will resume us.
                    if (hasAwaitingPeers()) {
                        if (!pollScheduled) {
                            pollScheduled = true;
                            setTimeout(() => { pollScheduled = false; sendNextChunk(); }, 250);
                        }
                        return;
                    }
                    logger.warn(`All target peers disconnected or failed for transfer ${transferId}.`);
                    this.finalizeSendTransfer(transferId, false, 'All peers failed');
                    return;
                }

                // Backpressure check on data channels
                let maxBuffered = 0;
                for (const [peerId, peerState] of activePeers) {
                    const connObj = this.connections.get(peerId);
                    if (!connObj || !connObj.conn || !connObj.conn.dataChannel || connObj.conn.dataChannel.readyState !== 'open') {
                        peerState.status = 'failed';
                        peerState.error = 'Data channel closed';
                        continue;
                    }
                    maxBuffered = Math.max(maxBuffered, connObj.conn.dataChannel.bufferedAmount || 0);
                }

                // Re-check active peers after dead channel pruning
                activePeers = acceptedPeers();
                if (activePeers.length === 0) {
                    if (hasAwaitingPeers()) {
                        sendNextChunk();
                    } else {
                        logger.warn(`All target peers disconnected or failed for transfer ${transferId}.`);
                        this.finalizeSendTransfer(transferId, false, 'All peers failed');
                    }
                    return;
                }

                if (maxBuffered > ProtocolConstants.BACKPRESSURE_HIGH_WATERMARK) {
                    // Buffer full, pause and check back
                    setTimeout(sendNextChunk, 15);
                    return;
                }

                // Read slice
                const slice = file.slice(offset, offset + chunkSize);
                readInFlight = true;
                reader.readAsArrayBuffer(slice);
            };

            reader.onload = (e) => {
                readInFlight = false;
                if (transferRecord.isCancelled) return;

                dispatchChunk(e.target.result);

                if (offset < file.size) {
                    // Continue streaming next chunk
                    setTimeout(sendNextChunk, 0);
                } else {
                    sendFileEndFooter();
                }
            };

            reader.onerror = (e) => {
                readInFlight = false;
                logger.error(`FileReader error on file ${safeName}:`, e);
                this.showToast(`Error reading file "${safeName}"`, 'error');
                this.finalizeSendTransfer(transferId, false, 'File reading error');
            };

            reader.onabort = () => {
                readInFlight = false;
                logger.warn(`FileReader aborted for file ${safeName}`);
                this.finalizeSendTransfer(transferId, false, 'File transfer cancelled');
            };

            if (file.size === 0) {
                // Zero-byte file: still emit the single empty chunk the
                // protocol expects (totalChunks === 1), then the footer.
                dispatchChunk(new ArrayBuffer(0));
                sendFileEndFooter();
                return;
            }

            // Kick off streaming
            sendNextChunk();
        } catch (err) {
            logger.error('Unexpected error in sendFile:', err);
            this.showToast(`Transfer failed unexpectedly: ${err.message}`, 'error');
            this.isSending = false;
            if (queueId) {
                const item = this.queuedFiles.find(i => i.id === queueId);
                if (item) item.status = 'failed';
                this.updateQueueUI();
            }
            setTimeout(() => this.processTransferQueue(), 50);
        }
    }

    /**
     * Receiver consented to the transfer: unlock chunk streaming for that peer.
     */
    handleFileAccept(peerId, data) {
        const transfer = this.activeSends.get(data.transferId);
        if (!transfer) return;

        const peerState = transfer.peers.get(peerId);
        if (peerState && peerState.status === 'awaiting-accept') {
            peerState.status = 'sending';
            peerState.accepted = true;
            logger.info(`Receiver ${peerId} accepted transfer ${data.transferId}`);

            const anyAwaiting = Array.from(transfer.peers.values()).some(p => p.status === 'awaiting-accept');
            if (!anyAwaiting && transfer.acceptTimeoutId) {
                clearTimeout(transfer.acceptTimeoutId);
                transfer.acceptTimeoutId = null;
            }
        }
    }

    /**
     * Handles Receiver ACK. An ACK is only legal AFTER file-end was sent to
     * that peer AND it carries status 'ok'; anything else is a protocol error.
     */
    handleFileCompleteAck(peerId, data) {
        const transfer = this.activeSends.get(data.transferId);
        if (!transfer) return;

        const peerState = transfer.peers.get(peerId);
        if (!peerState) return;

        if (!peerState.endSent) {
            logger.warn(`Protocol violation: file-complete-ack from ${peerId} before file-end (transfer ${data.transferId})`);
            peerState.status = 'failed';
            peerState.error = 'Protocol violation: unexpected ACK';
            this.checkTransferCompletion(data.transferId);
            return;
        }

        if (data.status !== 'ok') {
            logger.warn(`Receiver ${peerId} acknowledged transfer ${data.transferId} with status '${data.status}'`);
            peerState.status = 'failed';
            peerState.error = `Receiver reported status '${data.status}'`;
            this.checkTransferCompletion(data.transferId);
            return;
        }

        peerState.status = 'complete';
        peerState.ackReceived = true;
        logger.info(`Received completion ACK from ${peerId} for transfer ${data.transferId}`);
        this.checkTransferCompletion(data.transferId);
    }

    handleFileError(peerId, data) {
        const transferId = data?.transferId;
        if (typeof transferId !== 'string') return;

        // Sender role: a receiver reported an error on our transfer
        const transfer = this.activeSends.get(transferId);
        if (transfer) {
            const peerState = transfer.peers.get(peerId);
            if (peerState && peerState.status !== 'complete') {
                peerState.status = 'failed';
                peerState.error = data.error || 'Receiver error';
                logger.warn(`Receiver ${peerId} reported error on transfer ${transferId}:`, data.error);
                this.showToast(`Peer reported error on "${transfer.name}": ${data.error}`, 'error');
            }
            this.checkTransferCompletion(transferId);
            return;
        }

        // Receiver role: the SENDER reported a failure — clean up our receive
        // record, free its chunks and concurrency slot.
        const compositeKey = `${peerId}:${transferId}`;
        const receive = this.activeReceives.get(compositeKey);
        if (receive) {
            logger.warn(`Sender ${peerId} reported error on receive ${transferId}: ${data.error || 'unknown'}`);
            this.cleanupReceive(compositeKey, data.error || 'Sender reported an error');
        }
    }

    handleFileCancel(peerId, data) {
        const transferId = data?.transferId;
        if (typeof transferId !== 'string') return;

        // Sender role: receiver cancelled the download
        const transfer = this.activeSends.get(transferId);
        if (transfer) {
            const peerState = transfer.peers.get(peerId);
            if (peerState && peerState.status !== 'complete') {
                peerState.status = 'failed';
                peerState.error = 'Peer cancelled download';
            }
            this.checkTransferCompletion(transferId);
            return;
        }

        // Receiver role: the SENDER cancelled — remove the matching
        // activeReceives entry (peerId:transferId), free its chunks, update
        // the UI, and free its concurrency slot.
        const compositeKey = `${peerId}:${transferId}`;
        const receive = this.activeReceives.get(compositeKey);
        if (receive) {
            logger.warn(`Sender ${peerId} cancelled receive transfer ${transferId}`);
            this.cleanupReceive(compositeKey, 'Cancelled by sender');
        }
    }

    checkTransferCompletion(transferId) {
        const transfer = this.activeSends.get(transferId);
        if (!transfer) return;

        const allDone = Array.from(transfer.peers.values()).every(p => p.status === 'complete' || p.status === 'failed');
        if (allDone) {
            if (transfer.ackTimeoutId) {
                clearTimeout(transfer.ackTimeoutId);
                transfer.ackTimeoutId = null;
            }
            if (transfer.acceptTimeoutId) {
                clearTimeout(transfer.acceptTimeoutId);
                transfer.acceptTimeoutId = null;
            }

            const anySuccess = Array.from(transfer.peers.values()).some(p => p.status === 'complete');
            this.finalizeSendTransfer(transferId, anySuccess);
        }
    }

    /**
     * Notifies all peers that did NOT complete that the send failed. Receivers
     * use this to clean up stalled receive state.
     */
    notifyPeersOfSendFailure(transfer, reason) {
        transfer.peers.forEach((peerState, peerId) => {
            if (peerState.status === 'complete') return;
            const conn = this.connections.get(peerId)?.conn;
            if (conn) {
                try {
                    conn.send({ type: 'file-error', transferId: transfer.id, error: reason });
                } catch (e) {}
            }
        });
    }

    finalizeSendTransfer(transferId, success, failureReason = '') {
        const transfer = this.activeSends.get(transferId);
        if (!transfer) return;

        // Clear any outstanding timers
        if (transfer.ackTimeoutId) { clearTimeout(transfer.ackTimeoutId); transfer.ackTimeoutId = null; }
        if (transfer.acceptTimeoutId) { clearTimeout(transfer.acceptTimeoutId); transfer.acceptTimeoutId = null; }

        if (success) {
            this.completeTransferUI(transferId, transfer.size, transfer.startTime);
            this.saveHistory({ name: transfer.name, size: transfer.size, peer: 'Peers' }, 'send');

            // Per-peer outcome instead of a blanket "Sent"
            const okPeers = [];
            const failedPeers = [];
            transfer.peers.forEach((peerState, peerId) => {
                const name = this.connections.get(peerId)?.username || peerId;
                if (peerState.status === 'complete') okPeers.push(name);
                else failedPeers.push(`${name}${peerState.error ? ` (${peerState.error})` : ''}`);
            });

            let toast = `Sent: ${transfer.name}`;
            if (okPeers.length) toast += ` — delivered to ${okPeers.join(', ')}`;
            if (failedPeers.length) toast += ` — failed for ${failedPeers.join(', ')}`;
            this.showToast(toast, failedPeers.length ? 'warning' : 'success');
            if (failedPeers.length === 0) this.playCompletionSound();
        } else {
            // Tell receivers the send failed so they can clean up
            this.notifyPeersOfSendFailure(transfer, failureReason || 'Transfer failed');
            this.failTransferUI(transferId, failureReason || 'Transfer failed');
            this.showToast(`Failed to send ${transfer.name}: ${failureReason || 'unknown error'}`, 'error');
        }

        if (transfer.queueId) {
            const q = this.queuedFiles.find(i => i.id === transfer.queueId);
            if (q) {
                q.status = success ? 'completed' : 'failed';
                q.file = null; // Release the File reference
            }
        }

        // Release the File reference and reader
        transfer.file = null;
        transfer.reader = null;

        this.activeSends.delete(transferId);
        this.updateQueueUI();

        // Release queue lock and process next
        this.isSending = false;
        setTimeout(() => this.processTransferQueue(), 50);
    }

    // ==================== FILE TRANSFER: RECEIVER ====================

    receiveFileStart(peerId, data) {
        // Validate metadata strictly (sha256 mandatory)
        const validation = validateFileStartMetadata(data);
        if (!validation.valid) {
            logger.warn(`Rejected invalid file-start metadata from ${peerId}:`, validation.error);
            const conn = this.connections.get(peerId)?.conn;
            if (conn && data?.transferId) {
                try {
                    conn.send({
                        type: 'file-error',
                        transferId: data.transferId,
                        error: `Invalid metadata: ${validation.error}`
                    });
                } catch (e) {}
            }
            this.showToast(`Rejected transfer from peer: ${validation.error}`, 'error');
            return;
        }

        const { transferId, name: safeName, size, totalChunks, chunkSize, sha256: expectedSha256 } = validation.sanitized;

        const compositeKey = `${peerId}:${transferId}`;
        if (this.activeReceives.has(compositeKey)) {
            logger.warn(`Duplicate transferId ${transferId} from ${peerId}`);
            return;
        }

        const reject = (error) => {
            const conn = this.connections.get(peerId)?.conn;
            if (conn) {
                try {
                    conn.send({ type: 'file-error', transferId, error });
                } catch (e) {}
            }
            this.showToast(`Transfer rejected: ${error}`, 'warning');
        };

        // Per-peer concurrency cap
        let activeForPeer = 0;
        for (const r of this.activeReceives.values()) {
            if (r.peerId === peerId) activeForPeer++;
        }
        if (activeForPeer >= ProtocolConstants.MAX_CONCURRENT_RECEIVES) {
            logger.warn(`Rejecting transfer ${transferId} from ${peerId}: reached MAX_CONCURRENT_RECEIVES (${activeForPeer})`);
            reject(`Concurrency limit reached (${ProtocolConstants.MAX_CONCURRENT_RECEIVES} active transfers max per peer)`);
            return;
        }

        // Global concurrency cap
        if (this.activeReceives.size >= ProtocolConstants.MAX_ACTIVE_RECEIVES_TOTAL) {
            logger.warn(`Rejecting transfer ${transferId} from ${peerId}: global receive cap reached`);
            reject(`Too many concurrent incoming transfers (${ProtocolConstants.MAX_ACTIVE_RECEIVES_TOTAL} max)`);
            return;
        }

        // Aggregate buffered-bytes cap across ALL active receives
        let aggregateBytes = 0;
        for (const r of this.activeReceives.values()) {
            aggregateBytes += Math.max(0, r.size - r.receivedBytes);
        }
        if (aggregateBytes + size > ProtocolConstants.MAX_AGGREGATE_RECEIVE_BUFFER) {
            logger.warn(`Rejecting transfer ${transferId} from ${peerId}: aggregate receive buffer cap reached`);
            reject('Incoming transfer buffer limit reached. Try again after current transfers finish.');
            return;
        }

        const senderName = this.connections.get(peerId)?.username || peerId;
        logger.info(`file-start from ${peerId}: ${safeName} (${size} bytes, ${totalChunks} chunks) — requesting consent`);

        // Consent-gated intake: no chunks are allocated or accepted until the
        // user explicitly accepts.
        const receiveRecord = {
            compositeKey,
            transferId,
            peerId,
            senderName,
            name: safeName,
            size,
            totalChunks,
            chunkSize,
            sha256: expectedSha256,
            state: 'awaiting-consent', // 'awaiting-consent' -> 'receiving' -> 'verifying' -> 'completed' | 'failed'
            chunks: null,              // allocated on accept
            receivedBytes: 0,
            receivedChunks: new Set(),
            startTime: Date.now(),
            lastProgressAt: Date.now(),
            lastUpdate: Date.now(),
            lastBytes: 0,
            lastUiUpdate: 0,
            receivedInOrder: true,
            expectedNextSeq: 0
        };

        this.activeReceives.set(compositeKey, receiveRecord);
        this.showFileConsentPrompt(compositeKey, receiveRecord);
    }

    // ==================== INCOMING TRANSFER CONSENT (ABUSE CONTROL) ====================

    showFileConsentPrompt(compositeKey, receive) {
        const senderName = receive.senderName;
        const modal = document.createElement('div');
        modal.className = 'velo-consent-modal';
        modal.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.8); backdrop-filter: blur(8px); display: flex; align-items: center; justify-content: center; z-index: 250;';

        const card = document.createElement('div');
        card.style.cssText = 'background: var(--bg-surface); border-radius: 24px; padding: 2rem; max-width: 420px; width: 90%; border: 1px solid var(--border-light); text-align: center;';

        const title = document.createElement('h3');
        title.style.marginBottom = '0.5rem';
        title.textContent = 'Incoming file';
        card.appendChild(title);

        const desc = document.createElement('p');
        desc.style.cssText = 'color: var(--text-muted); margin-bottom: 1rem; font-size: 0.9rem;';
        desc.textContent = `${senderName} wants to send you:`;
        card.appendChild(desc);

        const fileInfo = document.createElement('div');
        fileInfo.style.cssText = 'background: var(--bg-main); padding: 0.85rem; border-radius: 12px; margin-bottom: 1.25rem; font-weight: 600; word-break: break-word;';
        fileInfo.textContent = `${receive.name} (${this.formatBytes(receive.size)})`;
        card.appendChild(fileInfo);

        const btnRow = document.createElement('div');
        btnRow.style.cssText = 'display: flex; gap: 0.75rem;';

        const acceptBtn = document.createElement('button');
        acceptBtn.className = 'btn-primary';
        acceptBtn.style.flex = '1';
        acceptBtn.textContent = 'Accept';
        acceptBtn.onclick = () => this.acceptIncomingTransfer(compositeKey);
        btnRow.appendChild(acceptBtn);

        const declineBtn = document.createElement('button');
        declineBtn.className = 'btn-ghost';
        declineBtn.style.flex = '1';
        declineBtn.textContent = 'Decline';
        declineBtn.onclick = () => this.declineIncomingTransfer(compositeKey, 'Declined by you');
        btnRow.appendChild(declineBtn);

        card.appendChild(btnRow);
        modal.appendChild(card);
        modal.onclick = (e) => { if (e.target === modal) this.declineIncomingTransfer(compositeKey, 'Declined by you'); };
        document.body.appendChild(modal);

        receive.consentModal = modal;
        this.pendingConsents.set(compositeKey, {
            peerId: receive.peerId,
            transferId: receive.transferId,
            requestedAt: Date.now(),
            modal
        });
    }

    acceptIncomingTransfer(compositeKey) {
        const receive = this.activeReceives.get(compositeKey);
        const consent = this.pendingConsents.get(compositeKey);
        this.pendingConsents.delete(compositeKey);
        if (consent?.modal) { try { consent.modal.remove(); } catch (e) {} }
        if (!receive || receive.state !== 'awaiting-consent') return;

        logger.info(`Transfer ${receive.transferId} accepted by user`);
        receive.state = 'receiving';
        receive.chunks = new Array(receive.totalChunks);
        receive.lastProgressAt = Date.now();

        const conn = this.connections.get(receive.peerId)?.conn;
        if (conn) {
            try {
                conn.send({ type: 'file-accept', transferId: receive.transferId });
            } catch (e) {}
        }

        this.addTransferToUI(receive.transferId, receive.name, receive.size, 'receive');
    }

    declineIncomingTransfer(compositeKey, reason = 'Declined by you') {
        const receive = this.activeReceives.get(compositeKey);
        const consent = this.pendingConsents.get(compositeKey);
        this.pendingConsents.delete(compositeKey);
        if (consent?.modal) { try { consent.modal.remove(); } catch (e) {} }
        if (!receive || receive.state !== 'awaiting-consent') return;

        const conn = this.connections.get(receive.peerId)?.conn;
        if (conn) {
            try {
                conn.send({ type: 'file-cancel', transferId: receive.transferId });
            } catch (e) {}
        }
        this.activeReceives.delete(compositeKey);
        this.showToast(`Declined incoming file "${receive.name}"${reason ? `: ${reason}` : ''}`, 'info');
    }

    /**
     * Removes a receive record: frees chunks + concurrency slot and updates UI.
     */
    cleanupReceive(compositeKey, reason) {
        const receive = this.activeReceives.get(compositeKey);
        if (!receive) return;

        this.pendingConsents.delete(compositeKey);
        if (receive.consentModal) { try { receive.consentModal.remove(); } catch (e) {} }

        this.activeReceives.delete(compositeKey); // frees the concurrency slot
        receive.chunks = null;                    // free buffered chunk memory

        if (receive.state !== 'awaiting-consent') {
            this.failTransferUI(receive.transferId, reason || 'Transfer aborted');
        }
        this.showToast(`Transfer of ${receive.name} aborted${reason ? ` (${reason})` : ''}`, 'error');
    }

    /**
     * Housekeeping sweep: reaps receives with no chunk progress (stalled
     * transfers) and expired consent requests.
     */
    sweepStalledReceives() {
        const now = Date.now();

        this.activeReceives.forEach((receive, key) => {
            if (receive.state === 'receiving' &&
                now - receive.lastProgressAt > ProtocolConstants.RECEIVE_IDLE_TIMEOUT_MS) {
                logger.warn(`Receive ${receive.transferId} stalled (${ProtocolConstants.RECEIVE_IDLE_TIMEOUT_MS}ms without progress). Cleaning up.`);
                const conn = this.connections.get(receive.peerId)?.conn;
                if (conn) {
                    try { conn.send({ type: 'file-cancel', transferId: receive.transferId }); } catch (e) {}
                }
                this.cleanupReceive(key, 'Timed out (no progress)');
            } else if (receive.state === 'awaiting-consent' &&
                now - receive.lastProgressAt > ProtocolConstants.CONSENT_TIMEOUT_MS) {
                this.declineIncomingTransfer(key, 'Consent request expired');
            }
        });
    }

    startSweeping() {
        if (this.sweepInterval) return;
        this.sweepInterval = setInterval(() => this.sweepStalledReceives(), 5000);
    }

    stopSweeping() {
        if (this.sweepInterval) {
            clearInterval(this.sweepInterval);
            this.sweepInterval = null;
        }
    }

    // ==================== PER-PEER BLOCKING ====================

    loadBlockedPeers() {
        try {
            const raw = localStorage.getItem('velo_blocked_peers');
            if (raw) {
                const parsed = JSON.parse(raw);
                if (Array.isArray(parsed)) {
                    parsed.forEach(id => {
                        if (typeof id === 'string') this.blockedPeers.add(id);
                    });
                }
            }
        } catch (e) {}
    }

    saveBlockedPeers() {
        try {
            localStorage.setItem('velo_blocked_peers', JSON.stringify(Array.from(this.blockedPeers)));
        } catch (e) {}
    }

    /**
     * Blocks a peer: closes any live connection, refuses future inbound
     * connections, and removes them from transfer/selection state.
     */
    blockPeer(peerId) {
        if (!peerId) return;
        this.blockedPeers.add(peerId);
        this.saveBlockedPeers();

        const info = this.connections.get(peerId);
        if (info) {
            try { info.conn?.close(); } catch (e) {}
            this.handlePeerDisconnect(peerId);
            this.showToast(`Blocked ${info.username || peerId}`, 'info');
        }
        this.updatePeerList();
    }

    unblockPeer(peerId) {
        if (!peerId) return;
        this.blockedPeers.delete(peerId);
        this.saveBlockedPeers();
        this.showToast(`${peerId} unblocked`, 'info');
        this.updatePeerList();
    }

    isPeerBlocked(peerId) {
        return this.blockedPeers.has(peerId);
    }

    receiveFileChunkFramed(peerId, { transferId, sequenceNumber, payload }) {
        const compositeKey = `${peerId}:${transferId}`;
        const receive = this.activeReceives.get(compositeKey);
        if (!receive) {
            logger.warn(`Received framed chunk for unknown transfer ${transferId} from ${peerId}`);
            return;
        }

        // State machine: chunks are only meaningful while 'receiving'. Anything
        // arriving before consent or during verification is dropped.
        if (receive.state !== 'receiving') {
            logger.warn(`Chunk for transfer ${transferId} ignored (state: ${receive.state})`);
            return;
        }

        if (receive.peerId !== peerId) {
            logger.warn(`Chunk sender mismatch for transfer ${transferId}: expected ${receive.peerId}, got ${peerId}`);
            return;
        }

        if (sequenceNumber >= receive.totalChunks) {
            logger.warn(`Sequence number ${sequenceNumber} out of bounds (max ${receive.totalChunks})`);
            this.abortReceiveWithProtocolError(receive, `Chunk sequence out of bounds (${sequenceNumber})`);
            return;
        }

        // Exact per-chunk length: every chunk must be min(chunkSize, remaining).
        // For a zero-byte file the single expected chunk has length 0.
        const expectedLen = Math.min(receive.chunkSize, receive.size - sequenceNumber * receive.chunkSize);
        if (payload.byteLength !== expectedLen) {
            logger.warn(`Chunk ${sequenceNumber} length mismatch for ${transferId}: got ${payload.byteLength}, expected ${expectedLen}`);
            this.abortReceiveWithProtocolError(receive, `Chunk ${sequenceNumber} has wrong length`);
            return;
        }

        if (receive.receivedChunks.has(sequenceNumber)) {
            logger.log(`Duplicate chunk ${sequenceNumber} for ${transferId} ignored`);
            return;
        }

        // Cumulative overflow guard: never accept more bytes than advertised
        if (receive.receivedBytes + payload.byteLength > receive.size) {
            logger.warn(`Cumulative bytes exceed advertised size for ${transferId}`);
            this.abortReceiveWithProtocolError(receive, 'Received more bytes than advertised');
            return;
        }

        receive.chunks[sequenceNumber] = payload;
        receive.receivedChunks.add(sequenceNumber);
        receive.receivedBytes += payload.byteLength;
        receive.lastProgressAt = Date.now();
        if (sequenceNumber !== receive.expectedNextSeq) {
            receive.receivedInOrder = false;
        }
        receive.expectedNextSeq = Math.max(receive.expectedNextSeq, sequenceNumber + 1);
        this.totalBytesTransferred += payload.byteLength;

        // Throttle UI updates
        const now = Date.now();
        if (now - receive.lastUiUpdate > 150 || receive.receivedChunks.size === receive.totalChunks) {
            receive.lastUiUpdate = now;
            const progress = receive.size > 0 ? Math.min(1, receive.receivedBytes / receive.size) : 1;
            this.updateTransferUI(transferId, progress);
        }
    }

    /**
     * Receiver-side protocol violation: notify sender, fail UI, free state.
     */
    abortReceiveWithProtocolError(receive, reason) {
        const conn = this.connections.get(receive.peerId)?.conn;
        if (conn) {
            try {
                conn.send({ type: 'file-error', transferId: receive.transferId, error: reason });
            } catch (e) {}
        }
        this.cleanupReceive(receive.compositeKey, reason);
    }

    async receiveFileEnd(peerId, data) {
        const transferId = data?.transferId;
        if (typeof transferId !== 'string') return;

        const compositeKey = `${peerId}:${transferId}`;
        const receive = this.activeReceives.get(compositeKey);
        if (!receive) return;

        if (receive.peerId !== peerId) {
            logger.warn(`File-end sender mismatch for transfer ${transferId}: expected ${receive.peerId}, got ${peerId}`);
            return;
        }

        // State machine: only ONE file-end is honored, and only from 'receiving'.
        // Duplicates or late file-ends (during verification) are ignored.
        if (receive.state !== 'receiving') {
            logger.warn(`file-end for ${transferId} ignored (state: ${receive.state})`);
            return;
        }

        // Mandatory digest: the protocol requires sha256 on every transfer
        if (!receive.sha256) {
            logger.warn(`file-end for ${transferId} rejected: no SHA-256 digest`);
            this.abortReceiveWithProtocolError(receive, 'Transfer missing SHA-256 digest');
            return;
        }

        receive.state = 'verifying';
        logger.info(`Received file-end for ${transferId}. Verifying integrity...`);
        this.setTransferVerifyingUI(transferId);

        const conn = this.connections.get(peerId)?.conn;

        // 1. Verify chunk count
        if (receive.receivedChunks.size !== receive.totalChunks) {
            logger.error(`Chunk count mismatch: got ${receive.receivedChunks.size} of ${receive.totalChunks}`);
            if (conn) {
                try {
                    conn.send({
                        type: 'file-error',
                        transferId,
                        error: `Missing chunks: received ${receive.receivedChunks.size}/${receive.totalChunks}`
                    });
                } catch (e) {}
            }
            this.failTransferUI(transferId, 'Corrupted transfer: missing chunks');
            this.activeReceives.delete(compositeKey);
            receive.chunks = null;
            this.showToast(`Transfer of ${receive.name} failed: missing chunks`, 'error');
            return;
        }

        // 2. Reconstruct file Blob
        const blob = new Blob(receive.chunks);
        // Release chunk array immediately to free memory
        receive.chunks = null;

        if (blob.size !== receive.size) {
            logger.error(`Byte size mismatch: expected ${receive.size}, reconstructed ${blob.size}`);
            if (conn) {
                try {
                    conn.send({
                        type: 'file-error',
                        transferId,
                        error: `Byte count mismatch: expected ${receive.size}, got ${blob.size}`
                    });
                } catch (e) {}
            }
            this.failTransferUI(transferId, 'Corrupted transfer: byte count mismatch');
            this.activeReceives.delete(compositeKey);
            this.showToast(`Transfer of ${receive.name} failed: byte count mismatch`, 'error');
            return;
        }

        // 3. Verify SHA-256 Checksum (FAIL-CLOSED: any error or mismatch aborts transfer)
        try {
            const computedHash = await computeSha256(blob);
            if (computedHash.toLowerCase() !== receive.sha256.toLowerCase()) {
                logger.error(`SHA-256 mismatch! Expected: ${receive.sha256}, computed: ${computedHash}`);
                if (conn) {
                    try {
                        conn.send({
                            type: 'file-error',
                            transferId,
                            error: 'SHA-256 integrity verification failed'
                        });
                    } catch (e) {}
                }
                this.failTransferUI(transferId, 'Integrity verification failed (corrupted file)');
                this.activeReceives.delete(compositeKey);
                this.showToast(`Transfer of ${receive.name} failed integrity verification`, 'error');
                return;
            }
            logger.info(`SHA-256 verified successfully: ${computedHash}`);
        } catch (err) {
            logger.error('Error computing SHA-256 verification (failing closed):', err);
            if (conn) {
                try {
                    conn.send({
                        type: 'file-error',
                        transferId,
                        error: 'Integrity verification failed during SHA-256 computation'
                    });
                } catch (e) {}
            }
            this.failTransferUI(transferId, 'Integrity check error (transfer aborted)');
            this.activeReceives.delete(compositeKey);
            this.showToast(`Transfer of ${receive.name} failed during integrity check`, 'error');
            return;
        }

        receive.state = 'completed';

        // 4. Send Completion ACK
        if (conn) {
            try {
                conn.send({
                    type: 'file-complete-ack',
                    transferId,
                    status: 'ok'
                });
            } catch (e) {}
        }

        // 5. Trigger download
        const downloadUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = receive.name;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);

        setTimeout(() => URL.revokeObjectURL(downloadUrl), 30000);

        // Update UI
        this.completeTransferUI(transferId, receive.size, receive.startTime);
        this.saveHistory({ name: receive.name, size: receive.size, peer: peerId }, 'receive');
        this.showToast(`Received: ${receive.name}`, 'success');
        this.playCompletionSound();

        this.activeReceives.delete(compositeKey);
    }

    // ==================== CANCELLATION & QUEUE MANAGEMENT ====================

    cancelTransfer(id) {
        // 1. Check active sends
        if (this.activeSends.has(id)) {
            const transfer = this.activeSends.get(id);
            transfer.isCancelled = true;
            if (transfer.reader) {
                try { transfer.reader.abort(); } catch (e) {}
            }

            // Notify connected peers
            transfer.peers.forEach((_, peerId) => {
                const conn = this.connections.get(peerId)?.conn;
                if (conn) {
                    try {
                        conn.send({ type: 'file-cancel', transferId: id });
                    } catch (e) {}
                }
            });

            this.finalizeSendTransfer(id, false, 'Cancelled by user');
            this.showToast(`Cancelled: ${transfer.name}`, 'info');
            return;
        }

        // 2. Check active receives (keyed by compositeKey or transferId)
        for (const [key, receive] of this.activeReceives.entries()) {
            if (receive.transferId === id || key === id) {
                if (receive.state === 'awaiting-consent') {
                    this.declineIncomingTransfer(key, 'Cancelled by you');
                    return;
                }
                const conn = this.connections.get(receive.peerId)?.conn;
                if (conn) {
                    try {
                        conn.send({ type: 'file-cancel', transferId: receive.transferId });
                    } catch (e) {}
                }
                this.activeReceives.delete(key);
                receive.chunks = null; // free buffered chunks + concurrency slot
                this.failTransferUI(receive.transferId, 'Cancelled by user');
                this.showToast(`Cancelled receive: ${receive.name}`, 'info');
                return;
            }
        }

        // 3. Check queued files
        const qItem = this.queuedFiles.find(i => i.id === id);
        if (qItem && qItem.status === 'pending') {
            qItem.status = 'cancelled';
            qItem.file = null; // Release the File reference
            this.updateQueueUI();
            this.showToast(`Removed from queue: ${qItem.name || 'file'}`, 'info');
        }
    }

    pauseQueue() {
        this.isPaused = true;
        this.showToast('Transfer queue paused', 'info');
        this.updateQueueUI();
    }

    resumeQueue() {
        this.isPaused = false;
        this.showToast('Transfer queue resumed', 'info');
        this.updateQueueUI();
        this.processTransferQueue();
    }

    clearQueue() {
        this.queuedFiles = this.queuedFiles.filter(item => item.status === 'sending');
        this.showToast('Pending queue cleared', 'info');
        this.updateQueueUI();
    }

    updateQueueUI() {
        if (!this.queueStatsEl) return;
        const pending = this.queuedFiles.filter(i => i.status === 'pending').length;
        const sending = this.queuedFiles.filter(i => i.status === 'sending').length;
        const totalSize = this.queuedFiles
            .filter(i => i.status === 'pending' || i.status === 'sending')
            .reduce((sum, i) => sum + i.file.size, 0);

        this.queueStatsEl.textContent = `Queue: ${pending} pending | ${this.formatBytes(totalSize)}`;
    }

    // ==================== MULTI-PEER BROADCAST PEER SELECTION ====================

    selectPeer(peerId) {
        this.selectedPeers.add(peerId);
        this.updatePeerList();
    }

    deselectPeer(peerId) {
        this.selectedPeers.delete(peerId);
        this.updatePeerList();
    }

    togglePeerSelection(peerId) {
        if (this.selectedPeers.has(peerId)) {
            this.deselectPeer(peerId);
        } else {
            this.selectPeer(peerId);
        }
    }

    setBroadcastMode(mode) {
        this.broadcastMode = mode === 'selected' ? 'selected' : 'all';
        if (this.broadcastMode === 'all') {
            this.selectedPeers.clear();
        }
        this.updatePeerList();
    }

    // ==================== SPEED TESTING (PER-PEER ISOLATED) ====================

    async runSpeedTest(peerId) {
        const peerInfo = this.connections.get(peerId);
        if (!peerInfo || !peerInfo.conn) {
            this.showToast('Peer not connected', 'error');
            return null;
        }

        // Clean up any stale test on this peer
        this.cleanupSpeedTest(peerId, 'New test initiated');

        const testId = generateUuid();
        const conn = peerInfo.conn;
        this.showToast(`Testing speed to ${peerInfo.username}...`, 'info');
        this.showSpeedTestModal(peerId, testId);

        const results = {
            peerId,
            testId,
            latency: 0,
            uploadSpeed: 0,
            timestamp: Date.now()
        };

        const testEntry = {
            testId,
            pingResolve: null,
            uploadResolve: null,
            expectingTestData: false,
            timer: null
        };
        this.activeSpeedTests.set(peerId, testEntry);

        // 1. Measure Latency (Ping-Pong)
        const pingStart = Date.now();
        const latencyPromise = new Promise(resolve => {
            testEntry.pingResolve = resolve;
            try {
                conn.send({ type: 'speed-test-ping', testId, timestamp: pingStart });
            } catch (e) {
                resolve({ error: true });
            }
        });

        testEntry.timer = setTimeout(() => {
            if (testEntry.pingResolve) testEntry.pingResolve({ timeout: true });
            if (testEntry.uploadResolve) testEntry.uploadResolve({ timeout: true });
        }, ProtocolConstants.SPEED_TEST_TIMEOUT_MS);

        const pingResult = await Promise.race([
            latencyPromise,
            new Promise(r => setTimeout(() => r({ timeout: true }), 5000))
        ]);

        if (pingResult?.timeout || pingResult?.error) {
            this.cleanupSpeedTest(peerId, 'Ping timed out');
            this.showToast('Speed test timed out (ping failure)', 'error');
            return null;
        }

        results.latency = Math.max(1, pingResult.latency);

        // 2. Measure Upload (send 1MB test binary)
        const testDataSize = 1024 * 1024; // 1MB
        const testData = new Uint8Array(testDataSize);
        crypto.getRandomValues(testData.subarray(0, 1024)); // Seed partial

        const uploadStart = Date.now();
        const uploadPromise = new Promise(resolve => {
            testEntry.uploadResolve = resolve;
            try {
                conn.send({ type: 'speed-test-data', testId, size: testDataSize, timestamp: uploadStart });
                conn.send(testData.buffer);
            } catch (e) {
                resolve({ error: true });
            }
        });

        const uploadResult = await Promise.race([
            uploadPromise,
            new Promise(r => setTimeout(() => r({ timeout: true }), 8000))
        ]);

        if (!uploadResult?.timeout && !uploadResult?.error && uploadResult.receivedAt) {
            const uploadTimeSec = Math.max(0.01, (uploadResult.receivedAt - uploadStart) / 1000);
            results.uploadSpeed = testDataSize / uploadTimeSec;
        }

        this.cleanupSpeedTest(peerId);
        this.peerSpeedResults.set(peerId, results);
        this.updateSpeedTestModal(results);
        this.updatePeerList();

        return results;
    }

    handleSpeedTestPing(peerId, data) {
        const conn = this.connections.get(peerId)?.conn;
        if (conn && data.testId) {
            conn.send({
                type: 'speed-test-pong',
                testId: data.testId,
                originalTimestamp: data.timestamp,
                respondedAt: Date.now()
            });
        }
    }

    handleSpeedTestPong(peerId, data) {
        const testEntry = this.activeSpeedTests.get(peerId);
        if (testEntry && testEntry.testId === data.testId && testEntry.pingResolve) {
            const latency = Date.now() - data.originalTimestamp;
            testEntry.pingResolve({ latency });
            testEntry.pingResolve = null;
        }
    }

    handleSpeedTestDataHeader(peerId, data) {
        if (!data || !data.testId) return;
        let testEntry = this.activeSpeedTests.get(peerId);
        // If we are currently running an outbound test with an active promise resolver, do not allow inbound collision
        if (testEntry && (testEntry.pingResolve || testEntry.uploadResolve)) {
            logger.warn(`Speed test conflict on ${peerId}: ignoring incoming header while outbound test active`);
            return;
        }
        if (!testEntry) {
            testEntry = { testId: data.testId, expectingTestData: true, timestamp: data.timestamp };
            this.activeSpeedTests.set(peerId, testEntry);
        } else {
            testEntry.expectingTestData = true;
            testEntry.timestamp = data.timestamp;
            testEntry.testId = data.testId;
        }
    }

    handleSpeedTestDataReceived(peerId, data) {
        const testEntry = this.activeSpeedTests.get(peerId);
        if (!testEntry || !testEntry.expectingTestData) return;
        if (data && data.testId && testEntry.testId && data.testId !== testEntry.testId) {
            logger.warn(`Speed test data ID mismatch for ${peerId}: expected ${testEntry.testId}, got ${data.testId}`);
            return;
        }

        testEntry.expectingTestData = false;
        const conn = this.connections.get(peerId)?.conn;
        if (conn) {
            try {
                conn.send({
                    type: 'speed-test-result',
                    testId: testEntry.testId,
                    originalTimestamp: testEntry.timestamp,
                    receivedAt: Date.now()
                });
            } catch (e) {}
        }
    }

    handleSpeedTestResult(peerId, data) {
        const testEntry = this.activeSpeedTests.get(peerId);
        if (testEntry && testEntry.testId === data.testId && testEntry.uploadResolve) {
            testEntry.uploadResolve({ receivedAt: data.receivedAt });
            testEntry.uploadResolve = null;
        }
    }

    cleanupSpeedTest(peerId, reason = '') {
        const testEntry = this.activeSpeedTests.get(peerId);
        if (testEntry) {
            if (testEntry.timer) clearTimeout(testEntry.timer);
            this.activeSpeedTests.delete(peerId);
            if (reason) logger.log(`Cleaned up speed test for ${peerId}: ${reason}`);
        }
    }

    // ==================== SPEED TRACKING & STATS ====================

    startSpeedTracking() {
        this.startSweeping();
        if (this.speedInterval) return;
        this.speedInterval = setInterval(() => this.updateGlobalStats(), 500);
    }

    stopSpeedTracking() {
        if (this.speedInterval) {
            clearInterval(this.speedInterval);
            this.speedInterval = null;
        }
    }

    updateGlobalStats() {
        let totalCurrentSpeed = 0;
        const now = Date.now();

        // 1. Calculate speeds for active sends
        this.activeSends.forEach((transfer, id) => {
            let transferTransferred = 0;
            transfer.peers.forEach(peerState => {
                transferTransferred += peerState.transferred;
            });

            const elapsed = (now - (transfer.lastSpeedCheck || transfer.startTime)) / 1000;
            if (elapsed > 0.4) {
                const bytesDelta = transferTransferred - (transfer.lastSpeedBytes || 0);
                const currentSpeed = bytesDelta / elapsed;
                totalCurrentSpeed += currentSpeed;

                transfer.lastSpeedBytes = transferTransferred;
                transfer.lastSpeedCheck = now;

                this.updateTransferStatUI(id, currentSpeed, transfer.size - transferTransferred);
            }
        });

        // 2. Calculate speeds for active receives
        this.activeReceives.forEach((receive, id) => {
            const elapsed = (now - (receive.lastSpeedCheck || receive.startTime)) / 1000;
            if (elapsed > 0.4) {
                const bytesDelta = receive.receivedBytes - (receive.lastSpeedBytes || 0);
                const currentSpeed = bytesDelta / elapsed;
                totalCurrentSpeed += currentSpeed;

                receive.lastSpeedBytes = receive.receivedBytes;
                receive.lastSpeedCheck = now;

                this.updateTransferStatUI(id, currentSpeed, receive.size - receive.receivedBytes);
            }
        });

        if (totalCurrentSpeed > this.peakSpeed) {
            this.peakSpeed = totalCurrentSpeed;
        }

        if (this.liveSpeedEl) {
            this.liveSpeedEl.textContent = this.formatSpeed(totalCurrentSpeed);
        }
        if (this.peakSpeedEl) {
            this.peakSpeedEl.textContent = this.formatSpeed(this.peakSpeed);
        }
    }

    updateTransferStatUI(id, speedBytesPerSec, bytesRemaining) {
        const speedEl = document.getElementById(`speed-${id}`);
        const etaEl = document.getElementById(`eta-${id}`);

        if (speedEl) {
            speedEl.textContent = this.formatSpeed(speedBytesPerSec);
        }
        if (etaEl && speedBytesPerSec > 0) {
            etaEl.textContent = this.formatTime(bytesRemaining / speedBytesPerSec);
        }
    }

    // ==================== UI RENDERING (100% XSS SAFE) ====================

    showRoomScreen() {
        if (this.landingScreen) this.landingScreen.style.display = 'none';
        if (this.roomScreen) this.roomScreen.style.display = 'flex';
    }

    showLandingScreen() {
        if (this.roomScreen) this.roomScreen.style.display = 'none';
        if (this.landingScreen) this.landingScreen.style.display = 'flex';
    }

    updateStatus(status) {
        if (!this.connectionStatus) return;

        switch (status) {
            case 'connecting':
                this.connectionStatus.textContent = 'Connecting...';
                this.connectionStatus.style.color = 'var(--text-muted)';
                break;
            case 'connected':
                this.connectionStatus.textContent = `${this.connections.size} Peer(s)`;
                this.connectionStatus.style.color = 'var(--accent)';
                break;
            case 'ready':
                this.connectionStatus.textContent = 'Ready';
                this.connectionStatus.style.color = 'var(--text-muted)';
                break;
            case 'disconnected':
                this.connectionStatus.textContent = 'Disconnected';
                this.connectionStatus.style.color = 'var(--danger)';
                break;
        }
    }

    updatePeerList() {
        if (!this.peerList) return;
        this.peerList.textContent = ''; // Safe clear

        // 1. "Add Peer" pill
        const addPill = document.createElement('div');
        addPill.className = 'peer-pill';
        addPill.style.cursor = 'pointer';

        const addAvatar = document.createElement('div');
        addAvatar.className = 'peer-pill-avatar';
        addAvatar.style.cssText = 'background: var(--bg-surface); border: 1px dashed var(--text-muted); color: var(--text-muted);';
        addAvatar.textContent = '+';
        addPill.appendChild(addAvatar);

        const addText = document.createElement('span');
        addText.textContent = 'Add';
        addPill.appendChild(addText);

        addPill.onclick = () => {
            const id = prompt('Enter Peer ID to connect:');
            if (id) this.connectToPeer(id.toUpperCase().trim());
        };
        this.peerList.appendChild(addPill);

        // 2. Connected Peer Pills
        this.connections.forEach((peerInfo, peerId) => {
            const isSelected = this.broadcastMode === 'all' || this.selectedPeers.has(peerId);
            const speedResult = this.peerSpeedResults.get(peerId);

            const pill = document.createElement('div');
            pill.className = `peer-pill active ${isSelected ? 'selected' : ''}`;
            if (isSelected) {
                pill.style.borderColor = 'var(--accent)';
                pill.style.background = 'rgba(52, 211, 153, 0.1)';
            }

            // Checkbox for selection
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'peer-select-checkbox';
            checkbox.checked = isSelected;
            checkbox.style.cssText = 'width: 16px; height: 16px; accent-color: var(--accent); cursor: pointer;';
            checkbox.onclick = (e) => {
                e.stopPropagation();
                this.togglePeerSelection(peerId);
            };
            pill.appendChild(checkbox);

            // Avatar
            const avatar = document.createElement('div');
            avatar.className = 'peer-pill-avatar';
            avatar.textContent = (peerInfo.username || 'P').charAt(0).toUpperCase();
            pill.appendChild(avatar);

            // Name & ID
            const metaContainer = document.createElement('div');
            metaContainer.style.flex = '1';

            const nameRow = document.createElement('div');
            nameRow.style.cssText = 'font-weight: 600; line-height: 1; display: flex; align-items: center;';
            
            const nameText = document.createElement('span');
            nameText.textContent = peerInfo.username;
            nameRow.appendChild(nameText);

            if (speedResult && speedResult.latency) {
                const badge = document.createElement('span');
                badge.style.cssText = 'font-size: 0.65rem; background: var(--accent-glow); color: var(--accent); padding: 0.15rem 0.4rem; border-radius: 4px; margin-left: 0.5rem;';
                badge.textContent = `${speedResult.latency}ms`;
                nameRow.appendChild(badge);
            }

            if (peerInfo.candidateType) {
                const candBadge = document.createElement('span');
                candBadge.style.cssText = 'font-size: 0.6rem; opacity: 0.7; margin-left: 0.35rem;';
                candBadge.textContent = `[${peerInfo.candidateType}]`;
                nameRow.appendChild(candBadge);
            }

            metaContainer.appendChild(nameRow);

            const idRow = document.createElement('div');
            idRow.style.cssText = 'font-size: 0.7rem; opacity: 0.7;';
            idRow.textContent = peerId;
            metaContainer.appendChild(idRow);

            pill.appendChild(metaContainer);

            // Speed test button
            const speedBtn = document.createElement('button');
            speedBtn.className = 'speed-test-btn';
            speedBtn.style.cssText = 'background: var(--bg-main); border: none; padding: 0.3rem 0.5rem; border-radius: 6px; cursor: pointer; color: var(--text-muted); font-size: 0.75rem;';
            speedBtn.title = 'Test Connection Speed';
            speedBtn.textContent = '⚡';
            speedBtn.onclick = (e) => {
                e.stopPropagation();
                this.runSpeedTest(peerId);
            };
            pill.appendChild(speedBtn);

            this.peerList.appendChild(pill);
        });

        // 3. Broadcast Mode Toggle
        if (this.connections.size > 1) {
            const togglePill = document.createElement('div');
            togglePill.className = 'peer-pill';
            togglePill.style.cssText = 'background: var(--bg-main); cursor: pointer;';

            const toggleSpan = document.createElement('span');
            toggleSpan.style.cssText = 'font-size: 0.8rem; color: var(--text-muted);';
            toggleSpan.textContent = this.broadcastMode === 'all' ? '📡 Send to All' : '🎯 Send to Selected';
            togglePill.appendChild(toggleSpan);

            togglePill.onclick = () => {
                this.setBroadcastMode(this.broadcastMode === 'all' ? 'selected' : 'all');
            };
            this.peerList.appendChild(togglePill);
        }
    }

    addTransferToUI(id, name, size, direction) {
        if (!this.transferQueue) return;

        const card = document.createElement('div');
        card.className = 'file-card-modern';
        card.id = `transfer-${id}`;

        const iconColor = direction === 'receive' ? 'var(--accent)' : 'var(--primary)';

        // Icon Container
        const iconDiv = document.createElement('div');
        iconDiv.style.cssText = `color: ${iconColor}; background: rgba(255,255,255,0.05); padding: 0.5rem; border-radius: 8px;`;
        iconDiv.textContent = direction === 'receive' ? '📥' : '📤';
        card.appendChild(iconDiv);

        // Info Container
        const infoDiv = document.createElement('div');
        infoDiv.style.cssText = 'flex: 1; min-width: 0;';

        const nameDiv = document.createElement('div');
        nameDiv.style.cssText = 'font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;';
        nameDiv.textContent = name; // Safe text
        infoDiv.appendChild(nameDiv);

        const metaDiv = document.createElement('div');
        metaDiv.style.cssText = 'font-size: 0.8rem; color: var(--text-muted); display: flex; gap: 0.5rem;';

        const sizeSpan = document.createElement('span');
        sizeSpan.textContent = this.formatBytes(size);
        metaDiv.appendChild(sizeSpan);

        const speedSpan = document.createElement('span');
        speedSpan.id = `speed-${id}`;
        speedSpan.style.color = iconColor;
        metaDiv.appendChild(speedSpan);

        infoDiv.appendChild(metaDiv);
        card.appendChild(infoDiv);

        // Stats Container
        const statsDiv = document.createElement('div');
        statsDiv.style.textAlign = 'right';

        const percentDiv = document.createElement('div');
        percentDiv.id = `percent-${id}`;
        percentDiv.style.fontWeight = 'bold';
        percentDiv.textContent = '0%';
        statsDiv.appendChild(percentDiv);

        const etaDiv = document.createElement('div');
        etaDiv.id = `eta-${id}`;
        etaDiv.style.cssText = 'font-size: 0.7rem; color: var(--text-muted);';
        etaDiv.textContent = '--';
        statsDiv.appendChild(etaDiv);

        card.appendChild(statsDiv);

        // Cancel Button
        const cancelBtn = document.createElement('button');
        cancelBtn.style.cssText = 'background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 0.3rem; margin-left: 0.5rem;';
        cancelBtn.title = 'Cancel Transfer';
        cancelBtn.textContent = '✕';
        cancelBtn.onclick = () => this.cancelTransfer(id);
        card.appendChild(cancelBtn);

        // Progress Bar
        const progressBg = document.createElement('div');
        progressBg.className = 'progress-bg';
        progressBg.id = `progress-${id}`;
        progressBg.style.width = '0%';
        card.appendChild(progressBg);

        this.transferQueue.insertBefore(card, this.transferQueue.firstChild);
    }

    updateTransferUI(id, progress) {
        const bar = document.getElementById(`progress-${id}`);
        const percent = document.getElementById(`percent-${id}`);
        if (bar) bar.style.width = `${Math.round(progress * 100)}%`;
        if (percent) percent.textContent = `${Math.round(progress * 100)}%`;
    }

    setTransferVerifyingUI(id) {
        const percent = document.getElementById(`percent-${id}`);
        const eta = document.getElementById(`eta-${id}`);
        if (percent) percent.textContent = 'Verifying...';
        if (eta) eta.textContent = 'SHA-256';
    }

    completeTransferUI(id, size, startTime) {
        const bar = document.getElementById(`progress-${id}`);
        const percent = document.getElementById(`percent-${id}`);
        const eta = document.getElementById(`eta-${id}`);

        if (bar) bar.style.width = '100%';
        if (percent) {
            percent.textContent = '✓ Complete';
            percent.style.color = 'var(--accent)';
        }
        if (eta) eta.textContent = 'Verified';
    }

    failTransferUI(id, reason) {
        const percent = document.getElementById(`percent-${id}`);
        const eta = document.getElementById(`eta-${id}`);
        const bar = document.getElementById(`progress-${id}`);

        if (bar) bar.style.background = 'var(--danger)';
        if (percent) {
            percent.textContent = '✕ Failed';
            percent.style.color = 'var(--danger)';
        }
        if (eta) {
            eta.textContent = reason || 'Error';
            eta.style.color = 'var(--danger)';
        }
    }

    removeTransferFromUI(id) {
        const card = document.getElementById(`transfer-${id}`);
        if (card) card.remove();
    }

    showToast(message, type = 'info') {
        if (!this.toastContainer) return;

        const icons = { success: '✓', error: '✕', info: 'ℹ' };
        const colors = {
            success: 'var(--accent)',
            error: 'var(--danger)',
            info: 'var(--primary)'
        };

        const toast = document.createElement('div');
        toast.style.cssText = `
            background: var(--bg-surface);
            border: 1px solid var(--border-light);
            padding: 0.85rem 1.25rem;
            border-radius: 12px;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            box-shadow: var(--shadow-lg);
            animation: slideIn 0.3s ease;
            max-width: 400px;
        `;

        const iconSpan = document.createElement('span');
        iconSpan.style.color = colors[type] || colors.info;
        iconSpan.style.fontWeight = 'bold';
        iconSpan.textContent = icons[type] || 'ℹ';
        toast.appendChild(iconSpan);

        const textSpan = document.createElement('span');
        textSpan.style.fontSize = '0.9rem';
        textSpan.textContent = message; // Safe text
        toast.appendChild(textSpan);

        this.toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            toast.style.transition = 'all 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 3500);
    }

    // ==================== SHARE LINKS & QR CODES (DYNAMIC ORIGIN) ====================

    generateShareLink() {
        if (!this.myPeerId) return null;
        const origin = window.location.origin;
        const pathname = window.location.pathname.replace(/\/+$/, '');
        return `${origin}${pathname}?join=${encodeURIComponent(this.myPeerId)}`;
    }

    showQrCode() {
        const modal = document.getElementById('qrModal');
        const container = document.getElementById('qrCodeContainer');
        const closeBtn = document.getElementById('closeQrModal');

        if (!modal || !container) return;
        container.textContent = '';

        const shareUrl = this.generateShareLink();
        if (!shareUrl) {
            this.showToast('Please wait for your Peer ID to initialize', 'error');
            return;
        }

        if (window.QRCode) {
            new QRCode(container, {
                text: shareUrl,
                width: 200,
                height: 200,
                colorDark: '#000000',
                colorLight: '#ffffff',
                correctLevel: QRCode.CorrectLevel.H
            });
            modal.style.display = 'flex';
        } else {
            this.showToast('QRCode library failed to load', 'error');
        }

        const close = () => modal.style.display = 'none';
        if (closeBtn) closeBtn.onclick = close;
        modal.onclick = (e) => { if (e.target === modal) close(); };
    }

    showShareModal() {
        const link = this.generateShareLink();
        if (!link) {
            this.showToast('Peer ID not ready yet', 'error');
            return;
        }

        const existing = document.getElementById('shareModal');
        if (existing) existing.remove();

        const modal = document.createElement('div');
        modal.id = 'shareModal';
        modal.style.cssText = `position: fixed; inset: 0; background: rgba(0,0,0,0.8); backdrop-filter: blur(8px); display: flex; align-items: center; justify-content: center; z-index: 200;`;

        const card = document.createElement('div');
        card.style.cssText = `background: var(--bg-surface); border-radius: 24px; padding: 2.5rem; max-width: 450px; width: 90%; text-align: center; border: 1px solid var(--border-light);`;

        const title = document.createElement('h2');
        title.style.marginBottom = '0.5rem';
        title.textContent = 'Share Your Session';
        card.appendChild(title);

        const sub = document.createElement('p');
        sub.style.cssText = 'color: var(--text-muted); margin-bottom: 1.5rem;';
        sub.textContent = 'Send this link to anyone to connect instantly';
        card.appendChild(sub);

        // Input & Copy Row
        const row = document.createElement('div');
        row.style.cssText = 'background: var(--bg-main); padding: 0.75rem 1rem; border-radius: 12px; margin-bottom: 1.5rem; display: flex; align-items: center; gap: 0.5rem;';

        const input = document.createElement('input');
        input.type = 'text';
        input.readOnly = true;
        input.value = link;
        input.style.cssText = 'flex: 1; background: transparent; border: none; color: var(--text-primary); font-size: 0.85rem; outline: none; font-family: monospace;';
        row.appendChild(input);

        const copyBtn = document.createElement('button');
        copyBtn.className = 'btn-primary';
        copyBtn.style.padding = '0.5rem 1rem';
        copyBtn.textContent = 'Copy';
        copyBtn.onclick = () => {
            navigator.clipboard.writeText(link)
                .then(() => this.showToast('Share link copied!', 'success'))
                .catch(() => this.showToast('Failed to copy link', 'error'));
        };
        row.appendChild(copyBtn);
        card.appendChild(row);

        // QR Code
        const qrContainer = document.createElement('div');
        qrContainer.style.cssText = 'display: flex; justify-content: center; margin-bottom: 1.5rem; padding: 1rem; background: white; border-radius: 12px; width: fit-content; margin-left: auto; margin-right: auto;';
        card.appendChild(qrContainer);

        if (window.QRCode) {
            new QRCode(qrContainer, {
                text: link,
                width: 150,
                height: 150,
                colorDark: '#000000',
                colorLight: '#ffffff',
                correctLevel: QRCode.CorrectLevel.H
            });
        }

        const closeBtn = document.createElement('button');
        closeBtn.className = 'btn-ghost';
        closeBtn.style.width = '100%';
        closeBtn.textContent = 'Close';
        closeBtn.onclick = () => modal.remove();
        card.appendChild(closeBtn);

        modal.appendChild(card);
        modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
        document.body.appendChild(modal);
    }

    // ==================== TEXT SHARING (DIRECT + ONE-TIME LINK) ====================

    showTextShareModal() {
        if (!this.myPeerId) {
            this.showToast('Start hosting first!', 'error');
            return;
        }

        const existing = document.getElementById('textShareModal');
        if (existing) existing.remove();

        const modal = document.createElement('div');
        modal.id = 'textShareModal';
        modal.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.8); backdrop-filter: blur(8px); display: flex; align-items: center; justify-content: center; z-index: 200;';

        const card = document.createElement('div');
        card.style.cssText = 'background: var(--bg-surface); border-radius: 24px; padding: 2.5rem; max-width: 550px; width: 95%; text-align: center; border: 1px solid var(--border-light); max-height: 85vh; overflow-y: auto;';

        const title = document.createElement('h2');
        title.style.marginBottom = '0.5rem';
        title.textContent = 'Share Text Directly';
        card.appendChild(title);

        const sub = document.createElement('p');
        sub.style.cssText = 'color: var(--text-muted); margin-bottom: 1.25rem; font-size: 0.9rem;';
        sub.textContent = 'Text is streamed peer-to-peer over WebRTC—never saved on any server. Only peers connected right now receive it.';
        card.appendChild(sub);

        const textarea = document.createElement('textarea');
        textarea.placeholder = 'Type or paste text to share...';
        textarea.style.cssText = 'width: 100%; min-height: 140px; background: var(--bg-main); border: 1px solid var(--border-light); border-radius: 12px; padding: 1rem; color: var(--text-primary); outline: none; font-family: monospace; resize: vertical; margin-bottom: 1rem;';
        card.appendChild(textarea);

        const sendBtn = document.createElement('button');
        sendBtn.className = 'btn-primary';
        sendBtn.style.cssText = 'width: 100%; padding: 0.75rem; margin-bottom: 0.75rem;';
        sendBtn.textContent = 'Send to Connected Peers';
        sendBtn.onclick = () => {
            const raw = textarea.value.trim();
            if (!raw) {
                this.showToast('Enter some text to share', 'error');
                return;
            }

            const safe = sanitizeText(raw);
            const targets = this.getTargetConnections();

            // Zero targets is an error, never a silent no-op
            if (targets.length === 0) {
                this.showToast('No peers selected. Select at least one peer or choose "Send to All".', 'error');
                return;
            }

            let delivered = 0;
            targets.forEach(({ conn }) => {
                try {
                    conn.send({ type: 'text-share', text: safe });
                    delivered++;
                } catch (e) {}
            });

            if (delivered === 0) {
                this.showToast('Failed to send text: no peer could be contacted.', 'error');
                return;
            }

            // Fire-and-forget: nothing is retained for peers joining later
            this.showToast(`Text sent to ${delivered} peer(s).`, 'success');
            modal.remove();
        };
        card.appendChild(sendBtn);

        const linkBtn = document.createElement('button');
        linkBtn.className = 'btn-ghost';
        linkBtn.style.cssText = 'width: 100%; padding: 0.75rem; margin-bottom: 0.75rem;';
        linkBtn.textContent = 'Create One-Time Text Link';
        linkBtn.onclick = () => {
            const raw = textarea.value.trim();
            if (!raw) {
                this.showToast('Enter some text to share', 'error');
                return;
            }

            const safe = sanitizeText(raw);
            const token = generateUuid();
            // One-time, expiring link token. The token is required verbatim:
            // a peer without the exact token never receives the text.
            this.activeTextLink = {
                token,
                text: safe,
                expiresAt: Date.now() + ProtocolConstants.TEXT_SHARE_LINK_TTL_MS,
                used: false
            };

            const base = this.generateShareLink();
            const link = `${base}&t=${encodeURIComponent(token)}`;

            navigator.clipboard.writeText(link)
                .then(() => this.showToast('One-time text link copied! It expires in 10 minutes.', 'success'))
                .catch(() => this.showToast('Link created but could not be copied: ' + link, 'warning'));
            modal.remove();
        };
        card.appendChild(linkBtn);

        const closeBtn = document.createElement('button');
        closeBtn.className = 'btn-ghost';
        closeBtn.style.width = '100%';
        closeBtn.textContent = 'Close';
        closeBtn.onclick = () => modal.remove();
        card.appendChild(closeBtn);

        modal.appendChild(card);
        modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
        document.body.appendChild(modal);
    }

    /**
     * Called when a peer connects presenting a text-share token. Delivers the
     * active one-time link text ONLY on an exact, unexpired, unused token
     * match; the link is single-use and cleared after delivery.
     */
    deliverTextLinkIfMatched(peerId, receiverToken) {
        if (!this.activeTextLink) return;

        const link = this.activeTextLink;
        if (link.used || Date.now() > link.expiresAt) {
            this.activeTextLink = null;
            if (receiverToken) {
                const conn = this.connections.get(peerId)?.conn;
                try { conn?.send({ type: 'text-share-miss', token: receiverToken }); } catch (e) {}
            }
            return;
        }

        const conn = this.connections.get(peerId)?.conn;
        if (!conn) return;

        if (!receiverToken || receiverToken !== link.token) {
            // No token or wrong token = no text. Never send to tokenless peers.
            logger.warn(`Text link token mismatch from ${peerId}`);
            if (receiverToken) {
                try { conn.send({ type: 'text-share-miss', token: receiverToken }); } catch (e) {}
            }
            return;
        }

        try {
            conn.send({ type: 'text-share', token: link.token, text: link.text });
            link.used = true;
            this.activeTextLink = null; // one-time: cleared after delivery
            logger.info(`One-time text link delivered to ${peerId}`);
        } catch (e) {}
    }

    handleTextShare(peerId, data) {
        if (typeof data.text !== 'string') return;
        const senderName = this.connections.get(peerId)?.username || peerId;
        const safe = sanitizeText(data.text);
        const linkToken = typeof data.token === 'string' ? data.token : null;

        // Link flow: the receiver must have requested this exact token via the
        // share link. No token requested -> refuse link-based delivery.
        if (linkToken && linkToken !== this.textShareTokenFromUrl) {
            logger.warn(`Text share token mismatch from ${peerId}; ignoring.`);
            return;
        }

        // Consent prompt: incoming text is never shown without user approval
        const modal = document.createElement('div');
        modal.className = 'velo-consent-modal';
        modal.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.8); backdrop-filter: blur(8px); display: flex; align-items: center; justify-content: center; z-index: 250;';

        const card = document.createElement('div');
        card.style.cssText = 'background: var(--bg-surface); border-radius: 24px; padding: 2rem; max-width: 650px; width: 95%; border: 1px solid var(--border-light); text-align: center; max-height: 85vh; overflow-y: auto;';

        const title = document.createElement('h2');
        title.style.marginBottom = '0.5rem';
        title.textContent = 'Incoming text';
        card.appendChild(title);

        const desc = document.createElement('p');
        desc.style.cssText = 'color: var(--text-muted); margin-bottom: 1rem; font-size: 0.9rem;';
        desc.textContent = `${senderName} sent you ${safe.length} characters of text.`;
        card.appendChild(desc);

        const preview = document.createElement('pre');
        preview.style.cssText = 'white-space: pre-wrap; word-break: break-word; max-height: 20vh; overflow: auto; background: var(--bg-main); padding: 1rem; border-radius: 12px; border: 1px solid var(--border-light); color: var(--text-primary); font-family: monospace; text-align: left; margin-bottom: 1.25rem;';
        preview.textContent = safe.slice(0, 500) + (safe.length > 500 ? '…' : '');
        card.appendChild(preview);

        const btnRow = document.createElement('div');
        btnRow.style.cssText = 'display: flex; gap: 0.75rem; margin-bottom: 0.75rem;';

        const acceptBtn = document.createElement('button');
        acceptBtn.className = 'btn-primary';
        acceptBtn.style.flex = '1';
        acceptBtn.textContent = 'Accept';
        acceptBtn.onclick = () => {
            modal.remove();
            this.showReceivedTextModal(safe);
        };
        btnRow.appendChild(acceptBtn);

        const declineBtn = document.createElement('button');
        declineBtn.className = 'btn-ghost';
        declineBtn.style.flex = '1';
        declineBtn.textContent = 'Decline';
        declineBtn.onclick = () => {
            modal.remove();
            this.showToast(`Declined text from ${senderName}`, 'info');
        };
        btnRow.appendChild(declineBtn);

        card.appendChild(btnRow);
        modal.appendChild(card);
        modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
        document.body.appendChild(modal);

        if (linkToken) {
            this.textShareTokenFromUrl = null; // token consumed
        }
    }

    showReceivedTextModal(safe) {
        const existing = document.getElementById('receivedTextModal');
        if (existing) existing.remove();

        const modal = document.createElement('div');
        modal.id = 'receivedTextModal';
        modal.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.8); backdrop-filter: blur(8px); display: flex; align-items: center; justify-content: center; z-index: 200;';

        const card = document.createElement('div');
        card.style.cssText = 'background: var(--bg-surface); border-radius: 24px; padding: 2.5rem; max-width: 650px; width: 95%; text-align: center; border: 1px solid var(--border-light); max-height: 85vh; overflow-y: auto;';

        const title = document.createElement('h2');
        title.style.marginBottom = '0.5rem';
        title.textContent = 'Received Text';
        card.appendChild(title);

        const pre = document.createElement('pre');
        pre.style.cssText = 'white-space: pre-wrap; word-break: break-word; max-height: 45vh; overflow: auto; background: var(--bg-main); padding: 1rem; border-radius: 12px; border: 1px solid var(--border-light); color: var(--text-primary); font-family: monospace; text-align: left; margin-bottom: 1.25rem;';
        pre.textContent = safe; // 100% XSS safe
        card.appendChild(pre);

        const btnRow = document.createElement('div');
        btnRow.style.cssText = 'display: flex; gap: 0.75rem;';

        const copyBtn = document.createElement('button');
        copyBtn.className = 'btn-primary';
        copyBtn.style.flex = '1';
        copyBtn.textContent = 'Copy Text';
        copyBtn.onclick = () => {
            navigator.clipboard.writeText(safe)
                .then(() => this.showToast('Text copied to clipboard!', 'success'))
                .catch(() => this.showToast('Failed to copy', 'error'));
        };
        btnRow.appendChild(copyBtn);

        const closeBtn = document.createElement('button');
        closeBtn.className = 'btn-ghost';
        closeBtn.style.flex = '1';
        closeBtn.textContent = 'Close';
        closeBtn.onclick = () => modal.remove();
        btnRow.appendChild(closeBtn);

        card.appendChild(btnRow);
        modal.appendChild(card);
        modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
        document.body.appendChild(modal);
    }

    // ==================== NETWORK & ICE SETTINGS MODAL ====================

    showNetworkSettingsModal() {
        const existing = document.getElementById('networkModal');
        if (existing) existing.remove();

        const modal = document.createElement('div');
        modal.id = 'networkModal';
        modal.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.8); backdrop-filter: blur(8px); display: flex; align-items: center; justify-content: center; z-index: 200;';

        const card = document.createElement('div');
        card.style.cssText = 'background: var(--bg-surface); border-radius: 24px; padding: 2.5rem; max-width: 550px; width: 95%; border: 1px solid var(--border-light); max-height: 85vh; overflow-y: auto; text-align: left;';

        const title = document.createElement('h2');
        title.style.marginBottom = '0.5rem';
        title.textContent = 'WebRTC & TURN Settings';
        card.appendChild(title);

        const desc = document.createElement('p');
        desc.style.cssText = 'color: var(--text-muted); font-size: 0.85rem; margin-bottom: 1.5rem; line-height: 1.4;';
        desc.textContent = 'Velo uses direct peer-to-peer lanes by default. When connecting across restrictive firewalls, symmetric NATs, or mobile cellular data, configure a TURN relay server (coturn, Metered.ca, Twilio, etc.) below.';
        card.appendChild(desc);

        // Status diagnostics
        const diagBox = document.createElement('div');
        diagBox.style.cssText = 'background: var(--bg-main); padding: 1rem; border-radius: 12px; margin-bottom: 1.25rem; font-family: monospace; font-size: 0.8rem;';
        
        const iceConfig = window.VeloConfig ? window.VeloConfig.getIceConfig() : { iceServers: [] };
        const stunCount = iceConfig.iceServers.filter(s => {
            const urls = Array.isArray(s.urls) ? s.urls : [s.urls];
            return urls.some(u => u.startsWith('stun:'));
        }).length;
        const turnCount = iceConfig.iceServers.filter(s => {
            const urls = Array.isArray(s.urls) ? s.urls : [s.urls];
            return urls.some(u => u.startsWith('turn:') || u.startsWith('turns:'));
        }).length;

        diagBox.textContent = `Signaling State: ${this.signalingState}\nSTUN Servers: ${stunCount}\nTURN Relays: ${turnCount}\nActive Peers: ${this.connections.size}`;
        card.appendChild(diagBox);

        // TURN JSON textarea
        const label = document.createElement('label');
        label.style.cssText = 'display: block; font-weight: 600; font-size: 0.85rem; margin-bottom: 0.35rem;';
        label.textContent = 'Custom ICE / TURN Servers (JSON Array):';
        card.appendChild(label);

        const textarea = document.createElement('textarea');
        textarea.style.cssText = 'width: 100%; min-height: 120px; background: var(--bg-main); border: 1px solid var(--border-light); border-radius: 8px; padding: 0.75rem; color: var(--text-primary); font-family: monospace; font-size: 0.8rem; margin-bottom: 1rem; outline: none;';
        textarea.placeholder = `[\n  {\n    "urls": ["turn:turn.example.com:3478"],\n    "username": "user",\n    "credential": "password"\n  }\n]`;

        const saved = (() => {
            try { return localStorage.getItem('velo_custom_ice_servers'); } catch (e) { return null; }
        })();
        if (saved) textarea.value = saved;
        card.appendChild(textarea);

        // Warn that applying new ICE servers re-inits the peer: the Peer ID
        // and all previously shared links change and current peers drop.
        const warn = document.createElement('p');
        warn.style.cssText = 'color: var(--text-muted); font-size: 0.8rem; margin-bottom: 1rem;';
        warn.textContent = '⚠️ Applying new settings reconnects you with a NEW Peer ID. Previously shared links/QR codes stop working and connected peers are disconnected.';
        card.appendChild(warn);

        // Buttons
        const btnRow = document.createElement('div');
        btnRow.style.cssText = 'display: flex; gap: 0.75rem;';

        const saveBtn = document.createElement('button');
        saveBtn.className = 'btn-primary';
        saveBtn.style.flex = '1';
        saveBtn.textContent = 'Save & Apply';
        let saveArmed = false;
        saveBtn.onclick = () => {
            // Two-step confirm: the first click arms the button so the user
            // sees that the Peer ID will change before anything happens.
            if (!saveArmed) {
                saveArmed = true;
                saveBtn.textContent = 'Confirm — my Peer ID will change';
                setTimeout(() => {
                    saveArmed = false;
                    saveBtn.textContent = 'Save & Apply';
                }, 4000);
                return;
            }
            saveArmed = false;
            saveBtn.textContent = 'Save & Apply';

            if (this.activeSends.size > 0 || this.activeReceives.size > 0 || this.isSending) {
                this.showToast('Cannot change network settings during active transfers', 'error');
                return;
            }

            let val;
            try {
                val = textarea.value.trim();
            } catch (e) {
                val = '';
            }
            if (!val) {
                if (window.VeloConfig) window.VeloConfig.setCustomIceServers(null);
                this.showToast('Custom TURN servers cleared. Default STUN active.', 'info');
                modal.remove();
                if (this.myPeerId) {
                    if (this.peer && !this.peer.destroyed) {
                        try { this.peer.destroy(); } catch (e) {}
                    }
                    this.initPeer();
                }
                return;
            }

            try {
                const parsed = JSON.parse(val);
                if (!Array.isArray(parsed)) throw new Error('Must be a JSON array of server objects');
                if (window.VeloConfig) window.VeloConfig.setCustomIceServers(parsed);
                this.showToast('TURN configuration saved! Reconnecting with a new Peer ID...', 'success');
                modal.remove();
                // Safely destroy previous peer and re-initialize with new ICE servers
                if (this.myPeerId) {
                    if (this.peer && !this.peer.destroyed) {
                        try { this.peer.destroy(); } catch (e) {}
                    }
                    this.initPeer();
                }
            } catch (err) {
                this.showToast(`Invalid JSON format: ${err.message}`, 'error');
            }
        };
        btnRow.appendChild(saveBtn);

        const closeBtn = document.createElement('button');
        closeBtn.className = 'btn-ghost';
        closeBtn.style.flex = '1';
        closeBtn.textContent = 'Close';
        closeBtn.onclick = () => modal.remove();
        btnRow.appendChild(closeBtn);

        card.appendChild(btnRow);
        modal.appendChild(card);
        modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
        document.body.appendChild(modal);
    }

    // ==================== SPEED TEST MODAL ====================

    showSpeedTestModal(peerId, testId) {
        const peerInfo = this.connections.get(peerId);
        const existing = document.getElementById('speedTestModal');
        if (existing) existing.remove();

        const modal = document.createElement('div');
        modal.id = 'speedTestModal';
        modal.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.8); backdrop-filter: blur(8px); display: flex; align-items: center; justify-content: center; z-index: 200;';

        const card = document.createElement('div');
        card.style.cssText = 'background: var(--bg-surface); border-radius: 24px; padding: 2.5rem; max-width: 400px; width: 90%; text-align: center; border: 1px solid var(--border-light);';

        const title = document.createElement('h2');
        title.style.marginBottom = '0.5rem';
        title.textContent = 'Connection Speed Test';
        card.appendChild(title);

        const sub = document.createElement('p');
        sub.style.cssText = 'color: var(--text-muted); margin-bottom: 1.5rem; font-size: 0.9rem;';
        sub.textContent = `Testing lane to ${peerInfo?.username || peerId}`;
        card.appendChild(sub);

        const progressDiv = document.createElement('div');
        progressDiv.id = 'speedTestProgress';
        progressDiv.style.margin = '2rem 0';

        const spinner = document.createElement('div');
        spinner.style.cssText = 'width: 48px; height: 48px; margin: 0 auto; border: 3px solid var(--border-light); border-top-color: var(--accent); border-radius: 50%; animation: spin 1s linear infinite;';
        progressDiv.appendChild(spinner);

        const measuringText = document.createElement('p');
        measuringText.style.cssText = 'margin-top: 1rem; color: var(--text-muted); font-size: 0.9rem;';
        measuringText.textContent = 'Measuring latency and bandwidth...';
        progressDiv.appendChild(measuringText);

        card.appendChild(progressDiv);

        const resultsDiv = document.createElement('div');
        resultsDiv.id = 'speedTestResults';
        resultsDiv.style.cssText = 'display: none; margin: 1.5rem 0;';

        const grid = document.createElement('div');
        grid.style.cssText = 'display: grid; gap: 1rem;';

        const latBox = document.createElement('div');
        latBox.style.cssText = 'background: var(--bg-main); padding: 1rem; border-radius: 12px;';
        latBox.innerHTML = '<div style="color: var(--text-muted); font-size: 0.75rem;">LATENCY</div><div id="testLatency" style="font-size: 1.5rem; font-weight: 700; color: var(--primary);">--</div>';
        grid.appendChild(latBox);

        const upBox = document.createElement('div');
        upBox.style.cssText = 'background: var(--bg-main); padding: 1rem; border-radius: 12px;';
        upBox.innerHTML = '<div style="color: var(--text-muted); font-size: 0.75rem;">UPLOAD SPEED</div><div id="testUpload" style="font-size: 1.5rem; font-weight: 700; color: var(--accent);">--</div>';
        grid.appendChild(upBox);

        resultsDiv.appendChild(grid);
        card.appendChild(resultsDiv);

        const closeBtn = document.createElement('button');
        closeBtn.className = 'btn-ghost';
        closeBtn.style.width = '100%';
        closeBtn.textContent = 'Close';
        closeBtn.onclick = () => modal.remove();
        card.appendChild(closeBtn);

        modal.appendChild(card);
        modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
        document.body.appendChild(modal);
    }

    updateSpeedTestModal(results) {
        const progress = document.getElementById('speedTestProgress');
        const resultsDiv = document.getElementById('speedTestResults');
        const latEl = document.getElementById('testLatency');
        const upEl = document.getElementById('testUpload');

        if (progress) progress.style.display = 'none';
        if (resultsDiv) resultsDiv.style.display = 'block';
        if (latEl) latEl.textContent = `${results.latency}ms`;
        if (upEl) upEl.textContent = this.formatSpeed(results.uploadSpeed);
    }

    // ==================== AUDIO & EFFECTS ====================

    playSound(type) {
        try {
            if (!this.audioCtx) {
                this.audioCtx = new (window.AudioContext || window.webkitAudioContext)();
            }
            if (this.audioCtx.state === 'suspended') {
                this.audioCtx.resume();
            }

            const osc = this.audioCtx.createOscillator();
            const gain = this.audioCtx.createGain();
            osc.connect(gain);
            gain.connect(this.audioCtx.destination);

            const now = this.audioCtx.currentTime;
            if (type === 'connect') {
                osc.frequency.setValueAtTime(440, now);
                osc.frequency.exponentialRampToValueAtTime(880, now + 0.1);
                gain.gain.setValueAtTime(0.1, now);
                gain.gain.exponentialRampToValueAtTime(0.01, now + 0.1);
                osc.start(now);
                osc.stop(now + 0.1);
            } else if (type === 'complete') {
                osc.frequency.setValueAtTime(523.25, now);
                osc.frequency.setValueAtTime(659.25, now + 0.1);
                gain.gain.setValueAtTime(0.1, now);
                gain.gain.linearRampToValueAtTime(0.01, now + 0.3);
                osc.start(now);
                osc.stop(now + 0.3);
            }
        } catch (e) {}
    }

    playCompletionSound() {
        this.playSound('complete');
    }

    saveHistory(transfer, direction) {
        try {
            const history = JSON.parse(localStorage.getItem('velo_history') || '[]');
            history.unshift({
                name: transfer.name,
                size: transfer.size,
                date: Date.now(),
                direction,
                peer: transfer.peer
            });
            if (history.length > 50) history.pop();
            localStorage.setItem('velo_history', JSON.stringify(history));
        } catch (e) {}
    }

    // ==================== FORMATTERS ====================

    formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    formatSpeed(bytesPerSec) {
        if (!bytesPerSec || bytesPerSec === 0) return '0 MB/s';
        const mbps = bytesPerSec / (1024 * 1024);
        if (mbps >= 1) return mbps.toFixed(1) + ' MB/s';
        const kbps = bytesPerSec / 1024;
        return kbps.toFixed(0) + ' KB/s';
    }

    formatTime(seconds) {
        if (!isFinite(seconds) || seconds < 0) return '--';
        if (seconds < 1) return '< 1s';
        if (seconds < 60) return Math.round(seconds) + 's';
        const mins = Math.floor(seconds / 60);
        const secs = Math.round(seconds % 60);
        return `${mins}m ${secs}s`;
    }

    // ==================== OBSERVABILITY DIAGNOSTICS ====================

    getDiagnostics() {
        return {
            timestamp: new Date().toISOString(),
            myPeerId: this.myPeerId,
            signalingState: this.signalingState,
            reconnectAttempts: this.reconnectAttempts,
            connections: Array.from(this.connections.entries()).map(([id, info]) => ({
                peerId: id,
                username: info.username,
                state: info.state,
                candidateType: info.candidateType || 'unknown',
                bufferedAmount: info.conn?.dataChannel?.bufferedAmount || 0,
                connectedDurationSec: Math.round((Date.now() - info.connectedAt) / 1000)
            })),
            pendingConnections: Array.from(this.pendingConnections.keys()),
            activeSends: Array.from(this.activeSends.values()).map(s => ({
                id: s.id,
                name: s.name,
                size: s.size,
                peers: Array.from(s.peers.entries()).map(([pid, st]) => ({
                    peerId: pid,
                    status: st.status,
                    transferred: st.transferred
                }))
            })),
            activeReceives: Array.from(this.activeReceives.values()).map(r => ({
                id: r.transferId,
                name: r.name,
                size: r.size,
                receivedChunks: r.receivedChunks.size,
                totalChunks: r.totalChunks
            })),
            queueLength: this.queuedFiles.length,
            isSending: this.isSending,
            isPaused: this.isPaused,
            broadcastMode: this.broadcastMode,
            selectedPeers: Array.from(this.selectedPeers),
            iceConfig: window.VeloConfig ? window.VeloConfig.getIceConfig() : null
        };
    }
}

// Initialize on DOM load
if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
        window.velo = new VeloApp();
    });
}

// Export protocol utilities for test runners (Node.js)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        ProtocolConstants,
        packChunk,
        unpackChunk,
        computeSha256,
        generateUuid,
        generatePeerId,
        randomInt,
        sanitizeFilename,
        sanitizeUsername,
        sanitizeText,
        validateFileStartMetadata,
        computeAdaptiveAckTimeout,
        UUID_REGEX,
        SHA256_REGEX,
        VeloApp
    };
}
