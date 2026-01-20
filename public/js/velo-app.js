/**
 * Velo - P2P File Transfer (PeerJS Edition)
 * Static deployment compatible - No server required!
 * Enhanced with live speed & ETA tracking
 */

class VeloApp {
    constructor() {
        this.peer = null;
        this.connections = new Map(); // peerId -> { conn, username }
        this.myUsername = '';
        this.myPeerId = null;
        this.isHost = false;

        // Transfer tracking
        this.transfers = new Map();
        this.activeTransfers = new Map(); // id -> { size, transferred, startTime, lastUpdate, lastBytes }
        this.transferId = 0;

        // Global stats
        this.totalBytesTransferred = 0;
        this.sessionStartTime = null;
        this.peakSpeed = 0;

        // Speed calculation interval
        this.speedInterval = null;

        this.initElements();
        this.bindEvents();
    }

    initElements() {
        // Landing
        this.landingScreen = document.getElementById('landingScreen');
        this.roomScreen = document.getElementById('roomScreen');

        // Host
        this.hostNameInput = document.getElementById('hostNameInput');
        this.hostBtn = document.getElementById('hostBtn');

        // Join
        this.joinNameInput = document.getElementById('joinNameInput');
        this.peerIdInput = document.getElementById('peerIdInput');
        this.joinBtn = document.getElementById('joinBtn');

        // Room
        this.myPeerIdDisplay = document.getElementById('myPeerId');
        this.copyPeerIdBtn = document.getElementById('copyPeerId');
        this.connectionStatus = document.getElementById('connectionStatus');
        this.disconnectBtn = document.getElementById('disconnectBtn');
        this.peerList = document.getElementById('peerList');

        // Stats
        this.liveSpeedEl = document.getElementById('liveSpeed');
        this.peakSpeedEl = document.getElementById('peakSpeedStat');
        this.totalTransferredEl = document.getElementById('totalTransferred');

        // Transfer
        this.dropZone = document.getElementById('dropZone');
        this.fileInput = document.getElementById('fileInput');
        this.transferQueue = document.getElementById('transferQueue');

        // Toast
        this.toastContainer = document.getElementById('toastContainer');
    }

    bindEvents() {
        // Host
        this.hostBtn.addEventListener('click', () => this.startHosting());
        this.hostNameInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.startHosting();
        });

        // Join
        this.joinBtn.addEventListener('click', () => this.joinPeer());
        this.peerIdInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.joinPeer();
        });
        this.peerIdInput.addEventListener('input', (e) => {
            e.target.value = e.target.value.toUpperCase();
        });

        // Room actions
        this.copyPeerIdBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(this.myPeerId);
            this.showToast('Peer ID copied!', 'success');
        });

        this.disconnectBtn.addEventListener('click', () => this.disconnect());

        // File transfer
        this.dropZone.addEventListener('click', () => this.fileInput.click());
        this.fileInput.addEventListener('change', (e) => {
            this.handleFiles(e.target.files);
            e.target.value = '';
        });

        this.dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            this.dropZone.classList.add('drag-over');
        });

        this.dropZone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            this.dropZone.classList.remove('drag-over');
        });

        this.dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            this.dropZone.classList.remove('drag-over');
            this.handleFiles(e.dataTransfer.files);
        });
    }

    // ==================== PEER MANAGEMENT ====================

    generatePeerId() {
        const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        let id = 'VELO-';
        for (let i = 0; i < 6; i++) {
            id += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return id;
    }

    startHosting() {
        const username = this.hostNameInput.value.trim();
        if (!username) {
            this.showToast('Please enter your name', 'error');
            return;
        }

        this.myUsername = username;
        this.saveProfile();
        this.isHost = true;
        this.initPeer();
    }

    joinPeer() {
        const username = this.joinNameInput.value.trim();
        const targetPeerId = this.peerIdInput.value.trim().toUpperCase();

        if (!username) {
            this.showToast('Please enter your name', 'error');
            return;
        }
        if (!targetPeerId) {
            this.showToast('Please enter a Peer ID', 'error');
            return;
        }

        this.myUsername = username;
        this.saveProfile();
        this.isHost = false;
        this.initPeer(targetPeerId);
    }

    initPeer(targetPeerId = null) {
        const myId = this.generatePeerId();

        this.peer = new Peer(myId, {
            debug: 1
        });

        this.peer.on('open', (id) => {
            this.myPeerId = id;
            this.myPeerIdDisplay.textContent = id;
            this.showRoomScreen();
            this.updateStatus('ready');
            this.showToast(`Your ID: ${id}`, 'success');
            this.sessionStartTime = Date.now();
            this.startSpeedTracking();

            // If joining, connect to target
            if (targetPeerId) {
                this.connectToPeer(targetPeerId);
            }
        });

        this.peer.on('connection', (conn) => {
            this.handleIncomingConnection(conn);
        });

        this.peer.on('error', (err) => {
            console.error('PeerJS Error:', err);
            if (err.type === 'peer-unavailable') {
                this.showToast('Peer not found. Check the ID.', 'error');
            } else {
                this.showToast(`Connection error: ${err.type}`, 'error');
            }
        });

        this.peer.on('disconnected', () => {
            this.updateStatus('disconnected');
        });
    }

    connectToPeer(peerId) {
        if (this.connections.has(peerId)) {
            this.showToast('Already connected to this peer', 'info');
            return;
        }

        const conn = this.peer.connect(peerId, {
            metadata: { username: this.myUsername }
        });

        this.setupConnection(conn);
    }

    handleIncomingConnection(conn) {
        this.showToast(`${conn.metadata?.username || 'Someone'} connected!`, 'success');
        this.playSound('connect');
        this.setupConnection(conn);
    }

    setupConnection(conn) {
        conn.on('open', () => {
            const username = conn.metadata?.username || 'Peer';
            this.connections.set(conn.peer, { conn, username, receivingId: null });
            this.updatePeerList();
            this.updateStatus('connected');

            // Send our username
            conn.send({
                type: 'handshake',
                username: this.myUsername
            });

            // Process queue
            this.processTransferQueue();
        });

        conn.on('data', (data) => {
            this.handleData(conn.peer, data);
        });

        conn.on('close', () => {
            const peerInfo = this.connections.get(conn.peer);
            this.connections.delete(conn.peer);
            this.updatePeerList();
            this.updateStatus(this.connections.size > 0 ? 'connected' : 'ready');
            this.showToast(`${peerInfo?.username || 'Peer'} disconnected`, 'info');
        });

        conn.on('error', (err) => {
            console.error('Connection error:', err);
        });
    }

    handleData(peerId, data) {
        // Handle Raw Binary Data (File Chunks)
        if (data instanceof ArrayBuffer || data instanceof Uint8Array || data instanceof Blob) {
            this.receiveFileChunkRaw(peerId, data);
            return;
        }

        switch (data.type) {
            case 'handshake':
                const peerInfo = this.connections.get(peerId);
                if (peerInfo) {
                    peerInfo.username = data.username;
                    this.updatePeerList();
                }
                break;

            case 'file-start':
                this.receiveFileStart(peerId, data);
                break;

            case 'file-end':
                this.receiveFileEnd(peerId, data);
                break;
        }
    }

    disconnect() {
        this.stopSpeedTracking();
        this.connections.forEach(({ conn }) => conn.close());
        this.connections.clear();

        if (this.peer) {
            this.peer.destroy();
            this.peer = null;
        }

        this.showLandingScreen();
    }

    // ==================== SPEED TRACKING ====================

    startSpeedTracking() {
        this.speedInterval = setInterval(() => {
            this.updateGlobalStats();
        }, 500);
    }

    stopSpeedTracking() {
        if (this.speedInterval) {
            clearInterval(this.speedInterval);
            this.speedInterval = null;
        }
    }

    updateGlobalStats() {
        // Calculate current speed from active transfers
        let totalSpeed = 0;
        const now = Date.now();

        this.activeTransfers.forEach((transfer, id) => {
            const elapsed = (now - transfer.lastUpdate) / 1000;
            if (elapsed > 0 && elapsed < 2) {
                const bytesPerSec = (transfer.transferred - transfer.lastBytes) / elapsed;
                totalSpeed += bytesPerSec;
                transfer.lastBytes = transfer.transferred;
                transfer.lastUpdate = now;

                // Update individual transfer speed and ETA
                this.updateTransferStats(id, transfer, bytesPerSec);
            }
        });

        // Update peak
        if (totalSpeed > this.peakSpeed) {
            this.peakSpeed = totalSpeed;
        }

        // Update UI
        if (this.liveSpeedEl) {
            this.liveSpeedEl.textContent = this.formatSpeed(totalSpeed);
        }
        if (this.peakSpeedEl) {
            this.peakSpeedEl.textContent = this.formatSpeed(this.peakSpeed);
        }
        if (this.totalTransferredEl) {
            this.totalTransferredEl.textContent = this.formatBytes(this.totalBytesTransferred);
        }
    }

    updateTransferStats(id, transfer, speed) {
        const speedEl = document.getElementById(`speed-${id}`);
        const etaEl = document.getElementById(`eta-${id}`);

        if (speedEl) {
            speedEl.textContent = this.formatSpeed(speed);
        }

        if (etaEl && speed > 0) {
            const remaining = transfer.size - transfer.transferred;
            const seconds = remaining / speed;
            etaEl.textContent = this.formatTime(seconds);
        }
    }

    // ==================== UI ====================

    showRoomScreen() {
        this.landingScreen.style.display = 'none';
        this.roomScreen.style.display = 'flex';
    }

    showLandingScreen() {
        this.roomScreen.style.display = 'none';
        this.landingScreen.style.display = 'flex';
    }

    updateStatus(status) {
        if (!this.connectionStatus) return;
        switch (status) {
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
        this.peerList.innerHTML = '';

        // Add "Add Peer" button first
        const addBtn = document.createElement('div');
        addBtn.className = 'peer-pill';
        addBtn.style.cursor = 'pointer';
        addBtn.innerHTML = `
            <div class="peer-pill-avatar" style="background: var(--bg-surface); border: 1px dashed var(--text-muted); color: var(--text-muted);">+</div>
            <span>Add</span>
        `;
        addBtn.onclick = () => {
            const id = prompt('Enter Peer ID to connect:');
            if (id) this.connectToPeer(id.toUpperCase());
        };
        this.peerList.appendChild(addBtn);

        this.connections.forEach(({ username }, peerId) => {
            const pill = document.createElement('div');
            pill.className = 'peer-pill active';
            pill.innerHTML = `
                <div class="peer-pill-avatar">${username.charAt(0).toUpperCase()}</div>
                <div>
                    <div style="font-weight: 600; line-height: 1;">${username}</div>
                    <div style="font-size: 0.7rem; opacity: 0.7;">${peerId}</div>
                </div>
            `;
            this.peerList.appendChild(pill);
        });
    }

    showToast(message, type = 'info') {
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
            padding: 1rem 1.5rem;
            border-radius: 12px;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            box-shadow: var(--shadow-lg);
            animation: slideIn 0.3s ease;
        `;
        toast.innerHTML = `
            <span style="color: ${colors[type]}; font-weight: bold;">${icons[type]}</span>
            <span>${message}</span>
        `;

        this.toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            toast.style.transition = 'all 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    // ==================== FILE TRANSFER ====================

    handleFiles(files) {
        if (this.connections.size === 0) {
            this.showToast('No peers connected!', 'error');
            return;
        }

        Array.from(files).forEach(file => {
            // Queue the file to be sent
            this.queueFileForSending(file);
        });
    }

    // Internal queue to enforce one-at-a-time sending per peer (crucial for raw streams)
    queueFileForSending(file) {
        if (!this.sendingQueue) this.sendingQueue = [];
        this.sendingQueue.push(file);
        this.processTransferQueue();
    }

    processTransferQueue() {
        if (this.isSending || !this.sendingQueue || this.sendingQueue.length === 0) return;

        const file = this.sendingQueue.shift();
        this.sendFile(file);
    }

    sendFile(file) {
        this.isSending = true; // Lock
        const id = ++this.transferId;
        const chunkSize = 512 * 1024; // 512KB for high speed
        const now = Date.now();

        // Track this transfer
        this.activeTransfers.set(id, {
            size: file.size,
            transferred: 0,
            startTime: now,
            lastUpdate: now,
            lastBytes: 0,
            lastUiProgress: 0,
            lastUiUpdate: 0
        });

        this.addTransferToUI(id, file.name, file.size, 'send');

        // 1. Send Control Header
        this.connections.forEach(({ conn }) => {
            conn.send({
                type: 'file-start',
                id,
                name: file.name,
                size: file.size
            });
        });

        const reader = new FileReader();
        let offset = 0;

        const sendNextChunk = () => {
            // Backpressure check
            let totalBuffered = 0;
            for (const { conn } of this.connections.values()) {
                if (conn.dataChannel) {
                    totalBuffered += conn.dataChannel.bufferedAmount || 0;
                }
            }

            if (totalBuffered > 8 * 1024 * 1024) { // 8MB threshold
                setTimeout(sendNextChunk, 10);
                return;
            }

            const slice = file.slice(offset, offset + chunkSize);
            reader.readAsArrayBuffer(slice);
        };

        reader.onload = (e) => {
            const chunk = e.target.result;

            // 2. Send Raw Chunk (No wrapping)
            this.connections.forEach(({ conn }) => {
                conn.send(chunk);
            });

            offset += chunk.byteLength;
            this.totalBytesTransferred += chunk.byteLength;

            // UI Updates (Throttled)
            const transfer = this.activeTransfers.get(id);
            if (transfer) {
                transfer.transferred = offset;
                const progress = offset / file.size;
                if (progress - transfer.lastUiProgress > 0.02 || Date.now() - transfer.lastUiUpdate > 200) {
                    this.updateTransferUI(id, progress);
                    transfer.lastUiProgress = progress;
                    transfer.lastUiUpdate = Date.now();
                }
            }

            if (offset < file.size) {
                sendNextChunk();
            } else {
                // 3. Send Control Footer
                this.updateTransferUI(id, 1);
                this.connections.forEach(({ conn }) => {
                    conn.send({ type: 'file-end', id });
                });

                this.activeTransfers.delete(id);
                this.completeTransferUI(id, file.size, now);
                this.saveHistory({ name: file.name, size: file.size, peer: 'Peers' }, 'send');
                this.showToast(`Sent: ${file.name}`, 'success');

                // Unlock and process next
                this.isSending = false;
                setTimeout(() => this.processTransferQueue(), 100);
            }
        };

        sendNextChunk();
    }

    receiveFileStart(peerId, data) {
        const now = Date.now();

        // Lock this peer to this file ID
        const peerInfo = this.connections.get(peerId);
        if (peerInfo) peerInfo.receivingId = data.id;

        this.transfers.set(data.id, {
            name: data.name,
            size: data.size,
            chunks: [],
            received: 0
        });

        this.activeTransfers.set(data.id, {
            size: data.size,
            transferred: 0,
            startTime: now,
            lastUpdate: now,
            lastBytes: 0
        });

        this.addTransferToUI(data.id, data.name, data.size, 'receive');
    }

    receiveFileChunkRaw(peerId, chunk) {
        const peerInfo = this.connections.get(peerId);
        if (!peerInfo || !peerInfo.receivingId) return; // Ignore stray binary data

        const transferId = peerInfo.receivingId;
        const transfer = this.transfers.get(transferId);
        if (!transfer) return;

        // PeerJS might give us Uint8Array or ArrayBuffer
        const data = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);

        transfer.chunks.push(data);
        transfer.received += data.byteLength;
        this.totalBytesTransferred += data.byteLength;

        const activeTransfer = this.activeTransfers.get(transferId);
        if (activeTransfer) {
            activeTransfer.transferred = transfer.received;

            // Throttle UI on receiver too
            const progress = transfer.received / transfer.size;
            if (progress - (activeTransfer.lastUiProgress || 0) > 0.02 || Date.now() - activeTransfer.lastUiUpdate > 200) {
                this.updateTransferUI(transferId, progress);
                activeTransfer.lastUiProgress = progress;
                activeTransfer.lastUiUpdate = Date.now();
            }
        }
    }

    receiveFileEnd(peerId, data) {
        const peerInfo = this.connections.get(peerId);
        if (peerInfo) peerInfo.receivingId = null; // Unlock peer

        // Force 100% UI
        this.updateTransferUI(data.id, 1);

        const transfer = this.transfers.get(data.id);
        const activeTransfer = this.activeTransfers.get(data.id);
        if (!transfer) return;

        const startTime = activeTransfer?.startTime || Date.now();

        // Combine chunks and download
        const blob = new Blob(transfer.chunks);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = transfer.name;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        this.transfers.delete(data.id);
        this.activeTransfers.delete(data.id);
        this.completeTransferUI(data.id, transfer.size, startTime);
        this.saveHistory({ name: transfer.name, size: transfer.size, peer: peerId }, 'receive');
        this.showToast(`Received: ${transfer.name}`, 'success');
    }

    // ==================== TRANSFER UI ====================

    addTransferToUI(id, name, size, direction) {
        const item = document.createElement('div');
        item.className = 'file-card-modern';
        item.id = `transfer-${id}`;

        const iconColor = direction === 'receive' ? 'var(--accent)' : 'var(--primary)';
        const iconSvg = direction === 'receive'
            ? '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>'
            : '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>';

        item.innerHTML = `
            <div style="color: ${iconColor}; background: rgba(255,255,255,0.05); padding: 0.5rem; border-radius: 8px;">${iconSvg}</div>
            <div style="flex: 1; min-width: 0;">
                <div style="font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${name}</div>
                <div style="font-size: 0.8rem; color: var(--text-muted); display: flex; gap: 0.5rem;">
                    <span>${this.formatBytes(size)}</span>
                    <span id="speed-${id}" style="color: ${iconColor}"></span>
                </div>
            </div>
            <div style="text-align: right;">
                <div id="percent-${id}" style="font-weight: bold;">0%</div>
                <div id="eta-${id}" style="font-size: 0.7rem; color: var(--text-muted);">--</div>
            </div>
            <div class="progress-bg" id="progress-${id}" style="width: 0%;"></div>
        `;

        this.transferQueue.insertBefore(item, this.transferQueue.firstChild);
    }

    updateTransferUI(id, progress) {
        const bar = document.getElementById(`progress-${id}`);
        const percent = document.getElementById(`percent-${id}`);
        if (bar) bar.style.width = `${progress * 100}%`;
        if (percent) percent.textContent = `${Math.round(progress * 100)}%`;
    }

    completeTransferUI(id, size, startTime) {
        const bar = document.getElementById(`progress-${id}`);
        const percent = document.getElementById(`percent-${id}`);
        const eta = document.getElementById(`eta-${id}`);

        if (bar) bar.style.width = '100%';
        if (percent) { percent.textContent = '✓'; percent.style.color = 'var(--accent)'; }
        if (eta) eta.textContent = 'Complete';

        this.triggerConfetti();
    }



    // ==================== FORMATTERS ====================

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    formatSpeed(bytesPerSec) {
        if (bytesPerSec === 0) return '0 MB/s';
        const mbps = bytesPerSec / (1024 * 1024);
        if (mbps >= 1) {
            return mbps.toFixed(1) + ' MB/s';
        }
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

    // ==================== NEW FEATURES ====================

    checkUrlParams() {
        const params = new URLSearchParams(window.location.search);
        const joinId = params.get('join');
        if (joinId) {
            // Fill ID
            if (this.peerIdInput) {
                this.peerIdInput.value = joinId;
                this.peerIdInput.style.borderColor = 'var(--accent)';
            }
            // Focus name or auto-join if name exists
            if (this.joinNameInput.value) {
                this.showToast(`Ready to join ${joinId}`, 'info');
            } else {
                this.joinNameInput.focus();
                this.showToast('Enter name to join session', 'info');
            }
        }
    }

    saveProfile() {
        localStorage.setItem('velo_username', this.myUsername);
    }

    loadProfile() {
        const savedName = localStorage.getItem('velo_username');
        if (savedName) {
            if (this.hostNameInput) this.hostNameInput.value = savedName;
            if (this.joinNameInput) this.joinNameInput.value = savedName;
        }
    }

    initNewFeatures() {
        // 1. Service Worker for PWA
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js')
                .then(() => console.log('Service Worker Registered'))
                .catch(err => console.error('SW Registration Failed:', err));
        }

        // 2. Audio Context for Sounds
        this.audioCtx = new (window.AudioContext || window.webkitAudioContext)();

        // 3. Load History & Profile
        this.loadHistory();
        this.loadProfile();

        // 4. Keyboard Shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') this.disconnect();
        });

        // 5. QR Code Button
        const qrBtn = document.getElementById('showQrBtn');
        if (qrBtn) {
            qrBtn.addEventListener('click', () => this.showQrCode());
        }

        // 6. Check URL Params (QR Code join)
        this.checkUrlParams();
    }

    playSound(type) {
        if (this.audioCtx && this.audioCtx.state === 'suspended') this.audioCtx.resume();
        if (!this.audioCtx) return;

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
        } else if (type === 'message') {
            osc.frequency.setValueAtTime(880, now);
            gain.gain.setValueAtTime(0.05, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.05);
            osc.start(now);
            osc.stop(now + 0.05);
        } else if (type === 'error') {
            osc.type = 'sawtooth';
            osc.frequency.setValueAtTime(150, now);
            osc.frequency.linearRampToValueAtTime(100, now + 0.2);
            gain.gain.setValueAtTime(0.1, now);
            gain.gain.linearRampToValueAtTime(0.01, now + 0.2);
            osc.start(now);
            osc.stop(now + 0.2);
        } else if (type === 'complete') {
            osc.frequency.setValueAtTime(523.25, now);
            osc.frequency.setValueAtTime(659.25, now + 0.1);
            gain.gain.setValueAtTime(0.1, now);
            gain.gain.linearRampToValueAtTime(0.01, now + 0.3);
            osc.start(now);
            osc.stop(now + 0.3);
        }
    }

    showQrCode() {
        const modal = document.getElementById('qrModal');
        const container = document.getElementById('qrCodeContainer');
        const closeBtn = document.getElementById('closeQrModal');

        container.innerHTML = ''; // Clear previous

        // Generate QR
        if (window.QRCode) {
            new QRCode(container, {
                text: `https://velo-share.netlify.app/app.html?join=${this.myPeerId || ''}`,
                width: 200,
                height: 200,
                colorDark: "#000000",
                colorLight: "#ffffff",
                correctLevel: QRCode.CorrectLevel.H
            });
            modal.style.display = 'flex';
        } else {
            console.error('QRCode library not loaded');
        }

        const close = () => modal.style.display = 'none';
        closeBtn.onclick = close;
        modal.onclick = (e) => { if (e.target === modal) close(); };
    }

    saveHistory(transfer, direction) {
        const historyItem = {
            name: transfer.name,
            size: transfer.size,
            date: Date.now(),
            direction: direction,
            peer: transfer.peer
        };

        let history = JSON.parse(localStorage.getItem('velo_history') || '[]');
        history.unshift(historyItem);
        if (history.length > 50) history.pop(); // Keep last 50
        localStorage.setItem('velo_history', JSON.stringify(history));
    }

    loadHistory() {
        // Could implement a history view UI here later
        console.log('History loaded', JSON.parse(localStorage.getItem('velo_history') || '[]'));
    }

    triggerConfetti() {
        this.showToast('🎉 Transfer Complete!', 'success');
        this.playSound('complete');
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    window.velo = new VeloApp();
    window.velo.initNewFeatures();
});
