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

        // ============ NEW FEATURES ============

        // Queue Management
        this.queuedFiles = []; // Array of { id, file, status, priority }
        this.isPaused = false;
        this.queueId = 0;

        // Multi-Peer Broadcasting
        this.selectedPeers = new Set(); // Selected peer IDs for targeted send
        this.broadcastMode = 'all'; // 'all' | 'selected'

        // Speed Test
        this.peerSpeedResults = new Map(); // peerId -> { latency, uploadSpeed, downloadSpeed }
        this.speedTestInProgress = false;

        // Adaptive Chunk Sizing for Speed Improvements
        this.currentChunkSize = 512 * 1024; // Start at 512KB
        this.minChunkSize = 256 * 1024; // 256KB minimum
        this.maxChunkSize = 2 * 1024 * 1024; // 2MB maximum
        this.measuredSpeed = 0; // Current measured speed in bytes/sec

        // Share Link
        this.sharePassword = null;

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
        // Handle Raw Binary Data (File Chunks or Speed Test Data)
        if (data instanceof ArrayBuffer || data instanceof Uint8Array || data instanceof Blob) {
            // Check if this is speed test data
            if (this._expectingTestData && this._expectingTestData.peerId === peerId) {
                this.handleSpeedTestDataReceived(peerId, data);
                return;
            }
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

            // Speed Test Protocol
            case 'speed-test-ping':
                this.handleSpeedTestPing(peerId, data);
                break;

            case 'speed-test-pong':
                this.handleSpeedTestPong(peerId, data);
                break;

            case 'speed-test-data':
                this.handleSpeedTestData(peerId, data);
                break;

            case 'speed-test-result':
                this.handleSpeedTestResult(peerId, data);
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
            const isSelected = this.selectedPeers.has(peerId) || this.broadcastMode === 'all';
            const speedResult = this.peerSpeedResults.get(peerId);
            const speedBadge = speedResult ? `
                <span style="font-size: 0.65rem; background: var(--accent-glow); color: var(--accent); 
                             padding: 0.15rem 0.4rem; border-radius: 4px; margin-left: 0.5rem;">
                    ${speedResult.latency}ms
                </span>
            ` : '';

            const pill = document.createElement('div');
            pill.className = `peer-pill active ${isSelected ? 'selected' : ''}`;
            pill.style.cssText = isSelected ? 'border-color: var(--accent); background: rgba(52, 211, 153, 0.1);' : '';
            pill.innerHTML = `
                <input type="checkbox" class="peer-select-checkbox" data-peer-id="${peerId}" 
                       ${isSelected ? 'checked' : ''} 
                       style="width: 16px; height: 16px; accent-color: var(--accent); cursor: pointer;">
                <div class="peer-pill-avatar">${username.charAt(0).toUpperCase()}</div>
                <div style="flex: 1;">
                    <div style="font-weight: 600; line-height: 1; display: flex; align-items: center;">
                        ${username}${speedBadge}
                    </div>
                    <div style="font-size: 0.7rem; opacity: 0.7;">${peerId}</div>
                </div>
                <button class="speed-test-btn" data-peer-id="${peerId}" 
                        style="background: var(--bg-main); border: none; padding: 0.3rem 0.5rem; 
                               border-radius: 6px; cursor: pointer; color: var(--text-muted); font-size: 0.75rem;"
                        title="Test Speed">
                    ⚡
                </button>
            `;

            // Checkbox handler
            const checkbox = pill.querySelector('.peer-select-checkbox');
            checkbox.onclick = (e) => {
                e.stopPropagation();
                this.togglePeerSelection(peerId);
            };

            // Speed test button handler
            const speedBtn = pill.querySelector('.speed-test-btn');
            speedBtn.onclick = (e) => {
                e.stopPropagation();
                this.runSpeedTest(peerId);
            };

            this.peerList.appendChild(pill);
        });

        // Add broadcast mode toggle if there are multiple peers
        if (this.connections.size > 1) {
            const toggleDiv = document.createElement('div');
            toggleDiv.className = 'peer-pill';
            toggleDiv.style.cssText = 'background: var(--bg-main); cursor: pointer;';
            toggleDiv.innerHTML = `
                <span style="font-size: 0.8rem; color: var(--text-muted);">
                    ${this.broadcastMode === 'all' ? '📡 Send to All' : '🎯 Send to Selected'}
                </span>
            `;
            toggleDiv.onclick = () => {
                this.setBroadcastMode(this.broadcastMode === 'all' ? 'selected' : 'all');
            };
            this.peerList.appendChild(toggleDiv);
        }
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

    // ==================== QUEUE MANAGEMENT ====================

    // Internal queue to enforce one-at-a-time sending (crucial for raw streams)
    queueFileForSending(file, priority = 0) {
        const queueItem = {
            id: ++this.queueId,
            file: file,
            status: 'pending', // pending, sending, paused, cancelled, complete
            priority: priority,
            addedAt: Date.now()
        };

        this.queuedFiles.push(queueItem);
        this.queuedFiles.sort((a, b) => b.priority - a.priority); // Higher priority first
        this.updateQueueUI();
        this.processTransferQueue();
        return queueItem.id;
    }

    processTransferQueue() {
        if (this.isSending || this.isPaused || this.queuedFiles.length === 0) return;

        const pendingItem = this.queuedFiles.find(item => item.status === 'pending');
        if (!pendingItem) return;

        pendingItem.status = 'sending';
        this.updateQueueUI();
        this.sendFile(pendingItem.file, pendingItem.id);
    }

    pauseQueue() {
        this.isPaused = true;
        this.showToast('Queue paused', 'info');
        this.updateQueueUI();
    }

    resumeQueue() {
        this.isPaused = false;
        this.showToast('Queue resumed', 'info');
        this.updateQueueUI();
        this.processTransferQueue();
    }

    cancelTransfer(queueId) {
        const item = this.queuedFiles.find(i => i.id === queueId);
        if (item) {
            item.status = 'cancelled';
            this.showToast(`Cancelled: ${item.file.name}`, 'info');
            this.updateQueueUI();
        }
    }

    clearQueue() {
        this.queuedFiles = this.queuedFiles.filter(item => item.status === 'sending');
        this.showToast('Queue cleared', 'info');
        this.updateQueueUI();
    }

    reorderQueue(fromIndex, toIndex) {
        const [item] = this.queuedFiles.splice(fromIndex, 1);
        this.queuedFiles.splice(toIndex, 0, item);
        this.updateQueueUI();
    }

    getQueueStats() {
        const pending = this.queuedFiles.filter(i => i.status === 'pending').length;
        const sending = this.queuedFiles.filter(i => i.status === 'sending').length;
        const complete = this.queuedFiles.filter(i => i.status === 'complete').length;
        const totalSize = this.queuedFiles.reduce((sum, i) => sum + i.file.size, 0);
        return { pending, sending, complete, total: this.queuedFiles.length, totalSize };
    }

    updateQueueUI() {
        const queueStatsEl = document.getElementById('queueStats');
        if (queueStatsEl) {
            const stats = this.getQueueStats();
            queueStatsEl.innerHTML = `
                <span>${stats.pending} pending</span>
                <span>${stats.sending} sending</span>
                <span>${this.formatBytes(stats.totalSize)} total</span>
            `;
        }
    }

    // ==================== MULTI-PEER BROADCASTING ====================

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

    selectAllPeers() {
        this.connections.forEach((_, peerId) => this.selectedPeers.add(peerId));
        this.broadcastMode = 'all';
        this.updatePeerList();
    }

    deselectAllPeers() {
        this.selectedPeers.clear();
        this.updatePeerList();
    }

    setBroadcastMode(mode) {
        this.broadcastMode = mode; // 'all' or 'selected'
        if (mode === 'all') {
            this.selectAllPeers();
        }
    }

    getTargetConnections() {
        if (this.broadcastMode === 'all' || this.selectedPeers.size === 0) {
            return Array.from(this.connections.values());
        }
        return Array.from(this.connections.entries())
            .filter(([peerId]) => this.selectedPeers.has(peerId))
            .map(([, value]) => value);
    }

    // ==================== ADAPTIVE CHUNK SIZING ====================

    calculateOptimalChunkSize() {
        // Adjust chunk size based on measured speed
        if (this.measuredSpeed > 50 * 1024 * 1024) { // > 50 MB/s
            this.currentChunkSize = this.maxChunkSize; // 2MB
        } else if (this.measuredSpeed > 20 * 1024 * 1024) { // > 20 MB/s
            this.currentChunkSize = 1.5 * 1024 * 1024; // 1.5MB
        } else if (this.measuredSpeed > 10 * 1024 * 1024) { // > 10 MB/s
            this.currentChunkSize = 1024 * 1024; // 1MB
        } else if (this.measuredSpeed > 5 * 1024 * 1024) { // > 5 MB/s
            this.currentChunkSize = 768 * 1024; // 768KB
        } else {
            this.currentChunkSize = this.minChunkSize; // 256KB for slow connections
        }
        return this.currentChunkSize;
    }

    // ==================== FILE TRANSFER (OPTIMIZED) ====================

    sendFile(file, queueId = null) {
        this.isSending = true; // Lock
        const id = ++this.transferId;
        const now = Date.now();

        // Get target connections based on broadcast mode
        const targetConnections = this.getTargetConnections();

        if (targetConnections.length === 0) {
            this.showToast('No peers selected!', 'error');
            this.isSending = false;
            if (queueId) {
                const item = this.queuedFiles.find(i => i.id === queueId);
                if (item) item.status = 'pending';
            }
            return;
        }

        // Calculate optimal chunk size based on current speed
        const chunkSize = this.calculateOptimalChunkSize();

        // Track this transfer
        this.activeTransfers.set(id, {
            size: file.size,
            transferred: 0,
            startTime: now,
            lastUpdate: now,
            lastBytes: 0,
            lastUiProgress: 0,
            lastUiUpdate: 0,
            queueId: queueId,
            chunkSize: chunkSize
        });

        this.addTransferToUI(id, file.name, file.size, 'send');

        // 1. Send Control Header to selected peers only
        targetConnections.forEach(({ conn }) => {
            conn.send({
                type: 'file-start',
                id,
                name: file.name,
                size: file.size
            });
        });

        const reader = new FileReader();
        let offset = 0;
        let chunkStartTime = now;

        const sendNextChunk = () => {
            // Check if cancelled
            if (queueId) {
                const queueItem = this.queuedFiles.find(i => i.id === queueId);
                if (queueItem && queueItem.status === 'cancelled') {
                    this.activeTransfers.delete(id);
                    this.isSending = false;
                    setTimeout(() => this.processTransferQueue(), 50);
                    return;
                }
            }

            // Backpressure check with optimized threshold (4MB instead of 8MB)
            let totalBuffered = 0;
            for (const { conn } of targetConnections) {
                if (conn.dataChannel) {
                    totalBuffered += conn.dataChannel.bufferedAmount || 0;
                }
            }

            // Dynamic backpressure threshold based on connection count
            const bufferThreshold = Math.max(2, 4 / targetConnections.length) * 1024 * 1024;

            if (totalBuffered > bufferThreshold) {
                setTimeout(sendNextChunk, 5); // Faster retry (5ms instead of 10ms)
                return;
            }

            // Use current adaptive chunk size
            const currentChunk = this.activeTransfers.get(id)?.chunkSize || chunkSize;
            const slice = file.slice(offset, offset + currentChunk);
            reader.readAsArrayBuffer(slice);
        };

        reader.onload = (e) => {
            const chunk = e.target.result;

            // 2. Send Raw Chunk to selected peers only
            targetConnections.forEach(({ conn }) => {
                conn.send(chunk);
            });

            offset += chunk.byteLength;
            this.totalBytesTransferred += chunk.byteLength;

            // Update measured speed for adaptive chunk sizing
            const chunkElapsed = (Date.now() - chunkStartTime) / 1000;
            if (chunkElapsed > 0) {
                this.measuredSpeed = chunk.byteLength / chunkElapsed;
                chunkStartTime = Date.now();

                // Recalculate chunk size every few chunks
                if (offset % (5 * 1024 * 1024) < chunk.byteLength) {
                    const transfer = this.activeTransfers.get(id);
                    if (transfer) {
                        transfer.chunkSize = this.calculateOptimalChunkSize();
                    }
                }
            }

            // UI Updates (Throttled more aggressively for speed)
            const transfer = this.activeTransfers.get(id);
            if (transfer) {
                transfer.transferred = offset;
                const progress = offset / file.size;
                // Throttle more during fast transfers (3% or 300ms)
                const throttlePercent = this.measuredSpeed > 10 * 1024 * 1024 ? 0.03 : 0.02;
                const throttleTime = this.measuredSpeed > 10 * 1024 * 1024 ? 300 : 200;

                if (progress - transfer.lastUiProgress > throttlePercent || Date.now() - transfer.lastUiUpdate > throttleTime) {
                    this.updateTransferUI(id, progress);
                    transfer.lastUiProgress = progress;
                    transfer.lastUiUpdate = Date.now();
                }
            }

            if (offset < file.size) {
                // Use setImmediate pattern for faster chunk processing
                if (typeof setImmediate !== 'undefined') {
                    setImmediate(sendNextChunk);
                } else {
                    setTimeout(sendNextChunk, 0);
                }
            } else {
                // 3. Send Control Footer
                this.updateTransferUI(id, 1);
                targetConnections.forEach(({ conn }) => {
                    conn.send({ type: 'file-end', id });
                });

                this.activeTransfers.delete(id);
                this.completeTransferUI(id, file.size, now);
                this.saveHistory({ name: file.name, size: file.size, peer: 'Peers' }, 'send');
                this.showToast(`Sent: ${file.name}`, 'success');

                // Update queue status
                if (queueId) {
                    const queueItem = this.queuedFiles.find(i => i.id === queueId);
                    if (queueItem) queueItem.status = 'complete';
                    this.updateQueueUI();
                }

                // Unlock and process next (faster - 50ms instead of 100ms)
                this.isSending = false;
                setTimeout(() => this.processTransferQueue(), 50);
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
        const iconSvg = this.getFileIcon(name);

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

    getFileIcon(filename) {
        const ext = filename.split('.').pop().toLowerCase();

        // Image
        if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp'].includes(ext)) {
            return '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>';
        }

        // Video
        if (['mp4', 'webm', 'mkv', 'mov', 'avi'].includes(ext)) {
            return '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>';
        }

        // Audio
        if (['mp3', 'wav', 'ogg', 'flac', 'm4a'].includes(ext)) {
            return '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>';
        }

        // Archive
        if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) {
            return '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>';
        }

        // Code
        if (['js', 'html', 'css', 'py', 'json', 'ts', 'java', 'c', 'cpp'].includes(ext)) {
            return '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>';
        }

        // Document
        if (['pdf', 'doc', 'docx', 'txt', 'md'].includes(ext)) {
            return '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>';
        }

        // Default File
        return '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>';
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

        // 7. Share Button
        const shareBtn = document.getElementById('shareBtn');
        if (shareBtn) {
            shareBtn.addEventListener('click', () => this.showShareModal());
        }

        // 8. Queue Control Buttons
        const pauseQueueBtn = document.getElementById('pauseQueueBtn');
        if (pauseQueueBtn) {
            pauseQueueBtn.addEventListener('click', () => {
                if (this.isPaused) {
                    this.resumeQueue();
                    pauseQueueBtn.textContent = '⏸️';
                    pauseQueueBtn.title = 'Pause Queue';
                } else {
                    this.pauseQueue();
                    pauseQueueBtn.textContent = '▶️';
                    pauseQueueBtn.title = 'Resume Queue';
                }
            });
        }

        const clearQueueBtn = document.getElementById('clearQueueBtn');
        if (clearQueueBtn) {
            clearQueueBtn.addEventListener('click', () => this.clearQueue());
        }
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

    // ==================== NETWORK SPEED TEST ====================

    async runSpeedTest(peerId) {
        const peerInfo = this.connections.get(peerId);
        if (!peerInfo) {
            this.showToast('Peer not connected', 'error');
            return null;
        }

        this.speedTestInProgress = true;
        this.showToast('Running speed test...', 'info');

        // Show speed test modal
        this.showSpeedTestModal(peerId);

        const conn = peerInfo.conn;
        const results = {
            peerId,
            latency: 0,
            uploadSpeed: 0,
            downloadSpeed: 0,
            timestamp: Date.now()
        };

        // 1. Measure Latency (ping-pong)
        const pingStart = Date.now();
        const latencyPromise = new Promise((resolve) => {
            this._speedTestResolve = resolve;
            conn.send({ type: 'speed-test-ping', timestamp: pingStart });
        });

        const latencyResult = await Promise.race([
            latencyPromise,
            new Promise(r => setTimeout(() => r({ timeout: true }), 5000))
        ]);

        if (latencyResult?.timeout) {
            this.showToast('Speed test timed out', 'error');
            this.speedTestInProgress = false;
            return null;
        }

        results.latency = latencyResult.latency;

        // 2. Measure Upload Speed (send 1MB of data)
        const testDataSize = 1 * 1024 * 1024; // 1MB
        const testData = new Uint8Array(testDataSize);
        // Fill with random data
        for (let i = 0; i < testDataSize; i += 1024) {
            testData[i] = Math.random() * 256;
        }

        const uploadStart = Date.now();
        conn.send({ type: 'speed-test-data', size: testDataSize, timestamp: uploadStart });
        conn.send(testData.buffer);

        // Wait for acknowledgment
        const uploadPromise = new Promise((resolve) => {
            this._uploadTestResolve = resolve;
        });

        const uploadResult = await Promise.race([
            uploadPromise,
            new Promise(r => setTimeout(() => r({ timeout: true }), 10000))
        ]);

        if (!uploadResult?.timeout) {
            const uploadTime = (uploadResult.receivedAt - uploadStart) / 1000;
            results.uploadSpeed = testDataSize / uploadTime;
        }

        // Store results
        this.peerSpeedResults.set(peerId, results);
        this.speedTestInProgress = false;

        // Update UI
        this.updateSpeedTestModal(results);
        this.updatePeerList();

        return results;
    }

    async runSpeedTestAll() {
        const results = [];
        for (const peerId of this.connections.keys()) {
            const result = await this.runSpeedTest(peerId);
            if (result) results.push(result);
        }
        return results;
    }

    handleSpeedTestPing(peerId, data) {
        // Respond immediately with pong
        const conn = this.connections.get(peerId)?.conn;
        if (conn) {
            conn.send({
                type: 'speed-test-pong',
                originalTimestamp: data.timestamp,
                respondedAt: Date.now()
            });
        }
    }

    handleSpeedTestPong(peerId, data) {
        const now = Date.now();
        const latency = now - data.originalTimestamp;
        if (this._speedTestResolve) {
            this._speedTestResolve({ latency });
            this._speedTestResolve = null;
        }
    }

    handleSpeedTestData(peerId, data) {
        // We're receiving test data - prepare to acknowledge
        this._expectingTestData = {
            peerId,
            size: data.size,
            timestamp: data.timestamp,
            received: 0
        };
    }

    handleSpeedTestResult(peerId, data) {
        // Received speed test result acknowledgment
        if (this._uploadTestResolve) {
            this._uploadTestResolve({ receivedAt: data.receivedAt });
            this._uploadTestResolve = null;
        }
    }

    handleSpeedTestDataReceived(peerId, data) {
        // We received the speed test binary data - send acknowledgment back
        const testInfo = this._expectingTestData;
        if (!testInfo) return;

        // Clear the expectation
        this._expectingTestData = null;

        // Send back acknowledgment with receive timestamp
        const conn = this.connections.get(peerId)?.conn;
        if (conn) {
            conn.send({
                type: 'speed-test-result',
                originalTimestamp: testInfo.timestamp,
                receivedAt: Date.now()
            });
        }
    }

    showSpeedTestModal(peerId) {
        const peerInfo = this.connections.get(peerId);
        const existingModal = document.getElementById('speedTestModal');
        if (existingModal) existingModal.remove();

        const modal = document.createElement('div');
        modal.id = 'speedTestModal';
        modal.style.cssText = `
            position: fixed; inset: 0; background: rgba(0,0,0,0.8); 
            backdrop-filter: blur(8px); display: flex; align-items: center; 
            justify-content: center; z-index: 200;
        `;
        modal.innerHTML = `
            <div style="background: var(--bg-surface); border-radius: 24px; padding: 2.5rem; 
                        max-width: 400px; width: 90%; text-align: center; border: 1px solid var(--border-light);">
                <h2 style="margin-bottom: 1.5rem;">Speed Test</h2>
                <p style="color: var(--text-muted); margin-bottom: 1rem;">Testing connection to ${peerInfo?.username || peerId}</p>
                <div id="speedTestProgress" style="margin: 2rem 0;">
                    <div class="speed-test-spinner" style="
                        width: 48px; height: 48px; margin: 0 auto;
                        border: 3px solid var(--border-light);
                        border-top-color: var(--primary);
                        border-radius: 50%;
                        animation: spin 1s linear infinite;
                    "></div>
                    <p style="margin-top: 1rem; color: var(--text-muted);">Measuring...</p>
                </div>
                <div id="speedTestResults" style="display: none;">
                    <div style="display: grid; gap: 1rem; margin: 1.5rem 0;">
                        <div style="background: var(--bg-main); padding: 1rem; border-radius: 12px;">
                            <div style="color: var(--text-muted); font-size: 0.8rem;">LATENCY</div>
                            <div id="testLatency" style="font-size: 1.5rem; font-weight: 700; color: var(--primary);">--</div>
                        </div>
                        <div style="background: var(--bg-main); padding: 1rem; border-radius: 12px;">
                            <div style="color: var(--text-muted); font-size: 0.8rem;">UPLOAD SPEED</div>
                            <div id="testUpload" style="font-size: 1.5rem; font-weight: 700; color: var(--accent);">--</div>
                        </div>
                    </div>
                </div>
                <button id="closeSpeedTest" class="btn-ghost" style="width: 100%; margin-top: 1rem;">Close</button>
            </div>
        `;

        document.body.appendChild(modal);
        document.getElementById('closeSpeedTest').onclick = () => modal.remove();
        modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
    }

    updateSpeedTestModal(results) {
        const progress = document.getElementById('speedTestProgress');
        const resultsDiv = document.getElementById('speedTestResults');

        if (progress) progress.style.display = 'none';
        if (resultsDiv) resultsDiv.style.display = 'block';

        const latencyEl = document.getElementById('testLatency');
        const uploadEl = document.getElementById('testUpload');

        if (latencyEl) latencyEl.textContent = `${results.latency}ms`;
        if (uploadEl) uploadEl.textContent = this.formatSpeed(results.uploadSpeed);
    }

    // ==================== SHARE VIA LINK ====================

    generateShareLink() {
        if (!this.myPeerId) {
            this.showToast('Start hosting first!', 'error');
            return null;
        }

        const baseUrl = window.location.origin + window.location.pathname;
        const shareUrl = `${baseUrl}?join=${this.myPeerId}`;
        return shareUrl;
    }

    async copyShareLink() {
        const link = this.generateShareLink();
        if (!link) return;

        try {
            await navigator.clipboard.writeText(link);
            this.showToast('Share link copied!', 'success');
        } catch (err) {
            // Fallback
            const input = document.createElement('input');
            input.value = link;
            document.body.appendChild(input);
            input.select();
            document.execCommand('copy');
            document.body.removeChild(input);
            this.showToast('Share link copied!', 'success');
        }
    }

    async nativeShare() {
        const link = this.generateShareLink();
        if (!link) return;

        if (navigator.share) {
            try {
                await navigator.share({
                    title: 'Join my Velo session',
                    text: `Connect with me on Velo for instant file transfer!`,
                    url: link
                });
                this.showToast('Shared successfully!', 'success');
            } catch (err) {
                if (err.name !== 'AbortError') {
                    this.copyShareLink(); // Fallback to copy
                }
            }
        } else {
            this.copyShareLink(); // Fallback to copy
        }
    }

    showShareModal() {
        const link = this.generateShareLink();
        if (!link) return;

        const existingModal = document.getElementById('shareModal');
        if (existingModal) existingModal.remove();

        const modal = document.createElement('div');
        modal.id = 'shareModal';
        modal.style.cssText = `
            position: fixed; inset: 0; background: rgba(0,0,0,0.8); 
            backdrop-filter: blur(8px); display: flex; align-items: center; 
            justify-content: center; z-index: 200;
        `;
        modal.innerHTML = `
            <div style="background: var(--bg-surface); border-radius: 24px; padding: 2.5rem; 
                        max-width: 450px; width: 90%; text-align: center; border: 1px solid var(--border-light);">
                <h2 style="margin-bottom: 0.5rem;">Share Your Session</h2>
                <p style="color: var(--text-muted); margin-bottom: 1.5rem;">Send this link to anyone to connect instantly</p>
                
                <div style="background: var(--bg-main); padding: 1rem; border-radius: 12px; margin-bottom: 1.5rem; 
                            display: flex; align-items: center; gap: 0.5rem;">
                    <input type="text" value="${link}" readonly id="shareLinkInput"
                           style="flex: 1; background: transparent; border: none; color: var(--text-primary); 
                                  font-size: 0.9rem; outline: none; font-family: monospace;">
                    <button id="copyLinkBtn" class="btn-primary" style="padding: 0.5rem 1rem; font-size: 0.9rem;">
                        Copy
                    </button>
                </div>

                <div style="display: flex; gap: 1rem; margin-bottom: 1.5rem;">
                    <button id="whatsappShare" class="btn-ghost" style="flex: 1; padding: 0.75rem;">
                        WhatsApp
                    </button>
                    <button id="telegramShare" class="btn-ghost" style="flex: 1; padding: 0.75rem;">
                        Telegram
                    </button>
                    ${navigator.share ? `
                    <button id="nativeShareBtn" class="btn-ghost" style="flex: 1; padding: 0.75rem;">
                        More...
                    </button>
                    ` : ''}
                </div>

                <div id="shareQrCode" style="display: flex; justify-content: center; margin-bottom: 1rem; 
                                              padding: 1rem; background: white; border-radius: 12px; width: fit-content; 
                                              margin-left: auto; margin-right: auto;"></div>

                <button id="closeShareModal" class="btn-ghost" style="width: 100%;">Close</button>
            </div>
        `;

        document.body.appendChild(modal);

        // Event handlers
        document.getElementById('copyLinkBtn').onclick = () => this.copyShareLink();
        document.getElementById('closeShareModal').onclick = () => modal.remove();
        modal.onclick = (e) => { if (e.target === modal) modal.remove(); };

        // Social share buttons
        document.getElementById('whatsappShare').onclick = () => {
            window.open(`https://wa.me/?text=${encodeURIComponent('Join my Velo session: ' + link)}`, '_blank');
        };
        document.getElementById('telegramShare').onclick = () => {
            window.open(`https://t.me/share/url?url=${encodeURIComponent(link)}&text=${encodeURIComponent('Join my Velo session!')}`, '_blank');
        };

        if (navigator.share) {
            document.getElementById('nativeShareBtn').onclick = () => this.nativeShare();
        }

        // Generate QR Code
        if (window.QRCode) {
            new QRCode(document.getElementById('shareQrCode'), {
                text: link,
                width: 150,
                height: 150,
                colorDark: "#000000",
                colorLight: "#ffffff",
                correctLevel: QRCode.CorrectLevel.H
            });
        }
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    window.velo = new VeloApp();
    window.velo.initNewFeatures();
});
