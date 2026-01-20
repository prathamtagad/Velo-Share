/**
 * Velo - P2P File Transfer (PeerJS Edition)
 * Static deployment compatible - No server required!
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
        this.transferId = 0;

        // Speed tracking
        this.bytesTransferred = 0;
        this.lastSpeedCheck = Date.now();
        this.currentSpeed = 0;

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
        this.connectionDot = document.getElementById('connectionDot');
        this.connectionStatus = document.getElementById('connectionStatus');
        this.disconnectBtn = document.getElementById('disconnectBtn');
        this.peerList = document.getElementById('peerList');
        this.addPeerInput = document.getElementById('addPeerInput');
        this.addPeerBtn = document.getElementById('addPeerBtn');

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

        this.addPeerBtn.addEventListener('click', () => {
            const peerId = this.addPeerInput.value.trim().toUpperCase();
            if (peerId) {
                this.connectToPeer(peerId);
                this.addPeerInput.value = '';
            }
        });

        this.addPeerInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.addPeerBtn.click();
            }
        });

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
        this.setupConnection(conn);
    }

    setupConnection(conn) {
        conn.on('open', () => {
            const username = conn.metadata?.username || 'Peer';
            this.connections.set(conn.peer, { conn, username });
            this.updatePeerList();
            this.updateStatus('connected');

            // Send our username
            conn.send({
                type: 'handshake',
                username: this.myUsername
            });
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
        switch (data.type) {
            case 'handshake':
                // Update peer's username
                const peerInfo = this.connections.get(peerId);
                if (peerInfo) {
                    peerInfo.username = data.username;
                    this.updatePeerList();
                }
                break;

            case 'file-start':
                this.receiveFileStart(peerId, data);
                break;

            case 'file-chunk':
                this.receiveFileChunk(peerId, data);
                break;

            case 'file-end':
                this.receiveFileEnd(peerId, data);
                break;
        }
    }

    disconnect() {
        this.connections.forEach(({ conn }) => conn.close());
        this.connections.clear();

        if (this.peer) {
            this.peer.destroy();
            this.peer = null;
        }

        this.showLandingScreen();
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
        switch (status) {
            case 'connected':
                this.connectionDot.classList.add('connected');
                this.connectionStatus.textContent = `${this.connections.size} peer(s)`;
                break;
            case 'ready':
                this.connectionDot.classList.remove('connected');
                this.connectionStatus.textContent = 'Waiting...';
                break;
            case 'disconnected':
                this.connectionDot.classList.remove('connected');
                this.connectionStatus.textContent = 'Disconnected';
                break;
        }
    }

    updatePeerList() {
        if (this.connections.size === 0) {
            this.peerList.innerHTML = '<li style="color: var(--text-muted); font-size: 0.9rem;">No peers connected yet.</li>';
            return;
        }

        this.peerList.innerHTML = '';
        this.connections.forEach(({ username }, peerId) => {
            const li = document.createElement('li');
            li.className = 'peer-card connected';
            li.innerHTML = `
                <div class="peer-avatar">${username.charAt(0).toUpperCase()}</div>
                <div>
                    <div class="peer-name">${username}</div>
                    <div class="peer-status">${peerId}</div>
                </div>
            `;
            this.peerList.appendChild(li);
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
            this.sendFile(file);
        });
    }

    sendFile(file) {
        const id = ++this.transferId;
        const chunkSize = 64 * 1024; // 64KB chunks

        // Add to UI
        this.addTransferToUI(id, file.name, file.size, 'send');

        // Notify all peers
        this.connections.forEach(({ conn }) => {
            conn.send({
                type: 'file-start',
                id,
                name: file.name,
                size: file.size
            });
        });

        // Read and send file
        const reader = new FileReader();
        let offset = 0;

        const readNextChunk = () => {
            const slice = file.slice(offset, offset + chunkSize);
            reader.readAsArrayBuffer(slice);
        };

        reader.onload = (e) => {
            const chunk = e.target.result;

            this.connections.forEach(({ conn }) => {
                conn.send({
                    type: 'file-chunk',
                    id,
                    data: chunk
                });
            });

            offset += chunk.byteLength;
            this.bytesTransferred += chunk.byteLength;

            const progress = offset / file.size;
            this.updateTransferUI(id, progress);

            if (offset < file.size) {
                readNextChunk();
            } else {
                // Done
                this.connections.forEach(({ conn }) => {
                    conn.send({
                        type: 'file-end',
                        id
                    });
                });
                this.completeTransferUI(id);
                this.showToast(`Sent: ${file.name}`, 'success');
            }
        };

        readNextChunk();
    }

    receiveFileStart(peerId, data) {
        this.transfers.set(data.id, {
            name: data.name,
            size: data.size,
            chunks: [],
            received: 0
        });

        this.addTransferToUI(data.id, data.name, data.size, 'receive');
    }

    receiveFileChunk(peerId, data) {
        const transfer = this.transfers.get(data.id);
        if (!transfer) return;

        transfer.chunks.push(data.data);
        transfer.received += data.data.byteLength;
        this.bytesTransferred += data.data.byteLength;

        const progress = transfer.received / transfer.size;
        this.updateTransferUI(data.id, progress);
    }

    receiveFileEnd(peerId, data) {
        const transfer = this.transfers.get(data.id);
        if (!transfer) return;

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
        this.completeTransferUI(data.id);
        this.showToast(`Received: ${transfer.name}`, 'success');
    }

    // ==================== TRANSFER UI ====================

    addTransferToUI(id, name, size, direction) {
        const iconPath = direction === 'receive'
            ? '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>'
            : '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>';

        const item = document.createElement('div');
        item.className = 'file-item';
        item.id = `transfer-${id}`;
        item.innerHTML = `
            <div class="file-icon">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    ${iconPath}
                </svg>
            </div>
            <div class="file-info">
                <div class="file-name">${name}</div>
                <div class="file-meta">${direction === 'receive' ? 'Receiving' : 'Sending'}... • ${this.formatBytes(size)}</div>
            </div>
            <div class="file-progress">
                <div class="file-percent" id="percent-${id}">0%</div>
            </div>
        `;

        this.transferQueue.insertBefore(item, this.transferQueue.firstChild);
    }

    updateTransferUI(id, progress) {
        const item = document.getElementById(`transfer-${id}`);
        const percent = document.getElementById(`percent-${id}`);

        if (item) {
            item.style.setProperty('--progress', `${progress * 100}%`);
        }
        if (percent) {
            percent.textContent = `${Math.round(progress * 100)}%`;
        }
    }

    completeTransferUI(id) {
        const item = document.getElementById(`transfer-${id}`);
        const percent = document.getElementById(`percent-${id}`);

        if (item) {
            item.style.setProperty('--progress', '100%');
            item.style.borderColor = 'var(--accent)';
        }
        if (percent) {
            percent.textContent = '✓';
            percent.style.color = 'var(--accent)';
        }
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    window.velo = new VeloApp();
});
