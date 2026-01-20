/**
 * PyShare Main Application
 * Connects WebSocket signaling, WebRTC, and UI
 */

class PyShareApp {
    constructor() {
        // Managers
        this.ws = null;
        this.webrtc = new WebRTCManager();
        this.transfer = new FileTransferManager(this.webrtc);

        // State
        this.userId = null;
        this.username = null;
        this.roomCode = null;
        this.users = [];
        this.isCreatingRoom = false;

        // UI Elements
        this.elements = {
            // Screens
            landingScreen: document.getElementById('landingScreen'),
            roomScreen: document.getElementById('roomScreen'),
            setupModal: document.getElementById('setupModal'),

            // Landing
            createRoomCard: document.getElementById('createRoomCard'),
            joinRoomCard: document.getElementById('joinRoomCard'),

            // Modal
            modalTitle: document.getElementById('modalTitle'),
            usernameInput: document.getElementById('usernameInput'),
            roomCodeInput: document.getElementById('roomCodeInput'),
            roomCodeGroup: document.getElementById('roomCodeGroup'),
            confirmSetup: document.getElementById('confirmSetup'),
            closeModal: document.getElementById('closeModal'),

            // Room
            roomCodeDisplay: document.getElementById('roomCodeDisplay'),
            copyRoomCode: document.getElementById('copyRoomCode'),
            leaveRoom: document.getElementById('leaveRoom'),
            usersList: document.getElementById('usersList'),
            headerStats: document.getElementById('headerStats'),
            peerCount: document.getElementById('peerCount'),
            currentSpeed: document.getElementById('currentSpeed'),

            // Transfer
            dropZone: document.getElementById('dropZone'),
            fileInput: document.getElementById('fileInput'),
            queueList: document.getElementById('queueList'),

            // Speed
            speedValue: document.getElementById('speedValue'),
            speedArc: document.getElementById('speedArc'),
            peakSpeed: document.getElementById('peakSpeed'),
            avgSpeed: document.getElementById('avgSpeed'),
            totalTransferred: document.getElementById('totalTransferred'),

            // Toast
            toastContainer: document.getElementById('toastContainer')
        };

        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupWebRTCCallbacks();
        this.setupTransferCallbacks();
        this.connectWebSocket();
    }

    // ==================== WebSocket ====================

    connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}`;

        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            console.log('WebSocket connected');
        };

        this.ws.onmessage = (event) => {
            const message = JSON.parse(event.data);
            this.handleServerMessage(message);
        };

        this.ws.onclose = () => {
            console.log('WebSocket disconnected');
            this.showToast('Disconnected from server', 'error');
            setTimeout(() => this.connectWebSocket(), 3000);
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }

    sendToServer(message) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(message));
        }
    }

    handleServerMessage(message) {
        switch (message.type) {
            case 'connected':
                this.userId = message.userId;
                this.webrtc.setLocalUserId(this.userId);
                break;

            case 'room-created':
                this.onRoomJoined(message.roomCode, message.users);
                break;

            case 'room-joined':
                this.onRoomJoined(message.roomCode, message.users);
                // Initiate connections to existing peers
                message.users.forEach(user => {
                    if (user.id !== this.userId) {
                        this.webrtc.initiateConnection(user.id, (signal) => {
                            this.sendToServer(signal);
                        });
                    }
                });
                break;

            case 'user-joined':
                this.onUserJoined(message.user, message.users);
                break;

            case 'user-left':
                this.onUserLeft(message.userId, message.users);
                break;

            case 'offer':
                this.webrtc.handleOffer(message.senderId, message.sdp, (signal) => {
                    this.sendToServer(signal);
                });
                break;

            case 'answer':
                this.webrtc.handleAnswer(message.senderId, message.sdp);
                break;

            case 'ice-candidate':
                this.webrtc.handleIceCandidate(message.senderId, message.candidate);
                break;

            case 'error':
                this.showToast(message.message, 'error');
                break;
        }
    }

    // ==================== Room Management ====================

    onRoomJoined(roomCode, users) {
        this.roomCode = roomCode;
        this.users = users;

        // Update UI
        this.elements.landingScreen.style.display = 'none';
        this.elements.roomScreen.style.display = 'flex';
        this.elements.setupModal.classList.remove('active');
        this.elements.headerStats.style.display = 'flex';

        this.elements.roomCodeDisplay.textContent = roomCode;
        this.updateUsersList();

        this.showToast(`Joined room ${roomCode}`, 'success');
    }

    onUserJoined(user, users) {
        this.users = users;
        this.updateUsersList();
        this.showToast(`${user.username} joined the room`, 'info');
    }

    onUserLeft(userId, users) {
        const leftUser = this.users.find(u => u.id === userId);
        this.users = users;
        this.updateUsersList();
        this.webrtc.closeConnection(userId);

        if (leftUser) {
            this.showToast(`${leftUser.username} left the room`, 'info');
        }
    }

    updateUsersList() {
        this.elements.usersList.innerHTML = '';

        this.users.forEach(user => {
            const isMe = user.id === this.userId;
            const isConnected = isMe || this.webrtc.isConnected(user.id);

            const li = document.createElement('li');
            li.className = `peer-card ${isConnected ? 'connected' : ''}`;
            li.innerHTML = `
                <div class="peer-avatar">${user.username.charAt(0).toUpperCase()}</div>
                <div>
                    <div class="peer-name">${user.username}${isMe ? ' (You)' : ''}</div>
                    <div class="peer-status">${isConnected ? 'Connected' : 'Connecting...'}</div>
                </div>
            `;
            this.elements.usersList.appendChild(li);
        });

        // Update peer count
        const connectedPeers = this.webrtc.getConnectedPeers().length;
        this.elements.peerCount.textContent = connectedPeers;
    }

    leaveCurrentRoom() {
        this.sendToServer({ type: 'leave-room' });
        this.webrtc.closeAll();
        this.transfer.resetStats();

        this.roomCode = null;
        this.users = [];

        // Reset UI
        this.elements.roomScreen.style.display = 'none';
        this.elements.landingScreen.style.display = 'flex';
        this.elements.headerStats.style.display = 'none';
        this.elements.queueList.innerHTML = '<div class="queue-empty"><span>No active transfers</span></div>';

        this.updateSpeedDisplay(0, 0, 0, 0);
    }

    // ==================== Event Listeners ====================

    setupEventListeners() {
        // Landing cards
        this.elements.createRoomCard.addEventListener('click', () => {
            this.isCreatingRoom = true;
            this.elements.modalTitle.textContent = 'Create Room';
            this.elements.roomCodeGroup.style.display = 'none';
            this.elements.setupModal.classList.add('active');
            this.elements.usernameInput.focus();
        });

        this.elements.joinRoomCard.addEventListener('click', () => {
            this.isCreatingRoom = false;
            this.elements.modalTitle.textContent = 'Join Room';
            this.elements.roomCodeGroup.style.display = 'block';
            this.elements.setupModal.classList.add('active');
            this.elements.usernameInput.focus();
        });

        // Modal
        this.elements.closeModal.addEventListener('click', () => {
            this.elements.setupModal.classList.remove('active');
        });

        this.elements.confirmSetup.addEventListener('click', () => {
            this.handleSetupConfirm();
        });

        this.elements.usernameInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                if (this.isCreatingRoom) {
                    this.handleSetupConfirm();
                } else {
                    this.elements.roomCodeInput.focus();
                }
            }
        });

        this.elements.roomCodeInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.handleSetupConfirm();
            }
        });

        this.elements.roomCodeInput.addEventListener('input', (e) => {
            e.target.value = e.target.value.toUpperCase();
        });

        // Room
        this.elements.copyRoomCode.addEventListener('click', () => {
            navigator.clipboard.writeText(this.roomCode);
            this.showToast('Room code copied!', 'success');
        });

        this.elements.leaveRoom.addEventListener('click', () => {
            this.leaveCurrentRoom();
        });

        // File upload
        this.elements.dropZone.addEventListener('click', () => {
            this.elements.fileInput.click();
        });

        this.elements.fileInput.addEventListener('change', (e) => {
            this.handleFiles(e.target.files);
            e.target.value = '';
        });

        // Drag and drop
        this.elements.dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            this.elements.dropZone.classList.add('drag-over');
        });

        this.elements.dropZone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            this.elements.dropZone.classList.remove('drag-over');
        });

        this.elements.dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            this.elements.dropZone.classList.remove('drag-over');
            this.handleFiles(e.dataTransfer.files);
        });
    }

    handleSetupConfirm() {
        const username = this.elements.usernameInput.value.trim();

        if (!username) {
            this.showToast('Please enter your name', 'error');
            return;
        }

        this.username = username;

        if (this.isCreatingRoom) {
            this.sendToServer({
                type: 'create-room',
                username: username
            });
        } else {
            const roomCode = this.elements.roomCodeInput.value.trim().toUpperCase();
            if (!roomCode) {
                this.showToast('Please enter a room code', 'error');
                return;
            }
            this.sendToServer({
                type: 'join-room',
                username: username,
                roomCode: roomCode
            });
        }

        // Clear inputs
        this.elements.usernameInput.value = '';
        this.elements.roomCodeInput.value = '';
    }

    handleFiles(files) {
        const connectedPeers = this.webrtc.getConnectedPeers().length;

        if (connectedPeers === 0) {
            this.showToast('No connected peers to send files to', 'error');
            return;
        }

        Array.from(files).forEach(file => {
            this.transfer.sendFile(file);
        });
    }

    // ==================== WebRTC Callbacks ====================

    setupWebRTCCallbacks() {
        this.webrtc.onDataChannelOpen = (peerId) => {
            this.updateUsersList();
            const user = this.users.find(u => u.id === peerId);
            if (user) {
                this.showToast(`Connected to ${user.username}`, 'success');
            }
        };

        this.webrtc.onDataChannelClose = (peerId) => {
            this.updateUsersList();
        };

        this.webrtc.onConnectionStateChange = (peerId, state) => {
            this.updateUsersList();
        };
    }

    // ==================== Transfer Callbacks ====================

    setupTransferCallbacks() {
        this.transfer.onTransferStart = (transfer) => {
            this.addTransferToQueue(transfer);
        };

        this.transfer.onTransferProgress = (transfer, progress) => {
            this.updateTransferProgress(transfer, progress);
        };

        this.transfer.onTransferComplete = (transfer) => {
            this.markTransferComplete(transfer);
        };

        this.transfer.onFileReceived = (transfer, blob) => {
            this.downloadFile(transfer.name, blob);
            this.showToast(`Received: ${transfer.name}`, 'success');
        };

        this.transfer.onSpeedUpdate = (speed, peak, avg, total) => {
            this.updateSpeedDisplay(speed, peak, avg, total);
        };
    }

    // ==================== Transfer UI ====================

    addTransferToQueue(transfer) {
        // Remove empty state
        const empty = this.elements.queueList.querySelector('.queue-empty');
        if (empty) empty.remove();

        const iconPath = transfer.direction === 'receive'
            ? '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>'
            : '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>';

        const item = document.createElement('div');
        item.className = 'file-item';
        item.id = `transfer-${transfer.id}`;

        item.innerHTML = `
            <div class="file-icon">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    ${iconPath}
                </svg>
            </div>
            <div class="file-info">
                <div class="file-name">${transfer.name}</div>
                <div class="file-meta">
                    <span id="status-${transfer.id}">${transfer.direction === 'receive' ? 'Receiving' : 'Sending'}...</span> • ${this.transfer.formatBytes(transfer.size)}
                </div>
            </div>
            <div class="file-progress">
                <div class="file-percent" id="percent-${transfer.id}">0%</div>
                <div class="file-speed" id="speed-${transfer.id}">0 MB/s</div>
            </div>
        `;

        this.elements.queueList.insertBefore(item, this.elements.queueList.firstChild);
    }

    updateTransferProgress(transfer, progress) {
        const item = document.getElementById(`transfer-${transfer.id}`);
        const percentEl = document.getElementById(`percent-${transfer.id}`);
        const statusEl = document.getElementById(`status-${transfer.id}`);
        const speedEl = document.getElementById(`speed-${transfer.id}`);

        if (item) {
            item.style.setProperty('--progress', `${progress * 100}%`);
        }
        if (percentEl) {
            percentEl.textContent = `${Math.round(progress * 100)}%`;
        }
        if (statusEl) {
            const direction = transfer.direction === 'receive' ? 'Receiving' : 'Sending';
            statusEl.textContent = `${direction}...`;
        }
        if (speedEl && this.transfer.speedHistory.length > 0) {
            const speed = this.transfer.speedHistory[this.transfer.speedHistory.length - 1];
            speedEl.textContent = this.transfer.formatSpeed(speed);
        }
    }

    markTransferComplete(transfer) {
        const item = document.getElementById(`transfer-${transfer.id}`);
        const percentEl = document.getElementById(`percent-${transfer.id}`);
        const statusEl = document.getElementById(`status-${transfer.id}`);
        const speedEl = document.getElementById(`speed-${transfer.id}`);

        if (item) {
            item.style.setProperty('--progress', '100%');
            item.style.borderColor = 'var(--accent)';
        }
        if (percentEl) {
            percentEl.textContent = '100%';
            percentEl.style.color = 'var(--accent)';
        }
        if (statusEl) {
            statusEl.textContent = 'Complete ✓';
        }
        if (speedEl) {
            const elapsed = (transfer.endTime - transfer.startTime) / 1000;
            const avgSpeed = transfer.size / elapsed / (1024 * 1024);
            speedEl.textContent = `${avgSpeed.toFixed(2)} MB/s avg`;
        }
    }

    downloadFile(filename, blob) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // ==================== Speed Display ====================

    updateSpeedDisplay(speed, peak, avg, total) {
        // Update speed value
        this.elements.speedValue.textContent = speed.toFixed(1);
        this.elements.currentSpeed.textContent = this.transfer.formatSpeed(speed);

        // Update stats
        this.elements.peakSpeed.textContent = this.transfer.formatSpeed(peak);
        this.elements.avgSpeed.textContent = this.transfer.formatSpeed(avg);
        this.elements.totalTransferred.textContent = this.transfer.formatBytes(total);
    }

    // ==================== Toast Notifications ====================

    showToast(message, type = 'info') {
        const icons = {
            success: '✓',
            error: '✕',
            info: 'ℹ'
        };

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <span class="toast-icon">${icons[type]}</span>
            <span class="toast-message">${message}</span>
        `;

        this.elements.toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.classList.add('toast-exit');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.app = new PyShareApp();
});
