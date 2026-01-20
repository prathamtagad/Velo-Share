/**
 * PyShare WebRTC Module
 * Handles P2P connections using WebRTC DataChannels
 */

class WebRTCManager {
    constructor() {
        this.localUserId = null;
        this.connections = new Map(); // peerId -> RTCPeerConnection
        this.dataChannels = new Map(); // peerId -> RTCDataChannel
        this.pendingCandidates = new Map(); // Buffer ICE candidates before connection is ready

        // WebRTC Configuration with STUN servers for NAT traversal
        this.config = {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' },
                { urls: 'stun:stun2.l.google.com:19302' },
                { urls: 'stun:stun3.l.google.com:19302' },
                { urls: 'stun:stun4.l.google.com:19302' }
            ]
        };

        // Event callbacks
        this.onDataChannelOpen = null;
        this.onDataChannelClose = null;
        this.onDataChannelMessage = null;
        this.onConnectionStateChange = null;
    }

    setLocalUserId(userId) {
        this.localUserId = userId;
    }

    /**
     * Create a new peer connection
     */
    createPeerConnection(peerId, sendSignal) {
        if (this.connections.has(peerId)) {
            console.log(`Connection to ${peerId} already exists`);
            return this.connections.get(peerId);
        }

        const pc = new RTCPeerConnection(this.config);
        this.connections.set(peerId, pc);
        this.pendingCandidates.set(peerId, []);

        // Handle ICE candidates
        pc.onicecandidate = (event) => {
            if (event.candidate) {
                sendSignal({
                    type: 'ice-candidate',
                    targetId: peerId,
                    candidate: event.candidate
                });
            }
        };

        // Handle connection state changes
        pc.onconnectionstatechange = () => {
            console.log(`Connection to ${peerId}: ${pc.connectionState}`);
            if (this.onConnectionStateChange) {
                this.onConnectionStateChange(peerId, pc.connectionState);
            }

            if (pc.connectionState === 'failed' || pc.connectionState === 'disconnected') {
                this.closeConnection(peerId);
            }
        };

        // Handle incoming data channels
        pc.ondatachannel = (event) => {
            this.setupDataChannel(event.channel, peerId);
        };

        return pc;
    }

    /**
     * Setup data channel event handlers
     */
    setupDataChannel(channel, peerId) {
        channel.binaryType = 'arraybuffer';
        this.dataChannels.set(peerId, channel);

        channel.onopen = () => {
            console.log(`Data channel open with ${peerId}`);
            // Process any pending ICE candidates
            const pending = this.pendingCandidates.get(peerId) || [];
            pending.forEach(candidate => {
                const pc = this.connections.get(peerId);
                if (pc) {
                    pc.addIceCandidate(candidate).catch(console.error);
                }
            });
            this.pendingCandidates.set(peerId, []);

            if (this.onDataChannelOpen) {
                this.onDataChannelOpen(peerId);
            }
        };

        channel.onclose = () => {
            console.log(`Data channel closed with ${peerId}`);
            if (this.onDataChannelClose) {
                this.onDataChannelClose(peerId);
            }
        };

        channel.onerror = (error) => {
            console.error(`Data channel error with ${peerId}:`, error);
        };

        channel.onmessage = (event) => {
            if (this.onDataChannelMessage) {
                this.onDataChannelMessage(peerId, event.data);
            }
        };
    }

    /**
     * Initiate connection to a peer (creates offer)
     */
    async initiateConnection(peerId, sendSignal) {
        const pc = this.createPeerConnection(peerId, sendSignal);

        // Create data channel for file transfer
        const channel = pc.createDataChannel('fileTransfer', {
            ordered: true
        });
        this.setupDataChannel(channel, peerId);

        // Create and send offer
        try {
            const offer = await pc.createOffer();
            await pc.setLocalDescription(offer);

            sendSignal({
                type: 'offer',
                targetId: peerId,
                sdp: pc.localDescription
            });
        } catch (error) {
            console.error('Error creating offer:', error);
        }
    }

    /**
     * Handle incoming offer (create answer)
     */
    async handleOffer(peerId, sdp, sendSignal) {
        const pc = this.createPeerConnection(peerId, sendSignal);

        try {
            await pc.setRemoteDescription(new RTCSessionDescription(sdp));
            const answer = await pc.createAnswer();
            await pc.setLocalDescription(answer);

            sendSignal({
                type: 'answer',
                targetId: peerId,
                sdp: pc.localDescription
            });
        } catch (error) {
            console.error('Error handling offer:', error);
        }
    }

    /**
     * Handle incoming answer
     */
    async handleAnswer(peerId, sdp) {
        const pc = this.connections.get(peerId);
        if (!pc) {
            console.error(`No connection found for ${peerId}`);
            return;
        }

        try {
            await pc.setRemoteDescription(new RTCSessionDescription(sdp));
        } catch (error) {
            console.error('Error handling answer:', error);
        }
    }

    /**
     * Handle incoming ICE candidate
     */
    async handleIceCandidate(peerId, candidate) {
        const pc = this.connections.get(peerId);
        if (!pc) {
            console.error(`No connection found for ${peerId}`);
            return;
        }

        try {
            if (pc.remoteDescription) {
                await pc.addIceCandidate(new RTCIceCandidate(candidate));
            } else {
                // Buffer candidate until remote description is set
                const pending = this.pendingCandidates.get(peerId) || [];
                pending.push(new RTCIceCandidate(candidate));
                this.pendingCandidates.set(peerId, pending);
            }
        } catch (error) {
            console.error('Error adding ICE candidate:', error);
        }
    }

    /**
     * Send data to a specific peer
     */
    sendToPeer(peerId, data) {
        const channel = this.dataChannels.get(peerId);
        if (channel && channel.readyState === 'open') {
            channel.send(data);
            return true;
        }
        return false;
    }

    /**
     * Send data to all connected peers
     */
    broadcast(data) {
        this.dataChannels.forEach((channel, peerId) => {
            if (channel.readyState === 'open') {
                channel.send(data);
            }
        });
    }

    /**
     * Check if connected to a peer
     */
    isConnected(peerId) {
        const channel = this.dataChannels.get(peerId);
        return channel && channel.readyState === 'open';
    }

    /**
     * Get all connected peer IDs
     */
    getConnectedPeers() {
        const connected = [];
        this.dataChannels.forEach((channel, peerId) => {
            if (channel.readyState === 'open') {
                connected.push(peerId);
            }
        });
        return connected;
    }

    /**
     * Close connection to a peer
     */
    closeConnection(peerId) {
        const channel = this.dataChannels.get(peerId);
        if (channel) {
            channel.close();
            this.dataChannels.delete(peerId);
        }

        const pc = this.connections.get(peerId);
        if (pc) {
            pc.close();
            this.connections.delete(peerId);
        }

        this.pendingCandidates.delete(peerId);
    }

    /**
     * Close all connections
     */
    closeAll() {
        this.dataChannels.forEach((channel, peerId) => {
            channel.close();
        });
        this.dataChannels.clear();

        this.connections.forEach((pc, peerId) => {
            pc.close();
        });
        this.connections.clear();
        this.pendingCandidates.clear();
    }
}

// Export for use in other modules
window.WebRTCManager = WebRTCManager;
