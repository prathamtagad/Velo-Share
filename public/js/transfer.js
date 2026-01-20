/**
 * PyShare File Transfer Module
 * Handles file chunking, transfer progress, and speed calculation
 */

class FileTransferManager {
    constructor(webrtcManager) {
        this.webrtc = webrtcManager;
        this.transfers = new Map(); // transferId -> transfer info
        this.receivingFiles = new Map(); // transferId -> receiving buffer

        // Transfer settings
        this.CHUNK_SIZE = 16 * 1024; // 16KB chunks for optimal speed
        this.MAX_BUFFER_SIZE = 16 * 1024 * 1024; // 16MB buffer limit

        // Speed tracking
        this.speedHistory = [];
        this.totalTransferred = 0;
        this.peakSpeed = 0;

        // Event callbacks
        this.onTransferStart = null;
        this.onTransferProgress = null;
        this.onTransferComplete = null;
        this.onTransferError = null;
        this.onFileReceived = null;
        this.onSpeedUpdate = null;

        // Setup message handler
        this.webrtc.onDataChannelMessage = (peerId, data) => {
            this.handleMessage(peerId, data);
        };
    }

    /**
     * Generate unique transfer ID
     */
    generateTransferId() {
        return 'transfer_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }

    /**
     * Send file to all connected peers
     */
    async sendFile(file) {
        const connectedPeers = this.webrtc.getConnectedPeers();
        if (connectedPeers.length === 0) {
            console.error('No connected peers');
            if (this.onTransferError) {
                this.onTransferError(null, 'No connected peers');
            }
            return;
        }

        const transferId = this.generateTransferId();
        const transfer = {
            id: transferId,
            file: file,
            name: file.name,
            size: file.size,
            type: file.type,
            chunks: Math.ceil(file.size / this.CHUNK_SIZE),
            sentChunks: 0,
            startTime: Date.now(),
            bytesTransferred: 0,
            recipients: connectedPeers,
            status: 'sending'
        };

        this.transfers.set(transferId, transfer);

        // Notify about transfer start
        if (this.onTransferStart) {
            this.onTransferStart(transfer);
        }

        // Send file info to all peers
        const fileInfo = {
            type: 'file-info',
            transferId: transferId,
            name: file.name,
            size: file.size,
            fileType: file.type,
            chunks: transfer.chunks
        };

        this.webrtc.broadcast(JSON.stringify(fileInfo));

        // Start sending chunks
        await this.sendChunks(transfer);
    }

    /**
     * Send file chunks
     */
    async sendChunks(transfer) {
        const file = transfer.file;
        let offset = 0;
        let chunkIndex = 0;

        const sendNextChunk = async () => {
            if (offset >= file.size) {
                // Transfer complete
                transfer.status = 'complete';
                transfer.endTime = Date.now();

                const completeMsg = {
                    type: 'file-complete',
                    transferId: transfer.id
                };
                this.webrtc.broadcast(JSON.stringify(completeMsg));

                if (this.onTransferComplete) {
                    this.onTransferComplete(transfer);
                }
                return;
            }

            // Check buffer level (back pressure)
            for (const peerId of transfer.recipients) {
                const channel = this.webrtc.dataChannels.get(peerId);
                if (channel && channel.bufferedAmount > this.MAX_BUFFER_SIZE) {
                    // Wait for buffer to drain
                    await new Promise(resolve => setTimeout(resolve, 100));
                    return sendNextChunk();
                }
            }

            const chunk = file.slice(offset, offset + this.CHUNK_SIZE);
            const buffer = await chunk.arrayBuffer();

            // Create chunk header
            const header = new TextEncoder().encode(JSON.stringify({
                type: 'file-chunk',
                transferId: transfer.id,
                index: chunkIndex
            }) + '\n');

            // Combine header and chunk data
            const combined = new Uint8Array(header.length + buffer.byteLength);
            combined.set(header, 0);
            combined.set(new Uint8Array(buffer), header.length);

            // Send to all peers
            this.webrtc.broadcast(combined.buffer);

            transfer.sentChunks++;
            transfer.bytesTransferred = offset + buffer.byteLength;
            offset += this.CHUNK_SIZE;
            chunkIndex++;

            // Calculate speed
            this.updateSpeed(transfer);

            // Update progress
            if (this.onTransferProgress) {
                this.onTransferProgress(transfer, transfer.bytesTransferred / transfer.size);
            }

            // Schedule next chunk (use requestAnimationFrame for smoother UI)
            requestAnimationFrame(() => sendNextChunk());
        };

        sendNextChunk();
    }

    /**
     * Handle incoming message
     */
    handleMessage(peerId, data) {
        if (typeof data === 'string') {
            try {
                const message = JSON.parse(data);
                this.handleJsonMessage(peerId, message);
            } catch (e) {
                console.error('Invalid JSON message:', e);
            }
        } else if (data instanceof ArrayBuffer) {
            this.handleBinaryMessage(peerId, data);
        }
    }

    /**
     * Handle JSON messages
     */
    handleJsonMessage(peerId, message) {
        switch (message.type) {
            case 'file-info':
                this.handleFileInfo(peerId, message);
                break;
            case 'file-complete':
                this.handleFileComplete(peerId, message);
                break;
        }
    }

    /**
     * Handle binary messages (file chunks)
     */
    handleBinaryMessage(peerId, buffer) {
        const data = new Uint8Array(buffer);

        // Find header end
        let headerEnd = -1;
        for (let i = 0; i < Math.min(data.length, 500); i++) {
            if (data[i] === 10) { // newline
                headerEnd = i;
                break;
            }
        }

        if (headerEnd === -1) {
            console.error('Invalid chunk: no header found');
            return;
        }

        try {
            const headerStr = new TextDecoder().decode(data.slice(0, headerEnd));
            const header = JSON.parse(headerStr);

            if (header.type === 'file-chunk') {
                const chunkData = data.slice(headerEnd + 1);
                this.handleFileChunk(peerId, header, chunkData);
            }
        } catch (e) {
            console.error('Error parsing chunk header:', e);
        }
    }

    /**
     * Handle incoming file info
     */
    handleFileInfo(peerId, message) {
        const receiving = {
            id: message.transferId,
            name: message.name,
            size: message.size,
            type: message.fileType,
            chunks: message.chunks,
            receivedChunks: new Map(),
            bytesReceived: 0,
            startTime: Date.now(),
            senderId: peerId,
            status: 'receiving'
        };

        this.receivingFiles.set(message.transferId, receiving);

        if (this.onTransferStart) {
            this.onTransferStart({
                ...receiving,
                direction: 'receive'
            });
        }
    }

    /**
     * Handle incoming file chunk
     */
    handleFileChunk(peerId, header, chunkData) {
        const receiving = this.receivingFiles.get(header.transferId);
        if (!receiving) {
            console.error('Receiving file not found:', header.transferId);
            return;
        }

        // Store chunk
        receiving.receivedChunks.set(header.index, chunkData);
        receiving.bytesReceived += chunkData.length;
        this.totalTransferred += chunkData.length;

        // Calculate speed
        const elapsed = (Date.now() - receiving.startTime) / 1000;
        const speed = receiving.bytesReceived / elapsed / (1024 * 1024); // MB/s

        if (speed > this.peakSpeed) {
            this.peakSpeed = speed;
        }

        this.speedHistory.push(speed);
        if (this.speedHistory.length > 10) {
            this.speedHistory.shift();
        }

        if (this.onSpeedUpdate) {
            const avgSpeed = this.speedHistory.reduce((a, b) => a + b, 0) / this.speedHistory.length;
            this.onSpeedUpdate(speed, this.peakSpeed, avgSpeed, this.totalTransferred);
        }

        // Update progress
        if (this.onTransferProgress) {
            this.onTransferProgress({
                ...receiving,
                direction: 'receive'
            }, receiving.bytesReceived / receiving.size);
        }
    }

    /**
     * Handle file transfer complete
     */
    handleFileComplete(peerId, message) {
        const receiving = this.receivingFiles.get(message.transferId);
        if (!receiving) return;

        receiving.status = 'complete';
        receiving.endTime = Date.now();

        // Reassemble file
        const chunks = [];
        for (let i = 0; i < receiving.chunks; i++) {
            const chunk = receiving.receivedChunks.get(i);
            if (chunk) {
                chunks.push(chunk);
            }
        }

        const blob = new Blob(chunks, { type: receiving.type });

        if (this.onFileReceived) {
            this.onFileReceived(receiving, blob);
        }

        if (this.onTransferComplete) {
            this.onTransferComplete({
                ...receiving,
                direction: 'receive'
            });
        }

        // Cleanup
        this.receivingFiles.delete(message.transferId);
    }

    /**
     * Update speed metrics for sending
     */
    updateSpeed(transfer) {
        const elapsed = (Date.now() - transfer.startTime) / 1000;
        if (elapsed === 0) return;

        const speed = transfer.bytesTransferred / elapsed / (1024 * 1024); // MB/s

        if (speed > this.peakSpeed) {
            this.peakSpeed = speed;
        }

        this.speedHistory.push(speed);
        if (this.speedHistory.length > 10) {
            this.speedHistory.shift();
        }

        this.totalTransferred = transfer.bytesTransferred;

        if (this.onSpeedUpdate) {
            const avgSpeed = this.speedHistory.reduce((a, b) => a + b, 0) / this.speedHistory.length;
            this.onSpeedUpdate(speed, this.peakSpeed, avgSpeed, this.totalTransferred);
        }
    }

    /**
     * Format bytes to human readable
     */
    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    /**
     * Format speed to human readable
     */
    formatSpeed(mbps) {
        if (mbps < 1) {
            return (mbps * 1024).toFixed(1) + ' KB/s';
        }
        return mbps.toFixed(2) + ' MB/s';
    }

    /**
     * Reset speed tracking
     */
    resetStats() {
        this.speedHistory = [];
        this.totalTransferred = 0;
        this.peakSpeed = 0;
    }
}

// Export for use in other modules
window.FileTransferManager = FileTransferManager;
