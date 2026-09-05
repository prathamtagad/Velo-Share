# Velo — Production P2P File Transfer

**Velo** is a high-performance, browser-based peer-to-peer file transfer engine built on WebRTC DataChannels and PeerJS. It features end-to-end cryptographic SHA-256 integrity verification, binary chunk framing with sequence numbers, a formal fail-closed receiver ACK protocol, composite transfer ownership isolation, and multi-tier STUN/TURN NAT traversal.

Files stream directly between browsers over encrypted WebRTC lanes. No intermediate file relaying or storage servers are used.

---

## 🚀 Key Architectural Features

- **Binary Framed Chunking**: 44-byte binary framing header (`VL` magic + version + 36-byte UUID + Uint32 sequence number + payload) prevents packet interleaving, detects out-of-order delivery, and runs at full WebRTC line speed without JSON/object serialization overhead.
- **Fail-Closed Cryptographic SHA-256 Integrity**: Senders compute SHA-256 digests; receivers verify chunk counts, byte length, and recomputed SHA-256 before triggering downloads. Any mismatch or crypto exception immediately aborts the transfer, notifies the peer with `file-error`, and prevents download.
- **Strict Metadata Validation**: Incoming `file-start` headers are strictly validated against a formal schema (RFC 4122 v4 UUID, bounded filename, finite safe integer sizes up to 2GB, valid chunk size, exact `totalChunks = Math.ceil(size / chunkSize)` equality, and 64-character hex hash).
- **Composite Transfer Ownership**: All receiver transfers are keyed by composite identity (`${peerId}:${transferId}`). Incoming chunks and completion commands are checked against the originating peer ID, eliminating transfer collisions and cross-peer injection.
- **Adaptive Verification ACK Timeout**: Replaced arbitrary static timeouts with an adaptive timeout dynamically scaled to file size: `clamp(30s, 30s + (fileSize / 15MB/s), 300s)`.
- **Multi-Tier STUN/TURN Merging**: True deduplicating ICE merger combines default public STUN servers with deployment-level TURN relays (`velo-config.template.js`) and user-supplied `localStorage` TURN servers without clobbering.
- **Ephemeral TURN Credential Support**: Optional hook (`fetchEphemeralTurnCredentials`) enables integration with dynamic short-lived token services (e.g. Cloudflare Calls, Twilio Network Traversal, custom API endpoints).
- **PeerJS Generation Safety**: PeerJS initialization cycles track epoch generation tokens (`peerGeneration`). Callbacks from old or orphaned peer instances are discarded, preventing stale listener leaks.
- **Safe Network Reconfiguration**: Network settings cannot be altered during active transfers. Applying new ICE servers safely tears down previous peer instances before reconnecting.
- **Queue Deadlock Elimination & DoS Limits**: Strict `try...catch...finally` execution safeguards queue processing against unhandled FileReader or peer aborts. Hard protocol limits (`MAX_QUEUED_FILES = 50`, `MAX_CONCURRENT_RECEIVES = 3`) defend against resource exhaustion.
- **100% XSS Hardened**: All dynamic remote data (usernames, filenames, text snippets) is rendered via DOM creation and `.textContent`. Unsafe `innerHTML` interpolation of untrusted input is completely eliminated.
- **Dynamic Origin Links**: Share URLs and QR codes resolve dynamically using `window.location.origin` for seamless local, staging, and production deployments.

---

## 🌐 NAT Traversal & The "One Friend Cannot Connect" Problem

### Why STUN Fails for Certain Users
WebRTC establishes direct peer-to-peer connections using ICE (Interactive Connectivity Establishment). STUN (Session Traversal Utilities for NAT) works by asking an external server to reflect back the user's public IP and port.

However, STUN **cannot** connect two peers when either peer is behind:
1. **Symmetric NAT**: The router assigns a *different* external mapping port for every destination address/port requested.
2. **Carrier-Grade NAT (CGNAT)**: Typical on 4G/5G mobile cellular connections, where thousands of subscribers share external IPs.
3. **Enterprise & Campus Firewalls**: Strict firewalls that block outbound UDP traffic or filter non-whitelisted ports.

When one friend is on mobile data or behind a symmetric router, direct UDP hole punching fails with ICE state `disconnected` or `failed`. **A TURN (Traversal Using Relays around NAT) server is mathematically mandatory** in these topologies to relay encrypted traffic over standard ports (UDP 3478, TCP 443, or TLS 5349).

---

## 🛠️ TURN Server Deployment & Configuration

Velo supports three methods of configuring TURN relays:

### 1. In-App Network Settings (Zero Code)
Users can input their own TURN credentials directly in the app:
1. Click the **⚙️ Network** button in the header or landing page.
2. Paste your TURN credentials as a JSON array:
```json
[
  {
    "urls": ["turn:turn.example.com:3478", "turns:turn.example.com:5349"],
    "username": "velo_user",
    "credential": "secure_password"
  }
]
```
3. Click **Save & Apply**. Credentials are saved in `localStorage` and merged with default STUN servers on every session.

### 2. Domain Deployment Configuration (`public/js/config.js`)
For administrators deploying Velo on a domain:
Copy `public/js/velo-config.template.js` to `public/js/config.js` or define `window.VELO_CONFIG`:
```javascript
window.VELO_CONFIG = {
    iceServers: [
        {
            urls: [
                'turn:turn.yourdomain.com:3478?transport=udp',
                'turn:turn.yourdomain.com:3478?transport=tcp',
                'turns:turn.yourdomain.com:5349?transport=tcp'
            ],
            username: 'production_user',
            credential: 'production_password'
        }
    ],
    // Optional: Dynamic ephemeral token endpoint
    // ephemeralTurnEndpoint: 'https://api.yourdomain.com/v1/turn-credentials'
};
```

### 3. Setting Up Self-Hosted Coturn (Ubuntu / Debian)
To run your own high-speed TURN server:
```bash
sudo apt update && sudo apt install coturn -y
sudo nano /etc/turnserver.conf
```
Add the following production configuration:
```ini
listening-port=3478
tls-listening-port=5349
listening-ip=0.0.0.0

# Domain & Realm
realm=turn.yourdomain.com
server-name=turn.yourdomain.com

# Long-term authentication
lt-cred-mech
user=velo_user:secure_password_here

# TLS certificates (e.g. Let's Encrypt)
cert=/etc/letsencrypt/live/turn.yourdomain.com/fullchain.pem
pkey=/etc/letsencrypt/live/turn.yourdomain.com/privkey.pem

# Security & Fingerprinting
fingerprint
no-cli
no-loopback-peers
no-multicast-peers
```
Restart and enable the service:
```bash
sudo systemctl restart coturn
sudo systemctl enable coturn
```

Ensure UDP port 3478 and TCP port 5349 are open in your cloud firewall (e.g. AWS Security Groups, UFW).

---

## 🔒 Security Architecture

| Vector | Mitigation |
| :--- | :--- |
| **Tampered / Corrupt File** | SHA-256 computed on sender, recomputed on reconstructed Blob by receiver. Fails closed (download aborted, error sent) on mismatch or crypto throw. |
| **Packet Interleaving** | 44-byte binary framing header per chunk (`VL` magic + UUID + seq) enforces deterministic indexed assembly. |
| **Spoofed Chunks / Cross-Peer Injection** | Transfers tracked by composite key `${peerId}:${transferId}`. Chunks from mismatching peers are rejected immediately. |
| **Denial of Service (Memory Exhaustion)** | Hard 2GB file limit (`ProtocolConstants.MAX_FILE_SIZE`). Max 50 queued files (`MAX_QUEUED_FILES`). Max 3 concurrent receives per peer (`MAX_CONCURRENT_RECEIVES`). Chunks array freed immediately upon Blob creation. |
| **XSS / HTML Injection** | 100% DOM element construction with `.textContent`. Sanitization passes on filenames (`sanitizeFilename`) and text snippets (`sanitizeText`). |
| **Queue Starvation / Deadlock** | Top-level `try...finally` wrappers on `sendFile` and reader error/abort hooks ensure `isSending` lock is always released. |

---

## 📦 Running Locally & Testing

### Prerequisites
* Node.js v18+
* npm v9+

### Quick Start
```bash
# Clone the repository
git clone https://github.com/prathamtagad/velo-share.git
cd velo-share

# Install dependencies
npm install

# Run automated verification test suite
npm test

# Start local server
npm start
```
Open `http://localhost:3000` in your browser.

---

## 🧪 Automated Verification Suite

Run the full protocol, security, and integrity test suite:
```bash
npm test
```

The test suite validates 21 automated assertions across:
1. Binary chunk framing & unpack header roundtrip (UUID, seq, binary payload).
2. Truncated and corrupted binary header rejection.
3. Out-of-order chunk reconstruction into exact indexed order.
4. Missing chunk detection prior to file finalization.
5. Broadcast target selection (`selected` mode with 0 peers safely returns empty list).
6. Deterministic tie-breaking for simultaneous cross-connections.
7. UUID v4 uniqueness and formatting.
8. Peer ID generation format (`VELO-XXXXXX`).
9. Directory traversal (`../../`) and XSS filename sanitization.
10. Text sharing length bounding.
11. Strict metadata validation (`validateFileStartMetadata`) on valid input.
12. Rejection of invalid UUIDs, negative/NaN sizes, size limit overflows, and totalChunk mismatches.
13. Adaptive ACK timeout scaling across file sizes [30s..300s].
14. ICE server multi-tier merging and duplicate URL deduplication.
15. ICE server object schema and scheme validation (`stun:`, `turn:`, `turns:`).
16. Composite transfer ownership isolation (`${peerId}:${transferId}`).
17. Protocol limits (`MAX_QUEUED_FILES`, `MAX_CONCURRENT_RECEIVES`, ACK timeouts).
18. Speed test collision guards (inbound headers ignored during active outbound tests).
19. WebCrypto SHA-256 match against standard Node.js `crypto`.
20. Tampered data detection via SHA-256 mismatch.
21. Fail-closed receiver verification behavior (abort transfer without triggering download).

---

## 📊 Verification & Production Readiness Matrix

| Area | Status | Verification Detail |
| :--- | :--- | :--- |
| **Binary Protocol & Framing** | ✅ VERIFIED | Automated test suite passes roundtrip framing, seq indexing, magic bytes, corrupted header rejection. |
| **SHA-256 Integrity Verification** | ✅ VERIFIED | Verified against Node `crypto.createHash('sha256')`. Fail-closed rejection verified. |
| **Strict Metadata Validation** | ✅ VERIFIED | Schema validated against bad UUIDs, negative sizes, >2GB limits, and chunk mismatches. |
| **Queue Management & Deadlocks** | ✅ VERIFIED | Verified `isSending` lock release on FileReader error, abort, peer failure, and unexpected exception. |
| **XSS Hardening** | ✅ VERIFIED | Zero `innerHTML` usage with untrusted input across codebase. Text nodes enforced. |
| **ICE Server Merging & Parsing** | ✅ VERIFIED | Validated deduplication, credential verification, and non-clobbering merge logic. |
| **TURN Traversal (Local / Sim)** | ⚠️ CONFIGURATION VERIFIED | Merging and credential parsing tested. *Note: Live cross-NAT relay requires external Coturn or managed TURN instance.* |

---

## 📁 Repository Structure

```
├── public/
│   ├── index.html                 # Marketing landing page
│   ├── app.html                   # Main P2P application workspace
│   ├── about.html                 # Project overview
│   ├── privacy.html               # Privacy policy
│   ├── terms.html                 # Terms of service
│   ├── manifest.json              # PWA manifest
│   ├── sw.js                      # Service Worker (offline cache v3)
│   ├── css/
│   │   └── style.css              # Core styles & design tokens
│   └── js/
│       ├── config.js              # Multi-tier ICE server merger & validator
│       ├── velo-config.template.js# Production deployment TURN configuration template
│       ├── theme.js               # Light/Dark mode state
│       └── velo-app.js            # Core WebRTC P2P engine & protocol logic
├── test/
│   └── test-suite.js              # Automated unit & protocol verification suite
├── package.json                   # Scripts & project metadata
└── README.md                      # Production technical documentation
```

---

## ⚠️ Operational Constraints

* **Maximum In-Memory File Size**: ~2GB per file in modern 64-bit browsers due to browser ArrayBuffer and Blob memory limits.
* **Signaling Service**: WebRTC connection establishment uses PeerJS signaling (`0.peerjs.com`). Once data channels are open, transfers continue directly peer-to-peer even if signaling temporarily disconnects.
* **Symmetric NATs / CGNAT**: Direct STUN connection between two symmetric NATs or restrictive mobile cellular networks is impossible without a TURN relay. Always configure a TURN server for public production deployments.

---

## 📄 License

MIT License. Built by Pratham Tagad.
