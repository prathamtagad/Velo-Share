# Velo — Production P2P File Transfer

**Velo** is a browser-based peer-to-peer file transfer engine built on WebRTC DataChannels and PeerJS, featuring streaming SHA-256 integrity verification, binary chunk framing, a fail-closed receiver ACK protocol, and multi-tier STUN/TURN NAT traversal.

Files stream directly between browsers over encrypted WebRTC lanes. No intermediate file relaying or storage servers are used.

---

## 🚀 Key Architectural Features

- **Binary Framed Chunking**: 44-byte header (`VL` magic + version + 36-byte UUID + Uint32 sequence + payload). Chunks are sized 64–256KB to stay under the browser SCTP message limit (~256KB) and sent with PeerJS serialization `raw` — no binary-pack re-encoding, straight to the DataChannel.
- **Streaming SHA-256 Integrity**: Vendored incremental SHA-256 (FIPS 180-4, verified against Node `crypto`) hashes chunk-by-chunk on both sender and receiver — the file is never materialized as one giant ArrayBuffer. Receivers verify chunk count, byte length, and digest before download. **Note: SHA-256 detects corruption/tampering of data in transit; it does not authenticate who the sender is.**
- **Disk Streaming (OPFS)**: When the browser supports the File System Access API, incoming files stream directly to OPFS storage — the receive path is memory-bounded regardless of file size. An in-memory chunk fallback is used elsewhere, with a device-aware capacity budget.
- **Event-Driven Flow Control**: Per-peer outbound queues drained by `dataChannel.bufferedamountlow` events; slice prefetch overlaps disk reads with network sends; one slow peer never throttles a broadcast.
- **Consent & Abuse Controls**: Incoming files and text require explicit accept/decline before any data flows. Per-peer block/unblock, protocol-message rate limiting (including speed-test pings), inbound connection caps.
- **Strict Metadata Validation**: `file-start` headers are validated against a strict schema (RFC 4122 **v4** UUID with version/variant enforced, real-number numeric fields — no string coercion, exact `totalChunks`, mandatory 64-hex sha256).
- **Exact Chunk Bounds**: Each chunk must be exactly `min(chunkSize, size − seq·chunkSize)` bytes; cumulative over-delivery aborts the transfer.
- **Composite Transfer Ownership**: Receiver transfers keyed `${peerId}:${transferId}`; chunks and control messages from mismatching peers are rejected.
- **Receiver State Machine**: `awaiting-consent → receiving → verifying → completed/failed`; late/duplicate `file-end`, chunks after exit, and spurious ACKs are ignored as protocol errors.
- **CSPRNG Identifiers**: Peer IDs (`VELO-` + 10 chars, ~50 bits) and UUIDs use `crypto.getRandomValues`. Peer IDs are routing addresses, not authorization.
- **100% XSS Hardened**: All dynamic remote data rendered via DOM construction and `.textContent`. The only `innerHTML` uses are static, hard-coded icon markup that never contains remote data.
- **SVG Icon System**: No emoji glyphs; all icons are inline SVG (XSS-safe `createElementNS` construction).

---

## 🌐 NAT Traversal & TURN

STUN cannot connect peers behind symmetric NAT, CGNAT (4G/5G), or strict firewalls — a TURN relay is mandatory there. Velo supports three configuration methods:

### 1. In-App Network Settings (Zero Code)
Click **Network** in the header, paste your TURN credentials as a JSON array, and click Save & Apply. Note: applying new settings **issues you a new Peer ID** (you are warned and must confirm).

### 2. Deployment Config (`public/js/velo-config.js`)
Copy `public/js/velo-config.template.js` to `public/js/velo-config.js` (this file is **git-ignored** — never commit credentials) and set `window.VELO_CONFIG`:

```javascript
window.VELO_CONFIG = {
    // Option A: ephemeral TURN credential endpoint (JSON { iceServers: [...] })
    turnTokenEndpoint: '/api/turn-credentials',
    // Option B: static TURN servers
    iceServers: [{ urls: ['turn:turn.yourdomain.com:3478'], username: 'u', credential: 'p' }],
    // Option C: self-hosted PeerJS signaling server
    peerServer: { host: 'signal.yourdomain.com', port: 443, path: '/velo', secure: true }
};
```

`velo-config.js` is loaded **before** `config.js` in `app.html`. Ephemeral credentials are fetched asynchronously during peer startup (`getIceConfigAsync`). If you don't create the file you'll see a harmless 404 for it in the console.

### 3. Self-Hosted Coturn (Ubuntu / Debian)
```bash
sudo apt update && sudo apt install coturn -y
```
`/etc/turnserver.conf`:
```ini
listening-port=3478
tls-listening-port=5349
listening-ip=0.0.0.0
realm=turn.yourdomain.com
lt-cred-mech
user=velo_user:secure_password_here
cert=/etc/letsencrypt/live/turn.yourdomain.com/fullchain.pem
pkey=/etc/letsencrypt/live/turn.yourdomain.com/privkey.pem
fingerprint
no-cli
no-loopback-peers
no-multicast-peers
```
Open UDP 3478 and TCP 5349 in your firewall.

### Self-Hosted PeerJS Signaling
To stop using the public PeerJS cloud (`0.peerjs.com`), run [peerjs-server](https://github.com/peers/peerjs-server) and set `peerServer` in `velo-config.js` (see above).

---

## 🔒 Security Architecture

| Vector | Mitigation |
| :--- | :--- |
| Corrupt/tampered file | Streaming SHA-256, fail-closed on mismatch or crypto error (download aborted, sender notified). Detects corruption; not sender authentication. |
| Oversized/mis-sized chunks | Exact per-chunk length check + cumulative byte ceiling; violations abort the transfer. |
| Cross-peer injection | Composite `${peerId}:${transferId}` keys; origin peer verified on every message. |
| Protocol violations | Spurious ACK (before file-end / non-'ok'), duplicate file-end, chunks after state exit → peer marked failed / transfer aborted. |
| DoS / floods | Rate limits per peer (control/chunk/ping buckets), inbound connection rate cap, per-peer + global receive caps, aggregate receive capacity, consent prompts, per-peer block list. |
| XSS | 100% `.textContent`/DOM construction for remote data. |
| Stalled transfers | 30s no-progress receive idle timeout; consent and accept timeouts. |

---

## 📦 Running Locally & Testing

```bash
git clone https://github.com/prathamtagad/velo-share.git
cd velo-share
npm install        # installs the pinned `serve` devDependency
npm test           # automated test suite (mock DOM + mock conns)
npm run benchmark  # protocol performance benchmark
npm start          # serve public/ at http://localhost:3000
```

## 🧪 Automated Verification Suite

`npm test` runs an async runner that drives **real VeloApp methods** against a minimal mock DOM and mock PeerJS connections, covering protocol framing, strict metadata validation, incremental SHA-256, the consent flow, sender cancel mid-transfer, receiver state machine, rate limiting, text-share semantics (never delivered to later peers; one-time expiring link tokens), Unicode usernames, control-character filenames, SCTP-safe chunk sizing, and more. Run it to see the full list; the suite exits non-zero on any failure.

Two-browser live transfer (the real WebRTC path) is best verified manually: open `http://localhost:3000` in two browser profiles and send a file.

---

## 📁 Repository Structure

```
├── public/
│   ├── index.html, app.html, about.html, privacy.html, terms.html
│   ├── manifest.json              # PWA manifest (real PNG icons, relative paths)
│   ├── sw.js                      # Service Worker (scope-relative, versioned cache v5)
│   ├── _headers                   # Netlify security headers (CSP etc.)
│   ├── icons/                     # real 192/512 PNGs + maskable variants
│   ├── vendor/                    # self-hosted PeerJS + qrcodejs (SRI-pinned)
│   └── js/
│       ├── velo-config.template.js# deployment config template (copy to velo-config.js)
│       ├── config.js              # ICE merger/validator + async ephemeral TURN fetch
│       ├── theme.js, velo-app.js
├── scripts/
│   ├── benchmark.js               # protocol performance benchmark
│   └── generate-icons.js          # regenerates the PNG icons
└── test/test-suite.js             # automated verification suite
```

---

## ⚠️ Operational Constraints

* **Max file size**: 2GB protocol ceiling. With OPFS streaming (Chrome/Edge desktop) receives are disk-bound, so large files don't hit RAM limits; the in-memory fallback applies a device-aware budget (256MB–1GB aggregate) and rejects beyond it with a clear message. Live 2GB end-to-end transfers have **not** been verified by the authors — treat 2GB as a protocol ceiling, not a tested guarantee.
* **Signaling**: Uses the public PeerJS cloud by default; self-host via `peerServer` for production.
* **Protocol version**: Wire protocol v2 — both peers must run this version.
* **Symmetric NAT / CGNAT** requires TURN; configure it for production deployments.

---

## 📄 License

MIT License. Built by Pratham Tagad.
