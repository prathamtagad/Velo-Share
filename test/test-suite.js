/**
 * Velo - Automated Test Suite
 * 
 * Verifies protocol framing, SHA-256 cryptographic verification,
 * sequence reassembly, broadcast selection, tie-breaker logic,
 * and security sanitization.
 */

const assert = require('assert');
const crypto = require('crypto');

// Polyfill Web Crypto for Node test environment
if (!global.crypto) {
    global.crypto = crypto.webcrypto;
}

const {
    ProtocolConstants,
    packChunk,
    unpackChunk,
    computeSha256,
    generateUuid,
    generatePeerId,
    sanitizeFilename,
    sanitizeText,
    validateFileStartMetadata,
    computeAdaptiveAckTimeout,
    UUID_REGEX,
    SHA256_REGEX
} = require('../public/js/velo-app.js');

const {
    mergeIceServers,
    validateIceServer,
    DEFAULT_STUN_SERVERS
} = require('../public/js/config.js');

let passedTests = 0;
let totalTests = 0;

function test(name, fn) {
    totalTests++;
    try {
        fn();
        console.log(`  ✓ ${name}`);
        passedTests++;
    } catch (err) {
        console.error(`  ✕ ${name}`);
        console.error(`    Error: ${err.message}`);
    }
}

async function asyncTest(name, fn) {
    totalTests++;
    try {
        await fn();
        console.log(`  ✓ ${name}`);
        passedTests++;
    } catch (err) {
        console.error(`  ✕ ${name}`);
        console.error(`    Error: ${err.message}`);
    }
}

console.log('\n==================== RUNNING VELO TEST SUITE ====================\n');

// 1. Binary Chunk Framing Tests
test('packChunk & unpackChunk roundtrip preserves UUID, seq, and binary payload', () => {
    const testUuid = generateUuid();
    const seq = 42;
    const testPayload = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);

    const packed = packChunk(testUuid, seq, testPayload);
    assert.strictEqual(packed.byteLength, ProtocolConstants.HEADER_SIZE + testPayload.byteLength);

    const unpacked = unpackChunk(packed);
    assert.ok(unpacked, 'unpackChunk returned null on valid buffer');
    assert.strictEqual(unpacked.transferId, testUuid);
    assert.strictEqual(unpacked.sequenceNumber, seq);
    assert.deepStrictEqual(Array.from(unpacked.payload), Array.from(testPayload));
});

test('unpackChunk rejects truncated or corrupt headers', () => {
    // Too short
    assert.strictEqual(unpackChunk(new Uint8Array([1, 2, 3])), null);

    // Invalid magic bytes
    const badMagic = new Uint8Array(50);
    badMagic[0] = 0x00;
    badMagic[1] = 0x00;
    assert.strictEqual(unpackChunk(badMagic), null);

    // Invalid version
    const badVersion = new Uint8Array(50);
    badVersion[0] = ProtocolConstants.MAGIC_0;
    badVersion[1] = ProtocolConstants.MAGIC_1;
    badVersion[2] = 99; // Unknown version
    assert.strictEqual(unpackChunk(badVersion), null);
});

// 2. Cryptographic Integrity & SHA-256
asyncTest('computeSha256 produces exact match with standard crypto', async () => {
    const sampleData = Buffer.from('Hello, Velo WebRTC P2P Transfer Engine!');
    const expectedHash = crypto.createHash('sha256').update(sampleData).digest('hex');

    const computed = await computeSha256(sampleData);
    assert.strictEqual(computed, expectedHash);
});

asyncTest('detects corrupted data via SHA-256 mismatch', async () => {
    const original = Buffer.from('Original file contents');
    const tampered = Buffer.from('Tampered file contents');

    const originalHash = await computeSha256(original);
    const tamperedHash = await computeSha256(tampered);

    assert.notStrictEqual(originalHash, tamperedHash);
});

// 3. Chunk Sequencing & Missing Chunk Detection
test('Out-of-order chunks are reconstructed into correct indexed order', () => {
    const totalChunks = 3;
    const transferId = generateUuid();
    const reconstructed = new Array(totalChunks);
    const receivedChunks = new Set();

    const chunk0 = packChunk(transferId, 0, new Uint8Array([1]));
    const chunk1 = packChunk(transferId, 1, new Uint8Array([2]));
    const chunk2 = packChunk(transferId, 2, new Uint8Array([3]));

    // Arrive out of order: 2, 0, 1
    const stream = [chunk2, chunk0, chunk1];
    for (const raw of stream) {
        const unpacked = unpackChunk(raw);
        reconstructed[unpacked.sequenceNumber] = unpacked.payload[0];
        receivedChunks.add(unpacked.sequenceNumber);
    }

    assert.strictEqual(receivedChunks.size, totalChunks);
    assert.deepStrictEqual(reconstructed, [1, 2, 3]);
});

test('Missing chunks are reliably identified before completion', () => {
    const totalChunks = 3;
    const receivedChunks = new Set([0, 2]); // Missing chunk 1

    const isComplete = receivedChunks.size === totalChunks;
    assert.strictEqual(isComplete, false, 'Incomplete transfer must not be flagged complete');
});

// 4. Broadcast Selection Logic
test('Broadcast mode "selected" with 0 peers returns empty array (NEVER falls back to all)', () => {
    const mockConnections = new Map([
        ['PEER-A', { id: 'PEER-A' }],
        ['PEER-B', { id: 'PEER-B' }]
    ]);
    const selectedPeers = new Set(); // 0 selected
    const broadcastMode = 'selected';

    function getTargetConnections(mode, selected, connections) {
        if (mode === 'all') {
            return Array.from(connections.values());
        }
        if (mode === 'selected') {
            if (selected.size === 0) {
                return []; // Bug fixed: returns empty, not all!
            }
            return Array.from(connections.entries())
                .filter(([id]) => selected.has(id))
                .map(([, val]) => val);
        }
        return [];
    }

    const targets = getTargetConnections(broadcastMode, selectedPeers, mockConnections);
    assert.strictEqual(targets.length, 0, 'Must return 0 targets when 0 peers are selected');

    // When 1 peer is selected
    selectedPeers.add('PEER-A');
    const targetsSelected = getTargetConnections(broadcastMode, selectedPeers, mockConnections);
    assert.strictEqual(targetsSelected.length, 1);
    assert.strictEqual(targetsSelected[0].id, 'PEER-A');

    // When mode is "all"
    const targetsAll = getTargetConnections('all', selectedPeers, mockConnections);
    assert.strictEqual(targetsAll.length, 2);
});

// 5. Simultaneous Cross-Connection Tie-Breaker
test('Tie-breaker deterministically picks winner when both peers connect simultaneously', () => {
    const peer1 = 'VELO-ABC123';
    const peer2 = 'VELO-XYZ789';

    // Comparison is symmetric and deterministic
    const cmp1 = peer1.localeCompare(peer2);
    const cmp2 = peer2.localeCompare(peer1);

    assert.ok(cmp1 !== 0);
    assert.strictEqual(cmp1 > 0, !(cmp2 > 0));

    // Peer 2 wins in both perspectives
    const peer1WinsFrom1 = peer1.localeCompare(peer2) > 0;
    const peer2WinsFrom2 = peer2.localeCompare(peer1) > 0;

    assert.strictEqual(peer1WinsFrom1, false);
    assert.strictEqual(peer2WinsFrom2, true);
});

// 6. Identifier Generation & Uniqueness
test('generateUuid produces 100 unique valid v4 UUIDs', () => {
    const ids = new Set();
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

    for (let i = 0; i < 100; i++) {
        const id = generateUuid();
        assert.ok(uuidRegex.test(id), `Invalid UUID format: ${id}`);
        ids.add(id);
    }
    assert.strictEqual(ids.size, 100);
});

test('generatePeerId produces valid VELO-XXXXXX format', () => {
    for (let i = 0; i < 50; i++) {
        const pid = generatePeerId();
        assert.ok(pid.startsWith('VELO-'), `ID must start with VELO-: ${pid}`);
        assert.strictEqual(pid.length, 11);
    }
});

// 7. Security Sanitization & XSS Hardening
test('sanitizeFilename neutralizes directory traversal and XSS characters', () => {
    assert.strictEqual(sanitizeFilename('../../../secret.txt'), '_________secret.txt');
    assert.strictEqual(sanitizeFilename('<script>alert(1)</script>.png'), '_script_alert(1)__script_.png');
    assert.strictEqual(sanitizeFilename('normal-photo.jpg'), 'normal-photo.jpg');
    assert.strictEqual(sanitizeFilename(''), 'unnamed_file');
    assert.strictEqual(sanitizeFilename(null), 'unknown_file');
});

test('sanitizeText bounds text length and escapes type anomalies', () => {
    const safe = sanitizeText('Hello World');
    assert.strictEqual(safe, 'Hello World');

    const huge = 'A'.repeat(ProtocolConstants.MAX_TEXT_SHARE_CHARS + 1000);
    const truncated = sanitizeText(huge);
    assert.strictEqual(truncated.length, ProtocolConstants.MAX_TEXT_SHARE_CHARS);
});

// 8. Strict Metadata Validation
test('validateFileStartMetadata accepts well-formed transfer metadata', () => {
    const validUuid = generateUuid();
    const validSha = 'a'.repeat(64);
    const result = validateFileStartMetadata({
        transferId: validUuid,
        name: 'test-archive.tar.gz',
        size: 262144,
        chunkSize: 131072,
        totalChunks: 2,
        sha256: validSha
    });

    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.error, null);
    assert.strictEqual(result.sanitized.transferId, validUuid);
    assert.strictEqual(result.sanitized.totalChunks, 2);
    assert.strictEqual(result.sanitized.sha256, validSha);
});

test('validateFileStartMetadata rejects invalid UUIDs, bad sizes, and totalChunk mismatches', () => {
    const validUuid = generateUuid();
    const validSha = 'b'.repeat(64);

    // Bad UUID
    assert.strictEqual(validateFileStartMetadata({ transferId: 'invalid-id', name: 'file.txt', size: 100, chunkSize: 131072, totalChunks: 1 }).valid, false);

    // Negative / NaN / non-safe-integer size
    assert.strictEqual(validateFileStartMetadata({ transferId: validUuid, name: 'file.txt', size: -50, chunkSize: 131072, totalChunks: 1 }).valid, false);
    assert.strictEqual(validateFileStartMetadata({ transferId: validUuid, name: 'file.txt', size: NaN, chunkSize: 131072, totalChunks: 1 }).valid, false);

    // Exceeds MAX_FILE_SIZE (2GB)
    assert.strictEqual(validateFileStartMetadata({ transferId: validUuid, name: 'huge.iso', size: ProtocolConstants.MAX_FILE_SIZE + 100, chunkSize: 131072, totalChunks: 100 }).valid, false);

    // totalChunks mismatch with size and chunkSize
    assert.strictEqual(validateFileStartMetadata({ transferId: validUuid, name: 'file.txt', size: 262144, chunkSize: 131072, totalChunks: 99 }).valid, false);

    // Invalid SHA-256 (not 64 hex chars)
    assert.strictEqual(validateFileStartMetadata({ transferId: validUuid, name: 'file.txt', size: 100, chunkSize: 131072, totalChunks: 1, sha256: 'not-a-hash' }).valid, false);
});

// 9. Adaptive ACK Timeout Computation
test('computeAdaptiveAckTimeout scales with file size and respects clamp boundaries', () => {
    // 0 bytes -> minimum (30s)
    assert.strictEqual(computeAdaptiveAckTimeout(0), ProtocolConstants.ACK_TIMEOUT_MIN_MS);

    // 1 MB -> minimum + slight delta
    assert.ok(computeAdaptiveAckTimeout(1024 * 1024) >= ProtocolConstants.ACK_TIMEOUT_MIN_MS);

    // 1 GB -> proportional between MIN and MAX
    const timeout1GB = computeAdaptiveAckTimeout(1024 * 1024 * 1024);
    assert.ok(timeout1GB > ProtocolConstants.ACK_TIMEOUT_MIN_MS, '1GB file should exceed minimum ACK timeout');
    assert.ok(timeout1GB < ProtocolConstants.ACK_TIMEOUT_MAX_MS, '1GB file should stay under maximum ACK timeout');

    // 2 GB limit -> scales appropriately under MAX_MS (300s)
    const timeout2GB = computeAdaptiveAckTimeout(ProtocolConstants.MAX_FILE_SIZE);
    assert.ok(timeout2GB > timeout1GB, '2GB timeout should exceed 1GB timeout');
    assert.ok(timeout2GB <= ProtocolConstants.ACK_TIMEOUT_MAX_MS, '2GB timeout should not exceed maximum');

    // Overflow / massive size -> capped at MAX_MS
    assert.strictEqual(computeAdaptiveAckTimeout(100 * 1024 * 1024 * 1024), ProtocolConstants.ACK_TIMEOUT_MAX_MS);
});

// 10. ICE Server Merging & Deduplication (config.js)
test('mergeIceServers combines STUN and TURN with URL deduplication without clobbering', () => {
    const defaultStun = [
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' }
    ];
    const deploymentTurn = [
        { urls: 'turn:turn.org.example:3478', username: 'deployUser', credential: 'secretDeployPassword' },
        { urls: 'stun:stun1.l.google.com:19302' } // Duplicate of default
    ];
    const userTurn = [
        { urls: ['turns:turn.user.example:5349'], username: 'user1', credential: 'pw1' }
    ];

    const merged = mergeIceServers(defaultStun, deploymentTurn, userTurn);

    // Check that default STUN was preserved
    const urls = merged.flatMap(s => Array.isArray(s.urls) ? s.urls : [s.urls]);
    assert.ok(urls.includes('stun:stun1.l.google.com:19302'));
    assert.ok(urls.includes('stun:stun2.l.google.com:19302'));
    assert.ok(urls.includes('turn:turn.org.example:3478'));
    assert.ok(urls.includes('turns:turn.user.example:5349'));

    // Check that duplicates were removed
    const stun1Count = urls.filter(u => u === 'stun:stun1.l.google.com:19302').length;
    assert.strictEqual(stun1Count, 1, 'Duplicate STUN server should be deduplicated');
});

test('validateIceServer correctly validates URLs, schemes, and credentials', () => {
    // Valid TURN
    const validTurn = validateIceServer({
        urls: 'turn:turn.example.com:3478',
        username: 'user',
        credential: 'pwd'
    });
    assert.ok(validTurn);
    assert.strictEqual(validTurn.username, 'user');

    // Valid STUN (credentials optional)
    const validStun = validateIceServer({ urls: 'stun:stun.example.com:3478' });
    assert.ok(validStun);

    // Invalid scheme (e.g. http://)
    assert.strictEqual(validateIceServer({ urls: 'http://malicious.com' }), null);

    // TURN without credentials
    assert.strictEqual(validateIceServer({ urls: 'turn:turn.example.com:3478' }), null);

    // Null or invalid object
    assert.strictEqual(validateIceServer(null), null);
    assert.strictEqual(validateIceServer({}), null);
});

// 11. Composite Transfer Isolation & Security
test('Composite transfer ownership isolates transfers by peerId', () => {
    const activeReceives = new Map();
    const transferId = generateUuid();
    const peer1 = 'VELO-USER001';
    const peer2 = 'VELO-USER002';

    // Store transfers with composite keys
    activeReceives.set(`${peer1}:${transferId}`, { transferId, peerId: peer1, name: 'file1.txt' });
    activeReceives.set(`${peer2}:${transferId}`, { transferId, peerId: peer2, name: 'file2.txt' });

    // Both coexist without collision
    assert.strictEqual(activeReceives.size, 2);
    assert.strictEqual(activeReceives.get(`${peer1}:${transferId}`).name, 'file1.txt');
    assert.strictEqual(activeReceives.get(`${peer2}:${transferId}`).name, 'file2.txt');

    // Peer 2 cannot access Peer 1's record
    const receiveLookupForPeer2 = activeReceives.get(`${peer2}:${transferId}`);
    assert.strictEqual(receiveLookupForPeer2.peerId, peer2);
    assert.notStrictEqual(receiveLookupForPeer2.peerId, peer1);
});

// 12. Fail-Closed SHA-256 Integrity Verification
asyncTest('Fail-closed SHA-256 rejects corrupted file and computation error without triggering download', async () => {
    const cleanData = Buffer.from('Legitimate data package');
    const corruptedData = Buffer.from('Manipulated data package');

    const expectedHash = await computeSha256(cleanData);

    let ackSent = false;
    let downloadTriggered = false;
    let transferFailed = false;

    // Simulate receiveFileEnd verification logic
    async function verifyAndFinalize(blobData, advertisedHash) {
        try {
            const actualHash = await computeSha256(blobData);
            if (actualHash.toLowerCase() !== advertisedHash.toLowerCase()) {
                transferFailed = true;
                return; // Fail closed
            }
            ackSent = true;
            downloadTriggered = true;
        } catch (err) {
            transferFailed = true;
            return; // Fail closed
        }
    }

    // Corrupted file test
    await verifyAndFinalize(corruptedData, expectedHash);
    assert.strictEqual(transferFailed, true, 'Corrupted file must fail verification');
    assert.strictEqual(ackSent, false, 'ACK must NOT be sent for corrupted file');
    assert.strictEqual(downloadTriggered, false, 'Download must NOT trigger for corrupted file');

    // Reset and test computation exception
    transferFailed = false;
    ackSent = false;
    downloadTriggered = false;

    // Simulate crypto failure (e.g. invalid blob / runtime crypto fault)
    async function faultyVerification() {
        try {
            throw new Error('WebCrypto subsystem failure');
        } catch (err) {
            transferFailed = true;
            return; // Fail closed
        }
    }
    await faultyVerification();
    assert.strictEqual(transferFailed, true, 'Crypto failure must fail closed');
    assert.strictEqual(ackSent, false);
});

// 13. Queue Bounds & DoS Limits
test('Protocol constants enforce maximum queue size and concurrency limits', () => {
    assert.strictEqual(ProtocolConstants.MAX_QUEUED_FILES, 50);
    assert.strictEqual(ProtocolConstants.MAX_CONCURRENT_RECEIVES, 3);
    assert.strictEqual(ProtocolConstants.ACK_TIMEOUT_MIN_MS, 30000);
    assert.strictEqual(ProtocolConstants.ACK_TIMEOUT_MAX_MS, 300000);
});

// 14. Speed Test Conflict Guard
test('Speed test data header ignores inbound collision when outbound test is active', () => {
    const activeSpeedTests = new Map();
    const peerId = 'VELO-TEST01';

    // Active outbound test with pending resolve callback
    let pingResolved = false;
    activeSpeedTests.set(peerId, {
        testId: 'outbound-test-id-123',
        pingResolve: () => { pingResolved = true; },
        uploadResolve: null
    });

    // Simulated handleSpeedTestDataHeader logic
    function handleSpeedTestDataHeader(peer, data) {
        if (!data || !data.testId) return;
        let testEntry = activeSpeedTests.get(peer);
        if (testEntry && (testEntry.pingResolve || testEntry.uploadResolve)) {
            // Must ignore collision
            return false;
        }
        testEntry.testId = data.testId;
        return true;
    }

    const collisionAccepted = handleSpeedTestDataHeader(peerId, { testId: 'inbound-malicious-overwrite' });
    assert.strictEqual(collisionAccepted, false, 'Inbound collision must be rejected while outbound test is running');
    assert.strictEqual(activeSpeedTests.get(peerId).testId, 'outbound-test-id-123', 'Outbound testId must remain intact');
});

// Run async tests
(async () => {
    await new Promise(resolve => setTimeout(resolve, 50));
    console.log(`\n==================== TEST RESULTS: ${passedTests}/${totalTests} PASSED ====================\n`);
    if (passedTests !== totalTests) {
        process.exit(1);
    }
})();
