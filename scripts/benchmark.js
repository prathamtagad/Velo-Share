/**
 * Velo - Protocol performance benchmark (Phase 3 verification).
 *
 * Measures, on this machine:
 *  1. Chunk framing throughput: old wire params (512KB chunks) vs new
 *     (256KB chunks, serialization 'raw').
 *  2. Incremental SHA-256 vs whole-file digest (the old computeSha256(file)
 *     materialized the entire file as one ArrayBuffer).
 *  3. JSON control-message encode/parse cost (used with serialization 'raw').
 *
 * Run: node scripts/benchmark.js
 */

const {
    ProtocolConstants,
    packChunk,
    unpackChunk,
    Sha256
} = require('../public/js/velo-app.js');

const crypto = require('crypto');

global.crypto = global.crypto || crypto.webcrypto;

function bench(name, iterations, fn) {
    // warmup
    for (let i = 0; i < 3; i++) fn(i);
    const start = process.hrtime.bigint();
    for (let i = 0; i < iterations; i++) fn(i);
    const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
    return { name, elapsedMs, iterations };
}

function mbPerSec(bytesPerOp, iterations, elapsedMs) {
    return (bytesPerOp * iterations) / (elapsedMs / 1000) / (1024 * 1024);
}

const PAYLOAD_MB = 128; // total bytes through the framing path
const transferId = '12345678-1234-4123-8123-123456789abc';

console.log('\n==== Velo protocol benchmark ====\n');

// 1. Framing throughput: old 512KB vs new 256KB
for (const label of ['OLD wire (512KB chunks)', 'NEW wire (256KB chunks)']) {
    const chunkSize = label.startsWith('OLD') ? 512 * 1024 : 256 * 1024;
    const payload = new Uint8Array(chunkSize);
    crypto.randomFillSync(payload);
    const iters = Math.ceil(PAYLOAD_MB * 1024 * 1024 / chunkSize);

    const pack = bench(`pack ${label}`, iters, () => packChunk(transferId, 7, payload));
    const framed = packChunk(transferId, 7, payload);
    const unpack = bench(`unpack ${label}`, iters, () => unpackChunk(framed));

    console.log(`${label}:`);
    console.log(`  pack:   ${mbPerSec(chunkSize, pack.iterations, pack.elapsedMs).toFixed(0)} MB/s (${pack.elapsedMs.toFixed(1)}ms for ${PAYLOAD_MB}MB)`);
    console.log(`  unpack: ${mbPerSec(chunkSize, unpack.iterations, unpack.elapsedMs).toFixed(0)} MB/s (${unpack.elapsedMs.toFixed(1)}ms for ${PAYLOAD_MB}MB)`);
}

// 2. Incremental SHA-256 vs whole-buffer digest (time + memory profile)
const FILE_MB = 256;
const fileBuf = new Uint8Array(FILE_MB * 1024 * 1024);
crypto.randomFillSync(fileBuf);

// OLD behavior first: whole-file copy (what Blob.arrayBuffer() paid) + native digest
let t0 = process.hrtime.bigint();
const wholeCopy = fileBuf.slice(); // the full-file materialization the old code paid for
const wholeDigest = crypto.createHash('sha256').update(wholeCopy).digest('hex');
const wholeMs = Number(process.hrtime.bigint() - t0) / 1e6;
// The copy itself: time a bare slice to isolate its cost
t0 = process.hrtime.bigint();
const bareCopy = fileBuf.slice();
const copyMs = Number(process.hrtime.bigint() - t0) / 1e6;

// NEW behavior: JS incremental digest over 4MB slices, O(1) state
t0 = process.hrtime.bigint();
const incremental = new Sha256();
const SLICE = 4 * 1024 * 1024;
for (let off = 0; off < fileBuf.length; off += SLICE) {
    incremental.update(fileBuf.subarray(off, Math.min(off + SLICE, fileBuf.length)));
}
const incHash = incremental.digest();
const incMs = Number(process.hrtime.bigint() - t0) / 1e6;

console.log(`\nSHA-256 over ${FILE_MB}MB file:`);
console.log(`  old (whole-file copy + native digest): digest ${wholeMs.toFixed(0)}ms, of which the full-file ArrayBuffer copy is ~${copyMs.toFixed(0)}ms; peak RAM += ${FILE_MB}MB`);
console.log(`  new (incremental JS digest): ${incMs.toFixed(0)}ms, peak RAM += ~0MB`);
console.log(`  digests identical: ${incHash === wholeDigest} (${incHash.slice(0, 12)}…)`);
console.log(`  -> old is faster on the clock but requires the ENTIRE file in RAM; new caps memory at O(1) with ~${(FILE_MB / (incMs / 1000)).toFixed(0)} MB/s hash throughput (ample for DataChannel speeds)`);
console.log(`  (bare copy sanity: ${(bareCopy.length / 1024 / 1024).toFixed(0)}MB copied in ${copyMs.toFixed(0)}ms)`);

// 3. Control message JSON cost
const control = { type: 'file-start', transferId, name: 'holiday-photo-archive.zip', size: 1073741824, totalChunks: 4096, chunkSize: 262144, sha256: 'a'.repeat(64) };
const enc = bench('JSON.stringify control msg', 200000, () => JSON.stringify(control));
const encoded = JSON.stringify(control);
const dec = bench('JSON.parse control msg', 200000, () => JSON.parse(encoded));
console.log(`\nControl messages (file-start, ${encoded.length} bytes):`);
console.log(`  encode: ${enc.elapsedMs.toFixed(1)}ms / 200k = ${(enc.elapsedMs * 5).toFixed(2)}µs each`);
console.log(`  parse:  ${dec.elapsedMs.toFixed(1)}ms / 200k = ${(dec.elapsedMs * 5).toFixed(2)}µs each`);

console.log('\nNotes:');
console.log(`- Chunk sizes capped at ${ProtocolConstants.MAX_CHUNK_SIZE / 1024}KB to stay under browser SCTP message limits.`);
console.log('- With serialization raw, binary chunks skip PeerJS binary-pack re-encoding entirely (not measurable in Node).');
console.log('');
