/**
 * Velo - App icon generator (pure Node, no dependencies).
 *
 * Replaces the mislabeled 1024x1024 JPEGs that shipped with a .png extension
 * with real, correctly-sized PNGs:
 *   icons/icon-192.png, icons/icon-512.png           (rounded square, "any")
 *   icons/icon-maskable-192.png, icon-maskable-512.png (full-bleed, "maskable")
 *
 * Design: diagonal purple gradient + white lightning bolt (Feather "zap").
 * Run: node scripts/generate-icons.js
 */

const zlib = require('zlib');
const fs = require('fs');
const path = require('path');

// ---------- PNG encoder (color type 6: RGBA, 8-bit) ----------

function crc32(buf) {
    let c, table = crc32.table;
    if (!table) {
        table = crc32.table = new Int32Array(256);
        for (let n = 0; n < 256; n++) {
            c = n;
            for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
            table[n] = c;
        }
    }
    let crc = -1;
    for (let i = 0; i < buf.length; i++) crc = (crc >>> 8) ^ table[(crc ^ buf[i]) & 0xFF];
    return (crc ^ -1) >>> 0;
}

function chunk(type, data) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(body));
    return Buffer.concat([len, body, crc]);
}

function encodePng(width, height, rgba) {
    const signature = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(width, 0);
    ihdr.writeUInt32BE(height, 4);
    ihdr[8] = 8;  // bit depth
    ihdr[9] = 6;  // color type RGBA
    ihdr[10] = 0; // compression
    ihdr[11] = 0; // filter
    ihdr[12] = 0; // interlace

    // Filter type 0 per scanline
    const raw = Buffer.alloc((width * 4 + 1) * height);
    for (let y = 0; y < height; y++) {
        raw[y * (width * 4 + 1)] = 0;
        rgba.copy(raw, y * (width * 4 + 1) + 1, y * width * 4, (y + 1) * width * 4);
    }

    return Buffer.concat([
        signature,
        chunk('IHDR', ihdr),
        chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
        chunk('IEND', Buffer.alloc(0))
    ]);
}

// ---------- Renderer ----------

const BOLT = [ // Feather "zap", 24x24 viewbox
    [13, 2], [3, 14], [12, 14], [11, 22], [21, 10], [12, 10]
];

function pointInBolt(x, y) { // even-odd ray casting, x/y in 24x24 space
    let inside = false;
    for (let i = 0, j = BOLT.length - 1; i < BOLT.length; j = i++) {
        const [xi, yi] = BOLT[i];
        const [xj, yj] = BOLT[j];
        if ((yi > y) !== (yj > y) &&
            x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) {
            inside = !inside;
        }
    }
    return inside;
}

function roundedRectMask(x, y, size, radius) {
    const dx = Math.max(Math.abs(x - size / 2) - (size / 2 - radius), 0);
    const dy = Math.max(Math.abs(y - size / 2) - (size / 2 - radius), 0);
    return dx * dx + dy * dy <= radius * radius;
}

/**
 * Renders one icon. opts:
 *  size, maskable (bool: full-bleed, content in the 40%-radius safe circle)
 */
function renderIcon({ size, maskable }) {
    const SS = 3; // 3x3 supersampling
    const out = Buffer.alloc(size * size * 4);
    const scale = 24 / size;

    // Content scale: maskable icons keep all content inside the central
    // 80% safe zone; regular icons use a small margin.
    const contentScale = maskable ? 0.58 : 0.78;
    const contentOffset = (24 - 24 * contentScale) / 2;

    const gradA = [124, 58, 237];  // #7C3AED
    const gradB = [167, 139, 250]; // #A78BFA

    for (let py = 0; py < size; py++) {
        for (let px = 0; px < size; px++) {
            let r = 0, g = 0, b = 0, a = 0;

            for (let sy = 0; sy < SS; sy++) {
                for (let sx = 0; sx < SS; sx++) {
                    const x = px + (sx + 0.5) / SS;
                    const y = py + (sy + 0.5) / SS;

                    // Background: rounded square ("any") or full-bleed (maskable)
                    let inBg;
                    if (maskable) {
                        inBg = true;
                    } else {
                        inBg = roundedRectMask(x, y, size, size * 0.22);
                    }

                    // Bolt coordinates: scaled into the safe area
                    const bx = (x * scale - contentOffset) / contentScale;
                    const by = (y * scale - contentOffset) / contentScale;
                    const inBolt = pointInBolt(bx, by);

                    // Diagonal gradient
                    const t = Math.min(1, Math.max(0, (x + y) / (2 * size)));
                    const cr = gradA[0] + (gradB[0] - gradA[0]) * t;
                    const cg = gradA[1] + (gradB[1] - gradA[1]) * t;
                    const cb = gradA[2] + (gradB[2] - gradA[2]) * t;

                    if (inBolt) {
                        r += 255; g += 255; b += 255; a += 255;
                    } else if (inBg) {
                        r += cr; g += cg; b += cb; a += 255;
                    }
                }
            }

            const n = SS * SS;
            const idx = (py * size + px) * 4;
            out[idx] = Math.round(r / n);
            out[idx + 1] = Math.round(g / n);
            out[idx + 2] = Math.round(b / n);
            out[idx + 3] = Math.round(a / n);
        }
    }
    return encodePng(size, size, out);
}

// ---------- Generate ----------

const iconsDir = path.join(__dirname, '..', 'public', 'icons');
fs.mkdirSync(iconsDir, { recursive: true });

const targets = [
    { file: 'icon-192.png', size: 192, maskable: false },
    { file: 'icon-512.png', size: 512, maskable: false },
    { file: 'icon-maskable-192.png', size: 192, maskable: true },
    { file: 'icon-maskable-512.png', size: 512, maskable: true }
];

for (const t of targets) {
    const png = renderIcon(t);
    fs.writeFileSync(path.join(iconsDir, t.file), png);
    console.log(`wrote public/icons/${t.file} (${t.size}x${t.size}, ${png.length} bytes)`);
}
