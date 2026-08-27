// Generates trayTemplate.png (16x16) + trayTemplate@2x.png (32x32): a tiny
// ID-card glyph, black + alpha only (macOS template image).
import zlib from 'node:zlib';
import fs from 'node:fs';

function crc32(buf) {
  let c, table = [];
  for (let n = 0; n < 256; n++) {
    c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  let crc = 0xffffffff;
  for (const b of buf) crc = table[(crc ^ b) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
function png(size, on) {
  const raw = [];
  for (let y = 0; y < size; y++) {
    raw.push(0); // filter: none
    for (let x = 0; x < size; x++) raw.push(0, 0, 0, on(x, y) ? 255 : 0); // RGBA
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 6; // 8-bit RGBA
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(Buffer.from(raw))),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

// 16x16 design: card border rows 3-12 / cols 1-14; person (head + shoulders)
// on the left; two text lines on the right.
function glyph16(x, y) {
  const border =
    ((y === 3 || y === 12) && x >= 1 && x <= 14) ||
    ((x === 1 || x === 14) && y >= 3 && y <= 12);
  const head = y >= 5 && y <= 6 && x >= 4 && x <= 5;
  const body = y >= 8 && y <= 10 && x >= 3 && x <= 6;
  const line1 = y === 6 && x >= 8 && x <= 12;
  const line2 = y === 9 && x >= 8 && x <= 12;
  return border || head || body || line1 || line2;
}

fs.writeFileSync('trayTemplate.png', png(16, glyph16));
fs.writeFileSync('trayTemplate@2x.png', png(32, (x, y) => glyph16(Math.floor(x / 2), Math.floor(y / 2))));
console.log('wrote trayTemplate.png + @2x');
