// Redis-compatible CRC16 slot math (mirrors python/qihse/browser/slots.py;
// vectors pinned there against CLUSTER KEYSLOT).
const TABLE = [];
for (let i = 0; i < 256; i++) {
  let crc = i << 8;
  for (let b = 0; b < 8; b++) {
    crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) : (crc << 1);
    crc &= 0xFFFF;
  }
  TABLE.push(crc);
}

export function crc16(data) {
  let crc = 0;
  for (let i = 0; i < data.length; i++) {
    crc = ((crc << 8) & 0xFFFF) ^ TABLE[(crc >> 8) ^ data[i]];
  }
  return crc;
}

export function keyslot(key) {
  const bytes = new TextEncoder().encode(key);
  const start = bytes.indexOf(0x7B); // '{'
  if (start !== -1) {
    const end = bytes.indexOf(0x7D, start + 1); // '}'
    if (end !== -1 && end > start + 1) {
      return crc16(bytes.slice(start + 1, end)) % 16384;
    }
  }
  return crc16(bytes) % 16384;
}

export function ownerForSlot(slot, runs) {
  for (const r of runs || []) {
    if (slot >= r.start && slot <= r.end) return r;
  }
  return null;
}
