// PNG Android opcional. Nenhum pixel é decodificado, recortado ou regravado.
export const MAX_PNG_BYTES = 4 * 1024 * 1024;
export const MAX_BASE64 = 4 * Math.ceil(MAX_PNG_BYTES / 3);
export const MAX_AVATAR_BYTES = 512 * 1024;
export const MAX_AVATAR_BASE64 = 4 * Math.ceil(MAX_AVATAR_BYTES / 3);
export const MAX_WIRE_BYTES = 256 * 1024 + MAX_BASE64 + MAX_AVATAR_BASE64;
const PNG_PREFIX = [137, 80, 78, 71, 13, 10, 26, 10];
const COLOR_CHUNKS = new Set(["sRGB", "sBIT", "gAMA", "cHRM", "pHYs", "cICP", "mDCV", "cLLI", "iCCP"]);
const CRC = Uint32Array.from({ length: 256 }, (_, n) => {
  for (let bit = 0; bit < 8; bit++) n = (n & 1) ? (0xedb88320 ^ (n >>> 1)) : (n >>> 1);
  return n >>> 0;
});

export function decodePNG(content, limit = MAX_PNG_BYTES) {
  if (typeof content !== "string" || content.length === 0 || content.length > 4 * Math.ceil(limit / 3) || content.length % 4 !== 0) throw new Error();
  const binary = atob(content);
  if (binary.length > limit || btoa(binary) !== content) throw new Error();
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < bytes.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function dimensions(bytes, avatar = false) {
  if (bytes.length < 45 || !PNG_PREFIX.every((v, i) => bytes[i] === v)) throw new Error();
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const compressed = [];
  let offset = 8, width = 0, height = 0, hasPixels = false, hasPalette = false, color = -1;
  for (let count = 0; count < 8192 && offset + 12 <= bytes.length; count++) {
    const size = view.getUint32(offset);
    const end = offset + 8 + size;
    if (end + 4 > bytes.length) throw new Error();
    let crc = 0xffffffff;
    for (let i = offset + 4; i < end; i++) crc = CRC[(crc ^ bytes[i]) & 255] ^ (crc >>> 8);
    if (((crc ^ 0xffffffff) >>> 0) !== view.getUint32(end)) throw new Error();
    const tag = String.fromCharCode(...bytes.subarray(offset + 4, offset + 8));
    if (count === 0) {
      if (tag !== "IHDR" || size !== 13) throw new Error();
      width = view.getUint32(offset + 8);
      height = view.getUint32(offset + 12);
      if (!width || !height || width > 8192 || height > 8192 || width * height > 16_777_216) throw new Error();
      const depth = bytes[offset + 16];
      color = bytes[offset + 17];
      if (bytes[offset + 18] || bytes[offset + 19] || bytes[offset + 20] > (avatar ? 1 : 0)) throw new Error();
      if (avatar) {
        if (width !== height || width > 512) throw new Error();
        const depths = { 0: [1, 2, 4, 8, 16], 2: [8, 16], 3: [1, 2, 4, 8], 4: [8, 16], 6: [8, 16] };
        if (!depths[color]?.includes(depth)) throw new Error();
      } else if (depth !== 8 || ![2, 6].includes(color)) throw new Error();
    } else if (avatar && tag === "PLTE" && !hasPalette && !hasPixels && size > 0 && size <= 768 && size % 3 === 0) {
      hasPalette = true;
    } else if (avatar && tag === "tRNS" && !hasPixels && size > 0 && size <= 256) {
      if (![0, 2, 3].includes(color)) throw new Error();
    } else if (tag === "IDAT") {
      hasPixels ||= size > 0;
      if (avatar && size) compressed.push(bytes.subarray(offset + 8, end));
    } else if (tag === "IEND" && size === 0 && end + 4 === bytes.length && hasPixels) {
      if (color === 3 && !hasPalette) throw new Error();
      return { width, height, depth: bytes[24], color, interlace: bytes[28], compressed };
    } else if (!COLOR_CHUNKS.has(tag) || hasPixels) {
      throw new Error();
    }
    offset = end + 4;
  }
  throw new Error();
}

async function verifyAvatar(avatar) {
  const { width, height, depth, color, interlace, compressed } = dimensions(decodePNG(avatar.content, MAX_AVATAR_BYTES), true);
  const channels = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 }[color];
  // Cada linha começa com um byte de filtro. No Adam7 cada passe tem sua própria largura.
  const passes = interlace ? [[0,0,8,8],[4,0,8,8],[0,4,4,8],[2,0,4,4],[0,2,2,4],[1,0,2,2],[0,1,1,2]] : [[0,0,1,1]];
  const filters = [];
  let expected = 0;
  for (const [x, y, dx, dy] of passes) {
    const cols = Math.ceil((width - x) / dx);
    if (cols <= 0) continue;
    const stride = 1 + Math.ceil(cols * depth * channels / 8);
    for (let row = y; row < height; row += dy) { filters.push(expected); expected += stride; }
  }
  const reader = new Blob(compressed).stream().pipeThrough(new DecompressionStream("deflate")).getReader();
  let size = 0, row = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (size + value.byteLength > expected) throw new Error();
      while (row < filters.length && filters[row] < size + value.byteLength) {
        if (value[filters[row++] - size] > 4) throw new Error();
      }
      size += value.byteLength;
    }
    if (size !== expected) throw new Error();
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export async function verifyEvidence(envelope) {
  const avatar = envelope.attachments.find(f => f.filename === "avatar.png");
  if (avatar) await verifyAvatar(avatar);
  const file = envelope.attachments.find(f => f.content_type === "image/png" && f.filename !== "avatar.png");
  if (!file) return;
  const attached = JSON.parse(envelope.attachments.find(f => f.content_type === "application/json").content);
  const metadata = attached.capture;
  if (attached.synthetic !== false || attached.consent?.screenshot !== true || metadata?.reviewed !== true || metadata?.status !== "REVISADA") throw new Error();
  if (metadata.filename !== file.filename || !Array.isArray(attached.findings) || !attached.findings.some(f => f.id === metadata.finding_id)) throw new Error();
  const bytes = decodePNG(file.content);
  const { width, height } = dimensions(bytes);
  if (width !== metadata.width || height !== metadata.height || bytes.length !== metadata.bytes) throw new Error();
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const hex = [...hash].map(n => n.toString(16).padStart(2, "0")).join("");
  if (hex !== metadata.sha256) throw new Error();
}
