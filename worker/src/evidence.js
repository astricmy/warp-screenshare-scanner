// PNG Android opcional. Nenhum pixel é decodificado, recortado ou regravado.
export const MAX_PNG_BYTES = 4 * 1024 * 1024;
export const MAX_BASE64 = 4 * Math.ceil(MAX_PNG_BYTES / 3);
export const MAX_WIRE_BYTES = 256 * 1024 + MAX_BASE64;
const PNG_PREFIX = [137, 80, 78, 71, 13, 10, 26, 10];
const COLOR_CHUNKS = new Set(["sRGB", "sBIT", "gAMA", "cHRM", "pHYs", "cICP", "mDCV", "cLLI", "iCCP"]);
const CRC = Uint32Array.from({ length: 256 }, (_, n) => {
  for (let bit = 0; bit < 8; bit++) n = (n & 1) ? (0xedb88320 ^ (n >>> 1)) : (n >>> 1);
  return n >>> 0;
});

export function decodePNG(content) {
  if (typeof content !== "string" || content.length === 0 || content.length > MAX_BASE64 || content.length % 4 !== 0) throw new Error();
  const binary = atob(content);
  if (binary.length > MAX_PNG_BYTES || btoa(binary) !== content) throw new Error();
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < bytes.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function dimensions(bytes) {
  if (bytes.length < 45 || !PNG_PREFIX.every((v, i) => bytes[i] === v)) throw new Error();
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 8, width = 0, height = 0, hasPixels = false;
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
      if (bytes[offset + 16] !== 8 || ![2, 6].includes(bytes[offset + 17]) || bytes[offset + 18] || bytes[offset + 19] || bytes[offset + 20]) throw new Error();
    } else if (tag === "IDAT") {
      hasPixels ||= size > 0;
    } else if (tag === "IEND" && size === 0 && end + 4 === bytes.length && hasPixels) {
      return { width, height };
    } else if (!COLOR_CHUNKS.has(tag) || hasPixels) {
      throw new Error();
    }
    offset = end + 4;
  }
  throw new Error();
}

export async function verifyEvidence(envelope) {
  const file = envelope.attachments.find(f => f.content_type === "image/png");
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
