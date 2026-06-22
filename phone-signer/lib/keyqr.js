/**
 * CapAuth — device-to-device key transfer over (animated) QR.
 *
 * A PGP private key (or a PIN-encrypted envelope of one) is too big for a single
 * QR when RSA, so we chunk it across frames the source device cycles through and
 * the scanning device reassembles. The payload is transfer-agnostic: it may be a
 * raw armored key OR a keyvault envelope JSON — the scanner decides what to do
 * once reassembled.
 *
 * Frame wire format (one QR per frame), pipe-delimited, chunk last:
 *   CAPK1|<id>|<i>|<n>|<chunk>
 *     id    short hex transfer id (so two concurrent transfers don't mix)
 *     i     0-based frame index
 *     n     total frames
 *     chunk this frame's slice of the payload
 *
 * Byte-compatible copy lives at phone-signer/lib/keyqr.js.
 *
 * @module keyqr
 */

export const KEYQR_MAGIC = "CAPK1";
const SEP = "|";
const DEFAULT_CHUNK = 700; // chars/frame — small enough to scan reliably off-screen

function randomId(len = 4) {
  const hex = "0123456789abcdef";
  const r = globalThis.crypto.getRandomValues(new Uint8Array(len));
  let s = "";
  for (let i = 0; i < len; i++) s += hex[r[i] & 15];
  return s;
}

/**
 * Split a payload string into an ordered array of QR frame strings.
 * @param {string} payload - raw armored key or envelope JSON
 * @param {number} [chunkSize]
 * @param {string} [id] - injectable for tests
 * @returns {string[]}
 */
export function chunkPayload(payload, chunkSize = DEFAULT_CHUNK, id = randomId()) {
  const s = String(payload);
  const chunks = [];
  for (let i = 0; i < s.length; i += chunkSize) chunks.push(s.slice(i, i + chunkSize));
  if (chunks.length === 0) chunks.push("");
  const n = chunks.length;
  return chunks.map((c, i) => `${KEYQR_MAGIC}${SEP}${id}${SEP}${i}${SEP}${n}${SEP}${c}`);
}

/**
 * Parse one frame string. Returns {id, i, n, chunk} or null if not a key frame.
 * @param {string} s
 */
export function parseKeyFrame(s) {
  if (typeof s !== "string" || !s.startsWith(KEYQR_MAGIC + SEP)) return null;
  const parts = s.split(SEP);
  if (parts.length < 5) return null;
  const id = parts[1];
  const i = parseInt(parts[2], 10);
  const n = parseInt(parts[3], 10);
  // The chunk is everything after the 4th separator (rejoin defensively).
  const chunk = parts.slice(4).join(SEP);
  if (!id || !Number.isInteger(i) || !Number.isInteger(n) || n < 1 || i < 0 || i >= n) {
    return null;
  }
  return { id, i, n, chunk };
}

/**
 * Collects frames of a single transfer until complete, then reassembles.
 * Frames from a different transfer id are ignored (returns false).
 */
export class KeyFrameCollector {
  constructor() {
    this.id = null;
    this.n = 0;
    this.frames = new Map();
  }

  /** Add a parsed frame. Returns true if accepted into the current transfer. */
  add(frame) {
    if (!frame) return false;
    if (this.id === null) {
      this.id = frame.id;
      this.n = frame.n;
    }
    if (frame.id !== this.id || frame.n !== this.n) return false;
    this.frames.set(frame.i, frame.chunk);
    return true;
  }

  /** Convenience: parse a raw QR value and add it. */
  addRaw(rawValue) {
    return this.add(parseKeyFrame(rawValue));
  }

  get received() {
    return this.frames.size;
  }

  get total() {
    return this.n;
  }

  get complete() {
    return this.n > 0 && this.frames.size === this.n;
  }

  /** Reassemble the payload (null until complete). */
  assemble() {
    if (!this.complete) return null;
    let out = "";
    for (let i = 0; i < this.n; i++) out += this.frames.get(i);
    return out;
  }
}
