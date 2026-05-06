/**
 * Shared cryptographic utilities.
 * Provides hex encoding/decoding, XOR, padding, modular arithmetic, and random bytes.
 * Only uses built-in JS primitives — no external crypto libraries.
 */

// ─── Hex encode / decode ────────────────────────────────────────────────────

/** Convert a Uint8Array to a hex string. */
export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Convert a hex string to a Uint8Array. */
export function hexToBytes(hex) {
  hex = hex.replace(/\s/g, '');
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return arr;
}

/** Convert a string (UTF-8) to Uint8Array. */
export function stringToBytes(str) {
  return new TextEncoder().encode(str);
}

/** Convert Uint8Array to UTF-8 string. */
export function bytesToString(bytes) {
  return new TextDecoder().decode(bytes);
}

// ─── Byte-level XOR ─────────────────────────────────────────────────────────

/** XOR two Uint8Arrays of the same length. */
export function xorBytes(a, b) {
  const len = Math.min(a.length, b.length);
  const result = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

// ─── PKCS#7 Padding ─────────────────────────────────────────────────────────

/** Pad data to a multiple of blockSize using PKCS#7. */
export function pkcs7Pad(data, blockSize = 16) {
  const padLen = blockSize - (data.length % blockSize);
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data);
  for (let i = data.length; i < padded.length; i++) {
    padded[i] = padLen;
  }
  return padded;
}

/** Remove PKCS#7 padding. */
export function pkcs7Unpad(data) {
  if (data.length === 0) return data;
  const padLen = data[data.length - 1];
  if (padLen === 0 || padLen > data.length) return data;
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) return data; // Invalid padding
  }
  return data.slice(0, data.length - padLen);
}

// ─── Random bytes ───────────────────────────────────────────────────────────

/** Generate n random bytes using the Web Crypto API. */
export function randomBytes(n) {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

/** Generate a random integer in [0, max). */
export function randomInt(max) {
  if (max <= 0) return 0;
  const buf = new Uint8Array(4);
  crypto.getRandomValues(buf);
  const val = ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]) >>> 0;
  return val % max;
}

// ─── BigInt modular arithmetic ──────────────────────────────────────────────

/** Modular exponentiation: base^exp mod mod (all BigInt). */
export function modPow(base, exp, mod) {
  base = ((base % mod) + mod) % mod;
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) {
      result = (result * base) % mod;
    }
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

/** Extended GCD: returns [gcd, x, y] such that a*x + b*y = gcd. */
export function extGcd(a, b) {
  if (b === 0n) return [a, 1n, 0n];
  const [g, x1, y1] = extGcd(b, a % b);
  return [g, y1, x1 - (a / b) * y1];
}

/** Modular inverse: a^{-1} mod m. Throws if not invertible. */
export function modInverse(a, m) {
  a = ((a % m) + m) % m;
  const [g, x] = extGcd(a, m);
  if (g !== 1n) throw new Error(`No inverse: gcd(${a}, ${m}) = ${g}`);
  return ((x % m) + m) % m;
}

/** GCD of two BigInts. */
export function gcd(a, b) {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b > 0n) {
    [a, b] = [b, a % b];
  }
  return a;
}

// ─── Block splitting ────────────────────────────────────────────────────────

/** Split a Uint8Array into blocks of blockSize, with PKCS#7 padding. */
export function splitBlocks(data, blockSize = 16, pad = true) {
  const padded = pad ? pkcs7Pad(data, blockSize) : data;
  const blocks = [];
  for (let i = 0; i < padded.length; i += blockSize) {
    blocks.push(padded.slice(i, i + blockSize));
  }
  return blocks;
}

/** Concatenate multiple Uint8Arrays. */
export function concatBytes(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

// ─── Bit-level helpers ──────────────────────────────────────────────────────

/** Get bit i (0-indexed from MSB) of a byte array. */
export function getBit(bytes, i) {
  const byteIdx = Math.floor(i / 8);
  const bitIdx = 7 - (i % 8);
  if (byteIdx >= bytes.length) return 0;
  return (bytes[byteIdx] >> bitIdx) & 1;
}

/** Convert bytes to a binary string (e.g. "01101001..."). */
export function bytesToBits(bytes) {
  return Array.from(bytes).map(b => b.toString(2).padStart(8, '0')).join('');
}

/** Convert a binary string to Uint8Array. */
export function bitsToBytes(bits) {
  while (bits.length % 8 !== 0) bits = '0' + bits;
  const arr = new Uint8Array(bits.length / 8);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(bits.substr(i * 8, 8), 2);
  }
  return arr;
}

/** Increment a 16-byte counter (big-endian). */
export function incrementCounter(counter) {
  const result = new Uint8Array(counter);
  for (let i = result.length - 1; i >= 0; i--) {
    result[i]++;
    if (result[i] !== 0) break;
  }
  return result;
}

/** Add an integer offset to a 16-byte counter (big-endian). */
export function addToCounter(counter, offset) {
  const result = new Uint8Array(counter);
  let carry = offset;
  for (let i = result.length - 1; i >= 0 && carry > 0; i--) {
    const sum = result[i] + (carry & 0xff);
    result[i] = sum & 0xff;
    carry = (carry >> 8) + (sum >> 8);
  }
  return result;
}

// ─── BigInt <-> bytes helpers ─────────────────────────────────────────────

/** Convert a Uint8Array (big-endian) to BigInt. */
export function bytesToBigInt(bytes) {
  let result = 0n;
  for (const b of bytes) {
    result = (result << 8n) | BigInt(b);
  }
  return result;
}

/** Convert a BigInt to a fixed-length Uint8Array (big-endian). */
export function bigIntToBytes(value, length) {
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Constant-time byte array comparison. */
export function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/** Truncate a byte array to a given bit length. */
export function truncateBits(bytes, bitLength) {
  const byteLength = Math.ceil(bitLength / 8);
  // Take the least significant bytes (at the end of the big-endian array)
  const out = bytes.slice(bytes.length - byteLength);
  const extraBits = (byteLength * 8) - bitLength;
  if (extraBits > 0 && out.length > 0) {
    out[0] &= (0xff >> extraBits);
  }
  return out;
}
