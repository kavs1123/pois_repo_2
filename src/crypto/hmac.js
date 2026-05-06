/**
 * PA#10: HMAC + Encrypt-then-HMAC.
 */

import { dlpHash, DLP_HASH_PARAMS } from './crhf.js';
import { constantTimeEqual, concatBytes, xorBytes, bytesToHex, pkcs7Pad } from './utils.js';
import { cpaEncrypt, cpaDecrypt } from './cpa_enc.js';

const BLOCK_SIZE = DLP_HASH_PARAMS.blockSize;
const IPAD = new Uint8Array(BLOCK_SIZE).fill(0x36);
const OPAD = new Uint8Array(BLOCK_SIZE).fill(0x5c);

function normalizeKey(key) {
  if (key.length > BLOCK_SIZE) {
    return dlpHash(key).digest.slice(0, BLOCK_SIZE);
  }
  if (key.length === BLOCK_SIZE) return key;
  const out = new Uint8Array(BLOCK_SIZE);
  out.set(key);
  return out;
}

/**
 * HMAC over the DLP-based hash.
 * @param {Uint8Array} key
 * @param {Uint8Array} message
 * @param {boolean} trace
 */
export function hmacConstruct(key, message, trace = false) {
  const k0 = normalizeKey(key);
  const innerKey = xorBytes(k0, IPAD);
  const outerKey = xorBytes(k0, OPAD);

  const inner = dlpHash(concatBytes(innerKey, message)).digest;
  const tag = dlpHash(concatBytes(outerKey, inner)).digest;

  if (!trace) return tag;
  return {
    tag,
    steps: [
      { label: 'Key (normalized)', value: bytesToHex(k0) },
      { label: 'Inner key', value: bytesToHex(innerKey) },
      { label: 'Outer key', value: bytesToHex(outerKey) },
      { label: 'Inner hash', value: bytesToHex(inner) },
      { label: 'HMAC tag', value: bytesToHex(tag) },
    ]
  };
}

/**
 * Constant-time HMAC verification.
 */
export function hmacVerify(key, message, tag) {
  const expected = hmacConstruct(key, message);
  return constantTimeEqual(expected, tag);
}

/**
 * Encrypt-then-HMAC using CPA-secure encryption.
 */
export function encryptThenHMAC(kE, kM, message) {
  const enc = cpaEncrypt(kE, message);
  const tag = hmacConstruct(kM, concatBytes(enc.nonce, enc.ciphertext));
  return { nonce: enc.nonce, ciphertext: enc.ciphertext, tag, steps: enc.steps };
}

/**
 * Decrypt-then-verify for Encrypt-then-HMAC.
 */
export function decryptThenHMAC(kE, kM, nonce, ciphertext, tag) {
  const valid = hmacVerify(kM, concatBytes(nonce, ciphertext), tag);
  if (!valid) return { valid: false, plaintext: new Uint8Array(0) };
  const dec = cpaDecrypt(kE, nonce, ciphertext);
  return { valid: true, plaintext: dec.plaintext, steps: dec.steps };
}

export const PA_NUMBER = 10;
export const STUB = false;