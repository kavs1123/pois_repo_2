/**
 * PA#5: Message Authentication Codes (MACs).
 * Implements PRF-MAC and CBC-MAC, plus verify helpers.
 */

import { prfEvaluate } from './prf.js';
import { constantTimeEqual, pkcs7Pad, splitBlocks, bytesToHex } from './utils.js';
import { hmacConstruct } from './hmac.js';

/**
 * PRF-MAC for fixed-length messages (one block).
 * @param {Uint8Array} key
 * @param {Uint8Array} message
 * @param {boolean} trace
 */
export function prfMac(key, message, trace = false) {
  const padded = message.length === 16 ? message : pkcs7Pad(message, 16).slice(0, 16);
  const tag = prfEvaluate(key, padded);
  if (!trace) return tag;
  return {
    tag,
    steps: [
      { label: 'Message (1 block)', value: bytesToHex(padded) },
      { label: 'Tag = F_k(m)', value: bytesToHex(tag) },
    ]
  };
}

/**
 * CBC-MAC for variable-length messages.
 * @param {Uint8Array} key
 * @param {Uint8Array} message
 * @param {boolean} trace
 */
export function cbcMac(key, message, trace = false) {
  const blocks = splitBlocks(pkcs7Pad(message, 16), 16, false);
  let cv = new Uint8Array(16);
  const steps = [];

  for (let i = 0; i < blocks.length; i++) {
    const xored = new Uint8Array(16);
    for (let j = 0; j < 16; j++) xored[j] = cv[j] ^ blocks[i][j];
    cv = prfEvaluate(key, xored);
    if (trace) {
      steps.push({ label: `Block ${i}`, value: bytesToHex(blocks[i]) });
      steps.push({ label: `CV ${i + 1}`, value: bytesToHex(cv) });
    }
  }

  if (!trace) return cv;
  return { tag: cv, steps };
}

/**
 * HMAC wrapper for PA#10 (uses DLP-based hash).
 */
export function hmac(key, message, trace = false) {
  return hmacConstruct(key, message, trace);
}

/**
 * Verify a MAC tag in constant time.
 */
export function macVerify(key, message, tag, mode = 'cbc') {
  const expected = mode === 'prf' ? prfMac(key, message) : cbcMac(key, message);
  return constantTimeEqual(expected, tag);
}

export const PA_NUMBER = 5;
export const STUB = false;