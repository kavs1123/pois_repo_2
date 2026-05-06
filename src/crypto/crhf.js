/**
 * PA#8: DLP-based Collision-Resistant Hash Function (CRHF).
 */

import { DLP_PARAMS } from './owf.js';
import { merkleDamgard } from './merkle_damgard.js';
import { bytesToBigInt, bigIntToBytes, modPow, truncateBits } from './utils.js';

const { p, q, g } = DLP_PARAMS;
const MOD_LEN = Math.ceil(p.toString(2).length / 8);

// Choose h = g^alpha mod p, alpha unknown (module-scoped).
const ALPHA = BigInt(Math.floor(Math.random() * Number(q)));
const H = modPow(g, ALPHA, p);

export const DLP_HASH_PARAMS = {
  p,
  q,
  g,
  h: H,
  blockSize: 4,
  outputSize: MOD_LEN,
};

/**
 * DLP compression function: h(x,y) = g^x * h^y mod p.
 * Inputs are byte arrays; outputs a fixed-length byte array.
 */
export function dlpCompression(cvBytes, blockBytes) {
  const x = bytesToBigInt(cvBytes) % q;
  const y = bytesToBigInt(blockBytes) % q;
  const gx = modPow(g, x, p);
  const hy = modPow(H, y, p);
  const out = (gx * hy) % p;
  return bigIntToBytes(out, MOD_LEN);
}

/**
 * Full DLP-based hash via Merkle-Damgard.
 * @param {Uint8Array} message
 * @param {{ outputBits?: number, trace?: boolean }} options
 */
export function dlpHash(message, options = {}) {
  const trace = Boolean(options.trace);
  const result = merkleDamgard(dlpCompression, message, {
    blockSize: DLP_HASH_PARAMS.blockSize,
    iv: new Uint8Array(DLP_HASH_PARAMS.outputSize),
    trace,
  });

  const digest = options.outputBits
    ? truncateBits(result.digest, options.outputBits)
    : result.digest;

  return { digest, steps: result.steps };
}

export const PA_NUMBER = 8;
export const STUB = false;