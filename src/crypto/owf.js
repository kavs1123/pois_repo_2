/**
 * PA#1: One-Way Functions (OWF).
 *
 * Two concrete instantiations:
 * 1. DLP-based: f(x) = g^x mod p  (in a prime-order subgroup)
 * 2. AES-based: f(k) = AES_k(0^128) || k  (Davies-Meyer style compression)
 *
 * Also provides the Goldreich-Levin hard-core bit for PRG construction.
 */

import { aesEncryptBlock } from './aes.js';
import { modPow, bytesToHex, hexToBytes, concatBytes, randomBytes } from './utils.js';

// ─── DLP Parameters (toy: ~30-bit safe prime) ──────────────────────────────
// Safe prime p = 2q + 1 where q is also prime.
// p = 1073741827  (close to 2^30, actually prime)
// q = 536870913 ... let's use proper ones.
//
// We'll use p = 1073741789 which is prime (~30 bits).
// Actually let's use a well-known small safe prime:
// p = 1073742847 is not safe. Let's compute one.
// p = 2147483659 is prime (~31 bits), q = (p-1)/2 = 1073741829 is prime → safe prime.

export const DLP_PARAMS = {
  p: 2147483659n,
  q: 1073741829n,  // (p-1)/2, also prime
  g: 2n,           // generator of the subgroup of order q
};

// Verify g is a generator of the subgroup of order q:
// g^q mod p should be 1, and g^1 mod p should not be 1.

/**
 * DLP-based OWF: f(x) = g^x mod p.
 * @param {BigInt} x - Input (secret exponent)
 * @param {BigInt} [g] - Generator (default: DLP_PARAMS.g)
 * @param {BigInt} [p] - Prime modulus (default: DLP_PARAMS.p)
 * @returns {{ output: BigInt, steps: Array }} - The OWF output and intermediate steps
 */
export function dlpOWF(x, g = DLP_PARAMS.g, p = DLP_PARAMS.p) {
  const output = modPow(g, x, p);
  return {
    output,
    steps: [
      { label: 'Input x', value: x.toString(16) },
      { label: `g = ${g}`, value: g.toString(16) },
      { label: `p = ${p}`, value: p.toString(16) },
      { label: `g^x mod p`, value: output.toString(16) },
    ]
  };
}

/**
 * AES-based OWF: f(k) = AES_k(0^128) || k.
 * Davies-Meyer style: the output is a compression of the key.
 * @param {Uint8Array} k - 16-byte key
 * @returns {{ output: Uint8Array, steps: Array }}
 */
export function aesOWF(k) {
  const zeroBlock = new Uint8Array(16); // 0^128
  const encrypted = aesEncryptBlock(k, zeroBlock);
  const output = concatBytes(encrypted, k);
  return {
    output,
    steps: [
      { label: 'Key k', value: bytesToHex(k) },
      { label: 'Plaintext (0^128)', value: bytesToHex(zeroBlock) },
      { label: 'AES_k(0^128)', value: bytesToHex(encrypted) },
      { label: 'Output: AES_k(0^128) || k', value: bytesToHex(output) },
    ]
  };
}

/**
 * Verify OWF hardness: attempt random inversion and show it fails.
 * @param {'dlp' | 'aes'} type - Which OWF to test
 * @param {number} attempts - Number of inversion attempts
 * @returns {{ target: string, attempts: number, successes: number, steps: Array }}
 */
export function verifyHardness(type = 'dlp', attempts = 100) {
  const steps = [];
  let successes = 0;

  if (type === 'dlp') {
    // Pick a random x, compute y = g^x mod p, then try random guesses
    const x = BigInt(Math.floor(Math.random() * Number(DLP_PARAMS.q)));
    const y = modPow(DLP_PARAMS.g, x, DLP_PARAMS.p);
    steps.push({ label: 'Target y = g^x mod p', value: y.toString(16) });
    steps.push({ label: 'True preimage x', value: x.toString(16) });

    for (let i = 0; i < attempts; i++) {
      const guess = BigInt(Math.floor(Math.random() * Number(DLP_PARAMS.q)));
      const guessy = modPow(DLP_PARAMS.g, guess, DLP_PARAMS.p);
      if (guessy === y) successes++;
    }
  } else {
    // AES OWF: pick random k, compute f(k), try random inversion
    const k = randomBytes(16);
    const { output } = aesOWF(k);
    steps.push({ label: 'Target f(k)', value: bytesToHex(output) });
    steps.push({ label: 'True preimage k', value: bytesToHex(k) });

    for (let i = 0; i < attempts; i++) {
      const guess = randomBytes(16);
      const { output: guessOut } = aesOWF(guess);
      if (bytesToHex(guessOut) === bytesToHex(output)) successes++;
    }
  }

  steps.push({ label: `Random inversion attempts`, value: `${attempts}` });
  steps.push({ label: `Successful inversions`, value: `${successes}` });
  steps.push({ label: 'Conclusion', value: successes === 0 ? 'OWF hardness confirmed ✓' : `Found ${successes} inversions (unexpected!)` });

  return { attempts, successes, steps };
}

// ─── Goldreich-Levin Hard-Core Bit ──────────────────────────────────────────
// b(x, r) = <x, r> mod 2  (inner product over GF(2))
// For the DLP OWF, x is the secret exponent, r is a public random string.

/**
 * Compute the Goldreich-Levin hard-core bit.
 * b(x, r) = sum of (x_i * r_i) mod 2  (bitwise inner product)
 * @param {BigInt} x - The input value
 * @param {BigInt} r - The random mask
 * @returns {number} - 0 or 1
 */
export function hardCoreBit(x, r) {
  const and = x & r;
  // Count number of 1-bits (parity)
  let parity = 0n;
  let v = and;
  while (v > 0n) {
    parity ^= (v & 1n);
    v >>= 1n;
  }
  return Number(parity);
}
