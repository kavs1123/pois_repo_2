/**
 * PA#13-style primality: Miller–Rabin + random prime generation for RSA (PA#12 / PA#15).
 */

import { randomBytes, bytesToBigInt, modPow } from './utils.js';

/** Miller–Rabin: return true iff n is a strong probable prime (k rounds). */
export function millerRabin(n, rounds = 40) {
  if (n < 2n) return false;
  if (n === 2n || n === 3n) return true;
  if ((n & 1n) === 0n) return false;

  let r = 0n;
  let d = n - 1n;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    r += 1n;
  }

  witness: for (let i = 0; i < rounds; i++) {
    const range = n - 3n;
    const a = (bytesToBigInt(randomBytes(32)) % range) + 2n;
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue witness;
    for (let j = 0n; j < r - 1n; j++) {
      x = (x * x) % n;
      if (x === n - 1n) continue witness;
    }
    return false;
  }
  return true;
}

/** Uniform odd integer in [2^(bits-1), 2^bits). */
export function randomOddBits(bits) {
  const byteLen = Math.ceil(bits / 8);
  const buf = randomBytes(byteLen);
  let n = bytesToBigInt(buf);
  const hi = BigInt(bits - 1);
  n |= 1n << hi;
  const mask = (1n << BigInt(bits)) - 1n;
  n &= mask;
  n |= 1n;
  return n;
}

/**
 * Sample a probable prime of exactly `bits` bits.
 * @param {number} bits
 * @param {number} [rounds] Miller–Rabin rounds (default 40)
 */
export function genPrime(bits, rounds = 40) {
  const maxTries = bits < 64 ? 50000 : 5000;
  for (let t = 0; t < maxTries; t++) {
    const candidate = randomOddBits(bits);
    if (millerRabin(candidate, rounds)) return candidate;
  }
  throw new Error(`genPrime(${bits}) failed after ${maxTries} attempts`);
}
