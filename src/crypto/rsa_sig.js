/**
 * PA#15: RSA digital signatures — hash-then-sign with PA#8 DLP hash,
 * raw RSA variant, multiplicative forgery helper, EUF-CMA challenger.
 */

import { dlpHash } from './crhf.js';
import { genPrime } from './prime.js';
import {
  bytesToBigInt,
  bigIntToBytes,
  modPow,
  modInverse,
  gcd,
  bytesToHex,
} from './utils.js';

export const RSA_DEFAULT_E = 65537n;

/**
 * @typedef {{ N: bigint, e: bigint }} RsaVk
 * @typedef {{ N: bigint, d: bigint, e: bigint, p?: bigint, q?: bigint }} RsaSk
 */

/**
 * RSA key generation (PA#12-style textbook modulus).
 * @param {number} [bits] — modulus bit length (default 512)
 * @param {number} [mrRounds] — Miller–Rabin rounds per prime (default 24)
 */
export function rsaKeyGen(bits = 512, mrRounds = 24) {
  const half = Math.floor(bits / 2);
  for (let attempt = 0; attempt < 2000; attempt++) {
    const p = genPrime(half, mrRounds);
    const q = genPrime(half, mrRounds);
    if (p === q) continue;
    const N = p * q;
    const phi = (p - 1n) * (q - 1n);
    if (gcd(RSA_DEFAULT_E, phi) !== 1n) continue;
    const d = modInverse(RSA_DEFAULT_E, phi);
    const vk = { N, e: RSA_DEFAULT_E };
    const sk = { N, d, e: RSA_DEFAULT_E, p, q };
    return { vk, sk, N, e: RSA_DEFAULT_E, d, p, q };
  }
  throw new Error('rsaKeyGen: could not find suitable primes');
}

/** Map PA#8 hash digest to Z_N^* proxy (non-zero mod N). */
export function hashMessageRepresentative(messageBytes, N) {
  const { digest } = dlpHash(messageBytes);
  let h = bytesToBigInt(digest) % N;
  if (h === 0n) h = 1n;
  return { h, digest };
}

/** Raw textbook RSA: message bytes as big-endian integer mod N. */
export function rawMessageRepresentative(messageBytes, N) {
  let m = bytesToBigInt(messageBytes) % N;
  if (m === 0n) m = 1n;
  return m;
}

/**
 * σ = rep(m)^d mod N with rep = H(m) or raw m.
 * @param {RsaSk} sk
 * @param {Uint8Array} messageBytes
 * @param {{ useHash?: boolean }} [options] — default true (hash-then-sign)
 */
export function Sign(sk, messageBytes, options = {}) {
  const useHash = options.useHash !== false;
  const N = sk.N;
  const representative = useHash
    ? hashMessageRepresentative(messageBytes, N).h
    : rawMessageRepresentative(messageBytes, N);
  const sigma = modPow(representative, sk.d, N);
  return { sigma, representative, useHash };
}

export function verifyWithTrace(vk, messageBytes, sigma, options = {}) {
  const useHash = options.useHash !== false;
  const { N, e } = vk;
  let representative;
  let digestHex = null;
  if (useHash) {
    const { h, digest } = hashMessageRepresentative(messageBytes, N);
    representative = h;
    digestHex = bytesToHex(digest);
  } else {
    representative = rawMessageRepresentative(messageBytes, N);
  }
  const sigmaPowE = modPow(sigma, e, N);
  const valid = sigmaPowE === representative;
  return {
    valid,
    representative,
    sigmaPowE,
    digestHex,
    useHash,
    N,
    e,
  };
}

/**
 * @param {RsaVk} vk
 * @param {Uint8Array} messageBytes
 * @param {bigint} sigma
 * @param {{ useHash?: boolean }} [options]
 */
export function Verify(vk, messageBytes, sigma, options = {}) {
  return verifyWithTrace(vk, messageBytes, sigma, options).valid;
}

/** σ* = σ₁·σ₂ mod N verifies for m* ≡ m₁·m₂ (mod N) under raw RSA. */
export function rawRsaMultiplicativeForge(sigma1, sigma2, N) {
  return (sigma1 * sigma2) % N;
}

export function rawProductRepresentative(m1Bytes, m2Bytes, N) {
  const m1 = rawMessageRepresentative(m1Bytes, N);
  const m2 = rawMessageRepresentative(m2Bytes, N);
  return (m1 * m2) % N;
}

export function sigmaByteLength(N) {
  return Math.ceil(N.toString(16).length / 2);
}

export function sigmaToHex(sigma, N) {
  return bytesToHex(bigIntToBytes(sigma, sigmaByteLength(N)));
}

export function sigmaFromHex(hex, N) {
  const cleaned = hex.replace(/\s/g, '');
  if (!cleaned.length) return 0n;
  const sigma = BigInt(`0x${cleaned}`);
  return sigma % N;
}

/**
 * EUF-CMA-style challenger with a bounded signing oracle.
 * @param {RsaSk} sk
 * @param {RsaVk} vk
 * @param {{ maxQueries?: number, useHash?: boolean }} [options]
 */
export function createEufCmaChallenger(sk, vk, options = {}) {
  const maxQueries = options.maxQueries ?? 50;
  const useHash = options.useHash !== false;
  const queried = new Set();

  function signingOracle(messageBytes) {
    if (queried.size >= maxQueries) {
      throw new Error(`Signing oracle limited to ${maxQueries} queries`);
    }
    const key = bytesToHex(messageBytes);
    const { sigma } = Sign(sk, messageBytes, { useHash });
    queried.add(key);
    return sigma;
  }

  function checkForgery(messageBytes, sigma) {
    const key = bytesToHex(messageBytes);
    if (queried.has(key)) {
      return {
        wins: false,
        validSig: false,
        reason: 'This message was already signed by the oracle — not a successful EUF-CMA forgery.',
      };
    }
    const validSig = Verify(vk, messageBytes, sigma, { useHash });
    return {
      wins: validSig,
      validSig,
      reason: validSig
        ? 'Valid signature on a fresh message (breaking EUF-CMA for this toy experiment).'
        : 'Verification failed — forger did not break EUF-CMA.',
    };
  }

  return {
    signingOracle,
    checkForgery,
    queryCount: () => queried.size,
    maxQueries,
    hasQuery: (messageBytes) => queried.has(bytesToHex(messageBytes)),
  };
}

export const PA_NUMBER = 15;
export const STUB = false;
