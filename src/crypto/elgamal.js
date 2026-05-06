/**
 * PA#16: ElGamal encryption over a cyclic subgroup of ℤₚ*.
 * Uses the same modulus / order as PA#11 DLP, with generator g' = g² mod p (order q).
 */

import { DLP_PARAMS } from './owf.js';
import { modPow, modInverse, bytesToBigInt, randomBytes } from './utils.js';

/** Subgroup generator of order q (safe-prime setup: (g')^q ≡ 1). */
export const ELGAMAL_DEFAULT_PARAMS = {
  p: DLP_PARAMS.p,
  q: DLP_PARAMS.q,
  g: (DLP_PARAMS.g * DLP_PARAMS.g) % DLP_PARAMS.p,
};

/** Smaller safe prime (q ≈ 2¹⁰) for CPA brute-force distinguisher demo. */
export const ELGAMAL_TINY_PARAMS = {
  p: 2039n,
  q: 1019n,
  g: 2n,
};

function uniformBelow(maxExclusive) {
  const bitLen = Number(maxExclusive.toString(2).length);
  const bytes = Math.ceil(bitLen / 8) + 4;
  for (;;) {
    const x = bytesToBigInt(randomBytes(bytes)) % maxExclusive;
    if (x >= 0n) return x;
  }
}

/** x ← ℤ_q \ {0} (full range practical for encryption nonces). */
export function sampleExponentNonZero(q) {
  let x = uniformBelow(q);
  if (x === 0n) x = 1n;
  return x;
}

/**
 * Key generation: x ← ℤ_q, h = g^x mod p.
 * @param {{ p: bigint, q: bigint, g: bigint }} [params]
 * @returns {{ sk: bigint, pk: { p, g, q, h } }}
 */
export function elgamalKeygen(params = ELGAMAL_DEFAULT_PARAMS) {
  const { p, q, g } = params;
  const x = uniformBelow(q);
  const xSecret = x === 0n ? 1n : x;
  const h = modPow(g, xSecret, p);
  return {
    sk: xSecret,
    pk: { p, g, q, h },
  };
}

function assertPlaintext(pk, m) {
  const { p } = pk;
  const mb = typeof m === 'bigint' ? m : BigInt(m);
  if (mb <= 0n || mb >= p) {
    throw new Error(`Plaintext must lie in ℤₚ* (1 … p-1); got ${mb}`);
  }
  return mb;
}

/**
 * ElGamal encryption: r ← ℤ_q, c₁ = g^r, c₂ = m · h^r mod p.
 * @returns {{ c1: bigint, c2: bigint }}
 */
export function Enc(pk, m) {
  const { p, g, q, h } = pk;
  const mb = assertPlaintext(pk, m);
  const r = sampleExponentNonZero(q);
  const c1 = modPow(g, r, p);
  const hr = modPow(h, r, p);
  const c2 = (mb * hr) % p;
  return { c1, c2 };
}

/**
 * Decryption: m = c₂ · (c₁^x)⁻¹ mod p.
 */
/** @param {bigint} sk — secret exponent x */
export function Dec(sk, c1, c2, p) {
  const s = modPow(c1, sk, p);
  const inv = modInverse(s, p);
  return (c2 * inv) % p;
}

/** Convenience for PA#17 when both pk and sk are available. */
export function DecWithPk(sk, pk, c1, c2) {
  return Dec(sk, c1, c2, pk.p);
}

/** Malleability: (c₁, k·c₂) decrypts to k·m mod p. */
export function malleateMultiplyC2(c1, c2, k, p) {
  const kb = typeof k === 'bigint' ? k : BigInt(k);
  return { c1, c2: ((kb % p + p) % p * c2) % p };
}

/** Enumerate r ∈ ℤ_q to solve for plaintext (feasible only for tiny q). */
export function recoverPlaintextBruteForce(pk, c1, c2) {
  const { p, g, q, h } = pk;
  for (let r = 0n; r < q; r += 1n) {
    if (modPow(g, r, p) !== c1) continue;
    const hr = modPow(h, r, p);
    return (c2 * modInverse(hr, p)) % p;
  }
  return null;
}

/**
 * IND-CPA guess: recover m via brute force, see if it equals m₀ or m₁.
 * @returns {0|1|null} bit guess or null if inconclusive
 */
export function indCpaGuessBitTiny(pk, m0, m1, c1, c2) {
  const m = recoverPlaintextBruteForce(pk, c1, c2);
  if (m === null) return null;
  if (m === m0) return 0;
  if (m === m1) return 1;
  return null;
}

/**
 * Run one IND-CPA round: challenger picks b, returns ciphertext of m_b.
 */
export function indCpaChallenge(pk, m0, m1, b) {
  const mb = b === 0 ? m0 : m1;
  return Enc(pk, mb);
}

export const PA_NUMBER = 16;
export const STUB = false;
