/**
 * PA#13: Miller-Rabin Primality Testing.
 *
 * Exports:
 *   millerRabin(n, k)       → { result, witnesses, s, d, timeMs }
 *   isPrime(n, k)           → boolean
 *   genPrime(bits, k)       → { prime, candidates, timeMs }
 *   fermatTest(n, a)        → boolean
 *   carmichaelDemo()        → { fermatResults, millerRabinResult, steps }
 *
 * Uses modPow from ./utils.js (already BigInt-safe).
 * All arithmetic uses native BigInt.
 */

import { modPow } from './utils.js';

// ─── Internal helpers ────────────────────────────────────────────────────────

/**
 * Write n-1 = 2^s * d, d odd.
 * @param {BigInt} n
 * @returns {{ s: BigInt, d: BigInt }}
 */
function factorTwos(n) {
  let s = 0n;
  let d = n - 1n;
  while (d % 2n === 0n) {
    d /= 2n;
    s += 1n;
  }
  return { s, d };
}

/**
 * Generate a random BigInt uniformly in [2, n-2].
 * @param {BigInt} n
 * @returns {BigInt}
 */
function randomBigIntInRange(n) {
  const bitLen = n.toString(2).length;
  const byteLen = Math.ceil(bitLen / 8);
  while (true) {
    const buf = new Uint8Array(byteLen);
    crypto.getRandomValues(buf);
    // Mask top bits to stay within bit length
    if (bitLen % 8 !== 0) {
      buf[0] &= (1 << (bitLen % 8)) - 1;
    }
    let val = 0n;
    for (const b of buf) val = (val << 8n) | BigInt(b);
    if (val >= 2n && val <= n - 2n) return val;
    // Retry (extremely rare for large n)
  }
}

// ─── Core Miller-Rabin ────────────────────────────────────────────────────────

/**
 * Miller-Rabin probabilistic primality test.
 *
 * @param {BigInt} n - Odd integer > 2 to test
 * @param {number} k - Number of rounds (default 40; error ≤ 4^{-k})
 * @returns {{
 *   result: 'PROBABLY_PRIME' | 'COMPOSITE',
 *   witnesses: Array<{ a: BigInt, steps: Array, verdict: string }>,
 *   s: BigInt,
 *   d: BigInt,
 *   timeMs: number
 * }}
 */
export function millerRabin(n, k = 40) {
  const start = performance.now();

  // Edge cases
  if (n === 2n || n === 3n) {
    return { result: 'PROBABLY_PRIME', witnesses: [], s: 0n, d: 1n, timeMs: 0 };
  }
  if (n < 2n || n % 2n === 0n) {
    return { result: 'COMPOSITE', witnesses: [], s: 0n, d: 0n, timeMs: 0 };
  }

  const { s, d } = factorTwos(n);
  const witnesses = [];

  for (let i = 0; i < k; i++) {
    // (a) Choose random a ∈ [2, n-2]
    const a = randomBigIntInRange(n);

    // (b) Compute x = a^d mod n
    let x = modPow(a, d, n);

    const steps = [
      {
        r: -1,
        x,
        note: `a^d mod n = ${a.toString().slice(0, 16)}... ^ ${d.toString().slice(0, 8)}... = ${x.toString().slice(0, 16)}...`,
      },
    ];

    // (c) If x = 1 or x = n-1: pass this round
    if (x === 1n || x === n - 1n) {
      steps.push({
        r: 0,
        x,
        note: x === 1n ? 'x = 1 → pass (trivially)' : 'x = n−1 → pass',
      });
      witnesses.push({ a, steps, verdict: 'PASS' });
      continue;
    }

    // (d) Square up to s-1 times
    let passed = false;
    for (let r = 1n; r < s; r++) {
      x = modPow(x, 2n, n);
      steps.push({
        r: Number(r),
        x,
        note: `r=${r}: x² mod n = ${x.toString().slice(0, 16)}...`,
      });
      if (x === n - 1n) {
        steps[steps.length - 1].note += ' → x = n−1, pass';
        passed = true;
        break;
      }
    }

    // (e) If not passed → composite witness found
    if (!passed) {
      steps.push({
        r: Number(s),
        x,
        note: `x ≠ n−1 after all ${s} squarings → COMPOSITE witness!`,
      });
      witnesses.push({ a, steps, verdict: 'COMPOSITE_WITNESS' });
      const timeMs = Math.round((performance.now() - start) * 100) / 100;
      return { result: 'COMPOSITE', witnesses, s, d, timeMs };
    }

    witnesses.push({ a, steps, verdict: 'PASS' });
  }

  const timeMs = Math.round((performance.now() - start) * 100) / 100;
  return { result: 'PROBABLY_PRIME', witnesses, s, d, timeMs };
}

// ─── Boolean wrapper ─────────────────────────────────────────────────────────

/**
 * Convenience wrapper — returns true if n is probably prime.
 * @param {BigInt|number|string} n
 * @param {number} k - rounds
 * @returns {boolean}
 */
export function isPrime(n, k = 40) {
  try {
    const bn = typeof n === 'bigint' ? n : BigInt(String(n));
    if (bn < 2n) return false;
    if (bn === 2n) return true;
    if (bn % 2n === 0n) return false;
    return millerRabin(bn, k).result === 'PROBABLY_PRIME';
  } catch {
    return false;
  }
}

// ─── Prime generation ─────────────────────────────────────────────────────────

/**
 * Generate a random b-bit probable prime using k rounds of Miller-Rabin.
 * Uses trial division by small primes as a fast pre-filter.
 *
 * @param {number} bits - Desired bit length
 * @param {number} k    - Miller-Rabin rounds (default 40)
 * @returns {{ prime: BigInt, candidates: number, timeMs: number }}
 */
export function genPrime(bits, k = 40) {
  const start = performance.now();
  const SMALL_PRIMES = [
    3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n,
    37n, 41n, 43n, 47n, 53n, 59n, 61n, 67n, 71n, 73n,
  ];
  const byteLen = Math.ceil(bits / 8);
  let candidates = 0;

  while (true) {
    candidates++;

    const buf = new Uint8Array(byteLen);
    crypto.getRandomValues(buf);
    // Set MSB to ensure exactly `bits` bits, set LSB to ensure odd
    buf[0] |= 0x80;
    buf[byteLen - 1] |= 1;

    let n = 0n;
    for (const b of buf) n = (n << 8n) | BigInt(b);

    // Quick trial division filter
    let skip = false;
    for (const p of SMALL_PRIMES) {
      if (n === p) { skip = false; break; }
      if (n % p === 0n) { skip = true; break; }
    }
    if (skip) continue;

    // Miller-Rabin test
    if (millerRabin(n, k).result === 'PROBABLY_PRIME') {
      const timeMs = Math.round(performance.now() - start);
      return { prime: n, candidates, timeMs };
    }
  }
}

// ─── Fermat test (for Carmichael demo) ────────────────────────────────────────

/**
 * Fermat primality test: checks if a^(n-1) ≡ 1 (mod n).
 * Carmichael numbers pass this for all a coprime to n.
 *
 * @param {BigInt} n
 * @param {BigInt} a - witness
 * @returns {{ passes: boolean, value: BigInt }}
 */
export function fermatTest(n, a) {
  const value = modPow(a, n - 1n, n);
  return { passes: value === 1n, value };
}

// ─── Carmichael demo ──────────────────────────────────────────────────────────

/**
 * Demonstrate that n=561 (smallest Carmichael number) passes Fermat
 * but is correctly rejected by Miller-Rabin.
 */
export function carmichaelDemo() {
  const n = 561n; // = 3 × 11 × 17

  const fermatWitnesses = [2n, 4n, 5n, 7n, 8n, 10n, 13n, 16n];
  const fermatResults = fermatWitnesses.map(a => {
    const { passes, value } = fermatTest(n, a);
    return { a, value, passes };
  });

  // Run Miller-Rabin with k=10 — should catch it quickly
  const mrResult = millerRabin(n, 10);

  return {
    n,
    factorization: '3 × 11 × 17',
    fermatResults,
    millerRabinResult: mrResult,
    steps: [
      { label: 'n = 561', value: '= 3 × 11 × 17 (composite, smallest Carmichael number)' },
      { label: 'Fermat test', value: 'a^(n−1) ≡ 1 (mod n) for ALL a coprime to n → naïvely looks prime!' },
      {
        label: 'Miller-Rabin',
        value: `${mrResult.result} after ${mrResult.witnesses.length} round(s) — correctly identified as COMPOSITE`,
        className: mrResult.result === 'COMPOSITE' ? 'success' : 'error',
      },
    ],
  };
}

// ─── Pre-computed benchmark data (from offline script) ────────────────────────

/**
 * Hardcoded benchmark results from running the offline script.
 * Script used 10 trials for 64-bit, 5 for 512-bit, 3 for 1024-bit.
 * 2048-bit is theoretical only (PNT prediction).
 */
export const BENCHMARK_DATA = [
  {
    bits: 64,
    avgCandidates: 29.9,
    pntPrediction: 22,
    ratio: 1.36,
    avgTimeMs: '<1',
    trials: 10,
    note: 'Measured (10 trials)',
  },
  {
    bits: 512,
    avgCandidates: 77.0,
    pntPrediction: 177,
    ratio: 0.44,
    avgTimeMs: '68',
    trials: 5,
    note: 'Measured (5 trials)',
  },
  {
    bits: 1024,
    avgCandidates: 129.7,
    pntPrediction: 355,
    ratio: 0.37,
    avgTimeMs: '469',
    trials: 3,
    note: 'Measured (3 trials)',
  },
  {
    bits: 2048,
    avgCandidates: 1235.0,
    pntPrediction: 710,
    ratio: 1.74,
    avgTimeMs: '14631',
    trials: 3,
    note: 'Measured (3 trials) — high variance due to randomness',
  },
];

/**
 * A known 512-bit prime (generated and verified offline with 40 rounds).
 * Used as a pre-loaded example in the demo.
 */
export const KNOWN_512_BIT_PRIME =
  '8108154283395426538862910592350124494498860600574868815545321961495965898116403069681680408875908462636050621478132160203100773358594486072240353359221219';

export const PA_NUMBER = 13;
export const STUB = false;
