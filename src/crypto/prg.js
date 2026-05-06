/**
 * PA#1: Pseudorandom Generator (PRG).
 *
 * Two constructions:
 * 1. PRG from DLP-OWF: Iterative hard-core-bit construction (HILL).
 *    G(s) = b(x0) || b(x1) || ... || b(xℓ) where xi+1 = f(xi).
 *
 * 2. PRG from AES-PRF: G(s) = F_s(0) || F_s(1)  (simpler, practical).
 *
 * Also includes NIST SP 800-22 statistical tests (frequency, runs, serial).
 *
 * Interface: seed(s), nextBits(n) — consumed by PA#2 as a black box.
 */

import { dlpOWF, hardCoreBit, DLP_PARAMS } from './owf.js';
import { aesEncryptBlock } from './aes.js';
import {
  modPow, bytesToHex, hexToBytes, concatBytes, randomBytes,
  bytesToBits, bitsToBytes
} from './utils.js';

// ─── PRG from DLP-OWF (Hard-Core Bit Construction) ─────────────────────────

/**
 * Create a DLP-based PRG.
 * Uses iterative hard-core-bit extraction: x_{i+1} = g^{x_i} mod p,
 * output_i = hardCoreBit(x_i, r).
 *
 * @param {BigInt} seed - Initial seed (the secret exponent x0)
 * @param {number} outputLen - Number of output bits desired
 * @param {BigInt} [r] - Random mask for hard-core bit (generated if not provided)
 * @returns {{ output: Uint8Array, bits: string, steps: Array }}
 */
export function prgFromDLP(seed, outputLen, r = null) {
  const { p, g, q } = DLP_PARAMS;

  // Generate random mask r if not provided
  if (r === null) {
    r = BigInt(Math.floor(Math.random() * Number(q)));
  }

  const steps = [];
  const bits = [];
  let x = seed;

  steps.push({ label: 'Seed x₀', value: seed.toString(16) });
  steps.push({ label: 'Random mask r', value: r.toString(16) });

  for (let i = 0; i < outputLen; i++) {
    const bit = hardCoreBit(x, r);
    bits.push(bit);
    if (i < 8 || i === outputLen - 1) {
      steps.push({
        label: `Iteration ${i}: x=${x.toString(16).slice(0, 8)}..., b(x,r)`,
        value: `${bit}`
      });
    } else if (i === 8) {
      steps.push({ label: '...', value: `(${outputLen - 9} more iterations)` });
    }
    x = modPow(g, x % q, p);
  }

  const bitString = bits.join('');
  const output = bitsToBytes(bitString);

  steps.push({ label: 'PRG output (first 32 hex chars)', value: bytesToHex(output).slice(0, 32) });

  return { output, bits: bitString, steps };
}

// ─── PRG from AES-PRF ──────────────────────────────────────────────────────

/**
 * Create an AES-based PRG.
 * G(s) = F_s(0) || F_s(1) || F_s(2) || ...
 * Expands a 16-byte seed to arbitrary length (in 16-byte increments).
 *
 * @param {Uint8Array} seed - 16-byte seed
 * @param {number} outputLen - Number of output bytes desired
 * @returns {{ output: Uint8Array, steps: Array }}
 */
export function prgFromAES(seed, outputLen) {
  const steps = [];
  const blocks = [];
  const numBlocks = Math.ceil(outputLen / 16);

  steps.push({ label: 'Seed s', value: bytesToHex(seed) });

  for (let i = 0; i < numBlocks; i++) {
    const counter = new Uint8Array(16);
    // Set counter value (big-endian)
    counter[15] = i & 0xff;
    counter[14] = (i >> 8) & 0xff;

    const block = aesEncryptBlock(seed, counter);
    blocks.push(block);

    if (i < 4 || i === numBlocks - 1) {
      steps.push({
        label: `F_s(${i})`,
        value: bytesToHex(block)
      });
    } else if (i === 4) {
      steps.push({ label: '...', value: `(${numBlocks - 5} more blocks)` });
    }
  }

  const fullOutput = concatBytes(...blocks);
  const output = fullOutput.slice(0, outputLen);

  steps.push({ label: 'PRG output length', value: `${outputLen} bytes (${outputLen * 8} bits)` });
  steps.push({ label: 'PRG output (hex)', value: bytesToHex(output).slice(0, 64) + (output.length > 32 ? '...' : '') });

  return { output, steps };
}

// ─── PRG Interface (consumed by PA#2) ───────────────────────────────────────

/**
 * Creates a PRG object with seed() and nextBits() interface.
 * @param {'dlp' | 'aes'} type - Which PRG construction to use
 */
export function createPRG(type = 'aes') {
  let currentSeed = null;
  let offset = 0;

  return {
    type,

    /**
     * Set the seed.
     * @param {Uint8Array|BigInt} s - Seed value
     */
    seed(s) {
      currentSeed = s;
      offset = 0;
    },

    /**
     * Generate n pseudorandom output bytes.
     * The PRG output is deterministic given the seed.
     * @param {number} n - Number of bytes
     * @returns {Uint8Array}
     */
    nextBytes(n) {
      if (currentSeed === null) throw new Error('PRG not seeded');

      if (type === 'aes') {
        // Use AES-CTR style expansion from seed
        const { output } = prgFromAES(currentSeed, offset + n);
        const result = output.slice(offset, offset + n);
        offset += n;
        return result;
      } else {
        // DLP: generate bits and convert to bytes
        const { output } = prgFromDLP(currentSeed, (offset + n) * 8);
        const result = output.slice(offset, offset + n);
        offset += n;
        return result;
      }
    },

    /**
     * Generate the full PRG expansion (for GGM tree).
     * Returns left half (G_0) and right half (G_1) of the output.
     * @param {Uint8Array} s - 16-byte input
     * @returns {{ left: Uint8Array, right: Uint8Array }}
     */
    expand(s) {
      // G(s) = F_s(0) || F_s(1) — doubles the input
      const left = aesEncryptBlock(s, new Uint8Array(16));  // F_s(0)
      const right = aesEncryptBlock(s, (() => { const c = new Uint8Array(16); c[15] = 1; return c; })()); // F_s(1)
      return { left, right };
    },

    /**
     * Full generation with steps (for UI).
     */
    generate(seed, outputLen) {
      if (type === 'aes') {
        return prgFromAES(seed, outputLen);
      } else {
        return prgFromDLP(seed, outputLen * 8);
      }
    }
  };
}

// ─── OWF from PRG (backward direction PA#1b) ───────────────────────────────
/**
 * f(s) = G(s) is a OWF.
 *
 * Proof sketch (as required by the assignment):
 * If an adversary A can invert f (i.e., given G(s) recover s),
 * then A can be used to distinguish G(s) from truly random:
 *   - Given y, run A to get s'. Check if G(s') = y.
 *   - If y was PRG output, s' exists (G is deterministic). Success.
 *   - If y was truly random, no valid preimage exists w.h.p. (G expands domain).
 * This breaks the PRG security assumption. □
 */
export function owfFromPRG(seed, type = 'aes') {
  const prg = createPRG(type);
  if (type === 'aes') {
    const { output, steps } = prgFromAES(seed, 32); // expand 16 bytes to 32
    return { output, steps: [...steps, { label: 'OWF from PRG', value: 'f(s) = G(s) is one-way because inverting it breaks PRG security (see proof in code)' }] };
  } else {
    const { output, steps } = prgFromDLP(seed, 64);
    return { output, steps: [...steps, { label: 'OWF from PRG', value: 'f(s) = G(s) is one-way because inverting it breaks PRG security' }] };
  }
}

// ─── NIST SP 800-22 Statistical Tests ───────────────────────────────────────

/**
 * Frequency (monobit) test.
 * Tests whether the number of 1s and 0s are approximately equal.
 * @param {string} bits - Binary string
 * @returns {{ pass: boolean, pValue: number, ones: number, zeros: number }}
 */
export function frequencyTest(bits) {
  const n = bits.length;
  let s = 0;
  for (let i = 0; i < n; i++) {
    s += bits[i] === '1' ? 1 : -1;
  }
  const sObs = Math.abs(s) / Math.sqrt(n);
  const pValue = erfc(sObs / Math.SQRT2);
  const ones = bits.split('').filter(b => b === '1').length;
  return {
    pass: pValue >= 0.01,
    pValue: Math.round(pValue * 10000) / 10000,
    ones,
    zeros: n - ones,
    ratio: Math.round(ones / n * 10000) / 10000
  };
}

/**
 * Runs test.
 * Tests whether the oscillation between 0s and 1s is as expected.
 * @param {string} bits - Binary string
 * @returns {{ pass: boolean, pValue: number, runs: number }}
 */
export function runsTest(bits) {
  const n = bits.length;
  const ones = bits.split('').filter(b => b === '1').length;
  const pi = ones / n;

  // Pre-test: check if proportion is reasonable
  if (Math.abs(pi - 0.5) >= 2 / Math.sqrt(n)) {
    return { pass: false, pValue: 0, runs: 0, note: 'Failed frequency prerequisite' };
  }

  let runs = 1;
  for (let i = 1; i < n; i++) {
    if (bits[i] !== bits[i-1]) runs++;
  }

  const num = Math.abs(runs - 2 * n * pi * (1 - pi));
  const den = 2 * Math.sqrt(2 * n) * pi * (1 - pi);
  const pValue = erfc(num / den);

  return {
    pass: pValue >= 0.01,
    pValue: Math.round(pValue * 10000) / 10000,
    runs
  };
}

/**
 * Serial test (simplified).
 * Tests the frequency of overlapping 2-bit patterns.
 * @param {string} bits - Binary string
 * @returns {{ pass: boolean, patterns: Object }}
 */
export function serialTest(bits) {
  const n = bits.length;
  const counts = { '00': 0, '01': 0, '10': 0, '11': 0 };

  for (let i = 0; i < n - 1; i++) {
    const pair = bits[i] + bits[i+1];
    counts[pair]++;
  }

  // Chi-squared test against expected uniform distribution
  const expected = (n - 1) / 4;
  let chiSq = 0;
  for (const key of Object.keys(counts)) {
    chiSq += Math.pow(counts[key] - expected, 2) / expected;
  }

  // For 3 degrees of freedom, p-value approximation
  const pValue = 1 - chiSquaredCDF(chiSq, 3);

  return {
    pass: pValue >= 0.01,
    pValue: Math.round(pValue * 10000) / 10000,
    patterns: counts,
    expected: Math.round(expected)
  };
}

// ─── Helper math functions ──────────────────────────────────────────────────

/** Complementary error function (approximation). */
function erfc(x) {
  const t = 1 / (1 + 0.3275911 * Math.abs(x));
  const poly = t * (0.254829592 + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429))));
  const result = poly * Math.exp(-x * x);
  return x >= 0 ? result : 2 - result;
}

/** Chi-squared CDF approximation (using regularized incomplete gamma). */
function chiSquaredCDF(x, k) {
  // Simple approximation using the normal approximation for larger k
  if (k <= 0 || x < 0) return 0;
  // Use series expansion of the lower incomplete gamma function
  const a = k / 2;
  const z = x / 2;
  let sum = 0;
  let term = Math.exp(-z) * Math.pow(z, a) / gamma(a + 1);
  for (let n = 0; n < 100; n++) {
    sum += term;
    term *= z / (a + n + 1);
    if (Math.abs(term) < 1e-10) break;
  }
  return Math.min(1, Math.max(0, sum));
}

/** Gamma function approximation (Stirling's). */
function gamma(z) {
  if (z < 0.5) {
    return Math.PI / (Math.sin(Math.PI * z) * gamma(1 - z));
  }
  z -= 1;
  const g = 7;
  const c = [0.99999999999980993, 676.5203681218851, -1259.1392167224028,
    771.32342877765313, -176.61502916214059, 12.507343278686905,
    -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7];
  let x = c[0];
  for (let i = 1; i < g + 2; i++) {
    x += c[i] / (z + i);
  }
  const t = z + g + 0.5;
  return Math.sqrt(2 * Math.PI) * Math.pow(t, z + 0.5) * Math.exp(-t) * x;
}

/**
 * Run all three NIST tests on PRG output.
 * @param {string} bits - Binary string of PRG output
 * @returns {Array} - Array of test results
 */
export function runNISTTests(bits) {
  return [
    { name: 'Frequency (Monobit)', ...frequencyTest(bits) },
    { name: 'Runs', ...runsTest(bits) },
    { name: 'Serial (2-bit patterns)', ...serialTest(bits) },
  ];
}
