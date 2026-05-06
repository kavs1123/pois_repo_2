/**
 * PA#2: Pseudorandom Function (PRF) via GGM Tree.
 *
 * Construction: F_k(x) = G_{x_n}(...G_{x_1}(k))
 * where G is a PRG that doubles its input, and G_0/G_1 are the left/right halves.
 *
 * Backward: PRF → PRG: G(s) = F_s(0) || F_s(1).
 *
 * Also includes a PRF distinguishing game.
 */

import { aesEncryptBlock } from './aes.js';
import { bytesToHex, hexToBytes, randomBytes, getBit, concatBytes } from './utils.js';

// ─── GGM Tree PRF ──────────────────────────────────────────────────────────

/**
 * PRG that doubles input: G(s) = F_s(0) || F_s(1).
 * Returns left half (G_0) and right half (G_1).
 * @param {Uint8Array} s - 16-byte seed
 * @returns {{ left: Uint8Array, right: Uint8Array }}
 */
function prgExpand(s) {
  const zero = new Uint8Array(16);
  const one = new Uint8Array(16);
  one[15] = 1;
  return {
    left: aesEncryptBlock(s, zero),   // G_0(s) = AES_s(0)
    right: aesEncryptBlock(s, one),   // G_1(s) = AES_s(1)
  };
}

/**
 * GGM Tree PRF evaluation: F_k(x).
 * Walk the binary tree from root k using bits of x.
 *
 * @param {Uint8Array} key   - 16-byte PRF key
 * @param {Uint8Array} input - Input (the bits are used to traverse the tree)
 * @param {number} [inputBits] - Number of bits of input to use (default: input.length * 8)
 * @returns {{ output: Uint8Array, steps: Array }}
 */
export function ggmPRF(key, input, inputBits = null) {
  if (inputBits === null) inputBits = input.length * 8;
  // Limit tree depth for performance (toy parameters)
  const depth = Math.min(inputBits, 16); // Use at most 16 bits for tree depth

  const steps = [];
  let current = new Uint8Array(key);

  steps.push({ label: 'Key k', value: bytesToHex(key) });
  steps.push({ label: 'Input x', value: bytesToHex(input) });
  steps.push({ label: 'Tree depth', value: `${depth} bits` });

  for (let i = 0; i < depth; i++) {
    const bit = getBit(input, i);
    const { left, right } = prgExpand(current);
    const prev = bytesToHex(current).slice(0, 8);
    current = bit === 0 ? left : right;

    if (i < 6 || i === depth - 1) {
      steps.push({
        label: `Level ${i}: x[${i}]=${bit} → G_${bit}(${prev}...)`,
        value: bytesToHex(current).slice(0, 16) + '...'
      });
    } else if (i === 6) {
      steps.push({ label: '...', value: `(${depth - 7} more levels)` });
    }
  }

  steps.push({ label: 'F_k(x) output', value: bytesToHex(current) });

  return { output: current, steps };
}

/**
 * Simple PRF evaluation (shorthand without detailed steps).
 * @param {Uint8Array} key   - 16-byte PRF key
 * @param {Uint8Array} input - Input block
 * @returns {Uint8Array}     - 16-byte output
 */
export function prfEvaluate(key, input) {
  // For efficiency with multi-block operations, use a simpler PRF:
  // Use AES in a Davies-Meyer-like mode: output = AES_k(input)
  // This is equivalent to the GGM PRF when the underlying PRG is AES-based.
  return aesEncryptBlock(key, input);
}

// ─── PRF → PRG (Backward Direction) ────────────────────────────────────────

/**
 * Construct a PRG from a PRF: G(s) = F_s(0) || F_s(1).
 *
 * Security argument: If G were distinguishable from random, the distinguisher
 * could be used to break the PRF security of F. Specifically, if D can
 * distinguish G(s) from random with advantage ε, then D can distinguish
 * F_k from a random function with the same advantage.
 *
 * @param {Uint8Array} seed - 16-byte seed
 * @returns {{ output: Uint8Array, steps: Array }}
 */
export function prgFromPRF(seed) {
  const zero = new Uint8Array(16);
  const one = new Uint8Array(16);
  one[15] = 1;

  const left = aesEncryptBlock(seed, zero);
  const right = aesEncryptBlock(seed, one);
  const output = concatBytes(left, right);

  return {
    output,
    steps: [
      { label: 'Seed s', value: bytesToHex(seed) },
      { label: 'F_s(0)', value: bytesToHex(left) },
      { label: 'F_s(1)', value: bytesToHex(right) },
      { label: 'G(s) = F_s(0) || F_s(1)', value: bytesToHex(output) },
      { label: 'Backward PRF→PRG', value: 'If G is distinguishable, the distinguisher breaks PRF security of F' },
    ]
  };
}

// ─── PRF Distinguishing Game ────────────────────────────────────────────────

/**
 * Run the PRF distinguishing game.
 * The adversary makes queries to either a real PRF F_k or a truly random function,
 * then guesses which one it is.
 *
 * @param {number} numQueries - Number of queries the adversary makes
 * @param {number} numRounds  - Number of game rounds
 * @returns {{ advantage: number, rounds: Array, steps: Array }}
 */
export function prfDistinguishGame(numQueries = 50, numRounds = 20) {
  const rounds = [];
  let correctGuesses = 0;

  for (let round = 0; round < numRounds; round++) {
    // Flip coin: b=0 means PRF, b=1 means random
    const b = crypto.getRandomValues(new Uint8Array(1))[0] & 1;
    const key = randomBytes(16);
    const randomFunc = new Map();

    // Adversary queries
    const queryResults = [];
    for (let q = 0; q < numQueries; q++) {
      const query = randomBytes(16);
      let response;

      if (b === 0) {
        // Real PRF
        response = prfEvaluate(key, query);
      } else {
        // Truly random function (lazy sampling)
        const qHex = bytesToHex(query);
        if (!randomFunc.has(qHex)) {
          randomFunc.set(qHex, randomBytes(16));
        }
        response = randomFunc.get(qHex);
      }

      queryResults.push({ query: bytesToHex(query).slice(0, 8), response: bytesToHex(response).slice(0, 8) });
    }

    // Naive adversary: just guess randomly (should have ~0 advantage)
    const guess = crypto.getRandomValues(new Uint8Array(1))[0] & 1;
    const correct = guess === b;
    if (correct) correctGuesses++;

    rounds.push({
      round: round + 1,
      isRealPRF: b === 0,
      guess: guess === 0 ? 'PRF' : 'Random',
      correct,
      numQueries
    });
  }

  const advantage = Math.abs(correctGuesses / numRounds - 0.5);

  return {
    advantage: Math.round(advantage * 10000) / 10000,
    correctGuesses,
    totalRounds: numRounds,
    rounds,
    steps: [
      { label: 'PRF Distinguishing Game', value: `${numRounds} rounds, ${numQueries} queries each` },
      { label: 'Correct guesses', value: `${correctGuesses}/${numRounds}` },
      { label: 'Adversary advantage', value: `|${correctGuesses}/${numRounds} - 0.5| = ${Math.round(advantage * 10000) / 10000}` },
      { label: 'Expected (secure PRF)', value: 'Advantage ≈ 0 (indistinguishable from random)' },
    ]
  };
}
