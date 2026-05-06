/**
 * PA#9: Birthday Attack (collision finding).
 */

import { bytesToHex, randomBytes, truncateBits } from './utils.js';

function hashToKey(bytes) {
  return bytesToHex(bytes);
}

/**
 * Naive birthday attack using a hash table.
 * @param {Function} hashFn - (inputBytes) => Uint8Array
 * @param {number} outputBits
 * @param {number} maxIterations
 */
export function birthdayAttack(hashFn, outputBits = 16, maxIterations = 100000) {
  const seen = new Map();
  // Use a fixed large input size so we don't accidentally sample the same input
  const inputLen = 16; 
  let evaluations = 0;

  while (evaluations < maxIterations) {
    const input = randomBytes(inputLen);
    const digest = truncateBits(hashFn(input), outputBits);
    const key = hashToKey(digest);

    if (seen.has(key)) {
      const other = seen.get(key);
      // Ensure the collision is a TRUE hash collision and not just sampling the same input
      if (bytesToHex(other) !== bytesToHex(input)) {
        return {
          found: true,
          evaluations,
          input1: other,
          input2: input,
          digest,
          steps: [
            { label: 'Collision found', value: key },
            { label: 'Evaluations', value: `${evaluations}` },
          ]
        };
      }
      // If we randomly picked the same input, ignore it
    } else {
      seen.set(key, input);
    }
    
    evaluations += 1;
  }

  return {
    found: false,
    evaluations,
    steps: [{ label: 'Status', value: 'No collision found (limit reached)' }]
  };
}

/**
 * Floyd's cycle-finding birthday attack (space-efficient).
 * @param {Function} hashFn - (inputBytes) => Uint8Array
 * @param {number} outputBits
 */
export function birthdayAttackFloyd(hashFn, outputBits = 16) {
  const inputLen = Math.max(1, Math.ceil(outputBits / 8));
  const next = (x) => truncateBits(hashFn(x), outputBits);

  let tortoise = randomBytes(inputLen);
  let hare = randomBytes(inputLen);
  let steps = 0;

  do {
    tortoise = next(tortoise);
    hare = next(next(hare));
    steps += 1;
  } while (bytesToHex(tortoise) !== bytesToHex(hare) && steps < 200000);

  // Find start of cycle
  let mu = 0;
  tortoise = randomBytes(inputLen);
  while (bytesToHex(tortoise) !== bytesToHex(hare) && mu < 200000) {
    tortoise = next(tortoise);
    hare = next(hare);
    mu += 1;
  }

  // Find cycle length
  let lam = 1;
  hare = next(tortoise);
  while (bytesToHex(tortoise) !== bytesToHex(hare) && lam < 200000) {
    hare = next(hare);
    lam += 1;
  }

  return {
    mu,
    lam,
    steps,
    stepsInfo: [
      { label: 'Cycle start (mu)', value: `${mu}` },
      { label: 'Cycle length (lambda)', value: `${lam}` },
      { label: 'Iterations', value: `${steps}` },
    ]
  };
}

export const PA_NUMBER = 9;
export const STUB = false;