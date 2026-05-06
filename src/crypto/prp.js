/**
 * PA#2: Pseudorandom Permutation (PRP) via Luby-Rackoff Feistel.
 *
 * Construction: 3-round Feistel network using the PRF as round function.
 * PRF → PRP: Apply 3 rounds of Feistel to get a secure PRP.
 * PRP → PRF: Switching lemma — a PRP over a super-polynomially large domain
 *             is computationally indistinguishable from a PRF.
 */

import { prfEvaluate } from './prf.js';
import { xorBytes, bytesToHex, randomBytes, concatBytes } from './utils.js';

// ─── Luby-Rackoff 3-Round Feistel ──────────────────────────────────────────

/**
 * One round of the Feistel network.
 * @param {Uint8Array} left  - Left half (8 bytes)
 * @param {Uint8Array} right - Right half (8 bytes)
 * @param {Uint8Array} roundKey - 16-byte round key for the PRF
 * @returns {{ left: Uint8Array, right: Uint8Array }}
 */
function feistelRound(left, right, roundKey) {
  // Pad right to 16 bytes for PRF input
  const prfInput = new Uint8Array(16);
  prfInput.set(right);
  const prfOut = prfEvaluate(roundKey, prfInput);
  // XOR left with first 8 bytes of PRF output
  const newRight = xorBytes(left, prfOut.slice(0, 8));
  return { left: right, right: newRight };
}

/**
 * Encrypt a 16-byte block using 3-round Luby-Rackoff Feistel.
 * Requires 3 independent round keys (each 16 bytes).
 *
 * @param {Array<Uint8Array>} keys - 3 round keys, each 16 bytes
 * @param {Uint8Array} block - 16-byte plaintext
 * @returns {{ output: Uint8Array, steps: Array }}
 */
export function feistelEncrypt(keys, block) {
  if (keys.length < 3) throw new Error('Need 3 round keys for Luby-Rackoff');

  const steps = [];
  let left = block.slice(0, 8);
  let right = block.slice(8, 16);

  steps.push({ label: 'Input', value: bytesToHex(block) });
  steps.push({ label: 'L₀ | R₀', value: `${bytesToHex(left)} | ${bytesToHex(right)}` });

  for (let i = 0; i < 3; i++) {
    const result = feistelRound(left, right, keys[i]);
    left = result.left;
    right = result.right;
    steps.push({
      label: `Round ${i + 1}: L${i+1} | R${i+1}`,
      value: `${bytesToHex(left)} | ${bytesToHex(right)}`
    });
  }

  const output = concatBytes(left, right);
  steps.push({ label: 'PRP output', value: bytesToHex(output) });

  return { output, steps };
}

/**
 * Decrypt a 16-byte block using 3-round Luby-Rackoff Feistel (inverse).
 * @param {Array<Uint8Array>} keys - 3 round keys, each 16 bytes
 * @param {Uint8Array} block - 16-byte ciphertext
 * @returns {{ output: Uint8Array, steps: Array }}
 */
export function feistelDecrypt(keys, block) {
  const steps = [];
  let left = block.slice(0, 8);
  let right = block.slice(8, 16);

  steps.push({ label: 'Ciphertext', value: bytesToHex(block) });
  steps.push({ label: 'L₃ | R₃', value: `${bytesToHex(left)} | ${bytesToHex(right)}` });

  // Reverse the rounds
  for (let i = 2; i >= 0; i--) {
    // Inverse Feistel round: swap and apply
    const prfInput = new Uint8Array(16);
    prfInput.set(left);
    const prfOut = prfEvaluate(keys[i], prfInput);
    const newLeft = xorBytes(right, prfOut.slice(0, 8));
    right = left;
    left = newLeft;

    steps.push({
      label: `Inv Round ${i + 1}: L${i} | R${i}`,
      value: `${bytesToHex(left)} | ${bytesToHex(right)}`
    });
  }

  const output = concatBytes(left, right);
  steps.push({ label: 'Decrypted', value: bytesToHex(output) });

  return { output, steps };
}

/**
 * Create a PRP from a master key.
 * Derives 3 independent round keys from the master key using the PRF itself.
 *
 * @param {Uint8Array} masterKey - 16-byte master key
 * @returns {{ encrypt: Function, decrypt: Function }}
 */
export function createPRP(masterKey) {
  // Derive 3 round keys: k_i = PRF_{masterKey}(i)
  const keys = [0, 1, 2].map(i => {
    const input = new Uint8Array(16);
    input[15] = i;
    return prfEvaluate(masterKey, input);
  });

  return {
    encrypt(block) { return feistelEncrypt(keys, block); },
    decrypt(block) { return feistelDecrypt(keys, block); },
    keys,
  };
}

/**
 * PRP → PRF backward direction.
 * Switching lemma: A PRP over {0,1}^n with n sufficiently large is
 * computationally indistinguishable from a PRF. The advantage is at most
 * q^2 / 2^n where q is the number of queries.
 *
 * For AES (n=128), this advantage is negligible for any polynomial q.
 */
export const PRP_TO_PRF_PROOF = {
  theorem: 'PRP/PRF Switching Lemma',
  statement: 'For any distinguisher D making q queries, |Pr[D^{PRP}=1] - Pr[D^{PRF}=1]| ≤ q²/2^n',
  implication: 'A PRP over {0,1}^128 is indistinguishable from a PRF for any polynomial number of queries',
  paNumber: 'PA#2',
};
