/**
 * PA#4: Modes of Operation — CBC, OFB, CTR.
 *
 * All modes use our own PRF/PRP from PA#2 (via AES) as the block cipher.
 * Block size: 16 bytes (128 bits).
 *
 * Includes:
 * - CBC mode (encrypt/decrypt)
 * - OFB mode (encrypt/decrypt — identical operations)
 * - Randomized CTR mode (encrypt/decrypt)
 * - Unified API: Encrypt(mode, k, M) / Decrypt(mode, k, C)
 * - Attack demos: CBC IV-reuse, OFB keystream-reuse
 * - Correctness tests
 */

import { prfEvaluate } from './prf.js';
import { aesEncryptBlock, aesDecryptBlock } from './aes.js';
import {
  xorBytes, bytesToHex, randomBytes, concatBytes,
  splitBlocks, pkcs7Pad, pkcs7Unpad, addToCounter
} from './utils.js';

// ─── CBC Mode ───────────────────────────────────────────────────────────────

/**
 * CBC Encrypt: C_i = E_k(C_{i-1} ⊕ M_i), C_0 = IV.
 * @param {Uint8Array} key - 16-byte key
 * @param {Uint8Array} iv  - 16-byte IV (random, unique per encryption)
 * @param {Uint8Array} message - Plaintext (arbitrary length, will be PKCS#7 padded)
 * @returns {{ iv: Uint8Array, ciphertext: Uint8Array, steps: Array, blocks: Array }}
 */
export function cbcEncrypt(key, iv, message) {
  const steps = [];
  const padded = pkcs7Pad(message, 16);
  const blocks = splitBlocks(padded, 16, false);
  const ctBlocks = [];

  steps.push({ label: 'Mode', value: 'CBC (Cipher Block Chaining)' });
  steps.push({ label: 'Key', value: bytesToHex(key) });
  steps.push({ label: 'IV', value: bytesToHex(iv) });
  steps.push({ label: 'Plaintext (padded)', value: bytesToHex(padded) });

  let prev = iv;
  for (let i = 0; i < blocks.length; i++) {
    const xored = xorBytes(prev, blocks[i]);
    const ct = aesEncryptBlock(key, xored);
    ctBlocks.push(ct);

    steps.push({
      label: `Block ${i}: E_k(C${i > 0 ? i-1 : 'IV'} ⊕ M${i})`,
      value: `E_k(${bytesToHex(xored).slice(0,8)}...) = ${bytesToHex(ct).slice(0,8)}...`
    });

    prev = ct;
  }

  const ciphertext = concatBytes(...ctBlocks);
  return { iv, ciphertext, steps, blocks: ctBlocks };
}

/**
 * CBC Decrypt: M_i = D_k(C_i) ⊕ C_{i-1}.
 */
export function cbcDecrypt(key, iv, ciphertext) {
  const steps = [];
  const blocks = splitBlocks(ciphertext, 16, false);
  const ptBlocks = [];

  steps.push({ label: 'Mode', value: 'CBC Decrypt' });

  let prev = iv;
  for (let i = 0; i < blocks.length; i++) {
    const decrypted = aesDecryptBlock(key, blocks[i]);
    const pt = xorBytes(decrypted, prev);
    ptBlocks.push(pt);

    steps.push({
      label: `Block ${i}: D_k(C${i}) ⊕ C${i > 0 ? i-1 : 'IV'}`,
      value: `${bytesToHex(pt).slice(0,8)}...`
    });

    prev = blocks[i];
  }

  const padded = concatBytes(...ptBlocks);
  const plaintext = pkcs7Unpad(padded);
  steps.push({ label: 'Plaintext', value: bytesToHex(plaintext) });
  return { plaintext, steps, blocks: ptBlocks };
}

// ─── OFB Mode ───────────────────────────────────────────────────────────────

/**
 * OFB Encrypt/Decrypt: O_i = E_k(O_{i-1}), C_i = M_i ⊕ O_i.
 * Encryption and decryption are identical operations.
 */
export function ofbEncrypt(key, iv, message) {
  const steps = [];
  const padded = pkcs7Pad(message, 16);
  const blocks = splitBlocks(padded, 16, false);
  const ctBlocks = [];
  const keystreamBlocks = [];

  steps.push({ label: 'Mode', value: 'OFB (Output Feedback)' });
  steps.push({ label: 'Key', value: bytesToHex(key) });
  steps.push({ label: 'IV', value: bytesToHex(iv) });

  let oi = iv;
  for (let i = 0; i < blocks.length; i++) {
    oi = aesEncryptBlock(key, oi); // O_i = E_k(O_{i-1})
    keystreamBlocks.push(new Uint8Array(oi));
    const ct = xorBytes(blocks[i], oi);
    ctBlocks.push(ct);

    steps.push({
      label: `Block ${i}: O${i}=E_k(O${i > 0 ? i-1 : 'IV'}) ⊕ M${i}`,
      value: `${bytesToHex(oi).slice(0,8)}... ⊕ ${bytesToHex(blocks[i]).slice(0,8)}... = ${bytesToHex(ct).slice(0,8)}...`
    });
  }

  const ciphertext = concatBytes(...ctBlocks);
  return { iv, ciphertext, steps, blocks: ctBlocks, keystreamBlocks };
}

export function ofbDecrypt(key, iv, ciphertext) {
  // OFB decrypt is identical to encrypt
  const steps = [];
  const blocks = splitBlocks(ciphertext, 16, false);
  const ptBlocks = [];

  steps.push({ label: 'Mode', value: 'OFB Decrypt (same as encrypt)' });

  let oi = iv;
  for (let i = 0; i < blocks.length; i++) {
    oi = aesEncryptBlock(key, oi);
    const pt = xorBytes(blocks[i], oi);
    ptBlocks.push(pt);

    steps.push({
      label: `Block ${i}: O${i} ⊕ C${i}`,
      value: `${bytesToHex(pt).slice(0,8)}...`
    });
  }

  const padded = concatBytes(...ptBlocks);
  const plaintext = pkcs7Unpad(padded);
  steps.push({ label: 'Plaintext', value: bytesToHex(plaintext) });
  return { plaintext, steps, blocks: ptBlocks };
}

// ─── CTR Mode ───────────────────────────────────────────────────────────────

/**
 * CTR Encrypt: C_i = M_i ⊕ F_k(r + i), where r is a random nonce.
 */
export function ctrEncrypt(key, message, nonce = null) {
  const steps = [];
  const r = nonce || randomBytes(16);
  const padded = pkcs7Pad(message, 16);
  const blocks = splitBlocks(padded, 16, false);
  const ctBlocks = [];

  steps.push({ label: 'Mode', value: 'CTR (Counter)' });
  steps.push({ label: 'Key', value: bytesToHex(key) });
  steps.push({ label: 'Nonce r', value: bytesToHex(r) });

  for (let i = 0; i < blocks.length; i++) {
    const counter = addToCounter(r, i);
    const keystream = prfEvaluate(key, counter);
    const ct = xorBytes(blocks[i], keystream);
    ctBlocks.push(ct);

    steps.push({
      label: `Block ${i}: F_k(r+${i}) ⊕ M${i}`,
      value: `${bytesToHex(keystream).slice(0,8)}... ⊕ ${bytesToHex(blocks[i]).slice(0,8)}... = ${bytesToHex(ct).slice(0,8)}...`
    });
  }

  const ciphertext = concatBytes(...ctBlocks);
  return { nonce: r, ciphertext, steps, blocks: ctBlocks };
}

/**
 * CTR Decrypt: M_i = C_i ⊕ F_k(r + i).
 */
export function ctrDecrypt(key, nonce, ciphertext) {
  const steps = [];
  const blocks = splitBlocks(ciphertext, 16, false);
  const ptBlocks = [];

  steps.push({ label: 'Mode', value: 'CTR Decrypt' });

  for (let i = 0; i < blocks.length; i++) {
    const counter = addToCounter(nonce, i);
    const keystream = prfEvaluate(key, counter);
    const pt = xorBytes(blocks[i], keystream);
    ptBlocks.push(pt);

    steps.push({
      label: `Block ${i}: F_k(r+${i}) ⊕ C${i}`,
      value: `${bytesToHex(pt).slice(0,8)}...`
    });
  }

  const padded = concatBytes(...ptBlocks);
  const plaintext = pkcs7Unpad(padded);
  steps.push({ label: 'Plaintext', value: bytesToHex(plaintext) });
  return { plaintext, steps, blocks: ptBlocks };
}

// ─── Unified API ────────────────────────────────────────────────────────────

/**
 * Unified encryption API.
 * @param {'CBC' | 'OFB' | 'CTR'} mode
 * @param {Uint8Array} key - 16-byte key
 * @param {Uint8Array} message - Plaintext
 * @returns {Object} - { iv/nonce, ciphertext, steps }
 */
export function encrypt(mode, key, message) {
  const iv = randomBytes(16);
  switch (mode) {
    case 'CBC': return cbcEncrypt(key, iv, message);
    case 'OFB': return ofbEncrypt(key, iv, message);
    case 'CTR': return ctrEncrypt(key, message);
    default: throw new Error(`Unknown mode: ${mode}`);
  }
}

/**
 * Unified decryption API.
 * @param {'CBC' | 'OFB' | 'CTR'} mode
 * @param {Uint8Array} key - 16-byte key
 * @param {Uint8Array} ivOrNonce - IV or nonce
 * @param {Uint8Array} ciphertext
 * @returns {Object} - { plaintext, steps }
 */
export function decrypt(mode, key, ivOrNonce, ciphertext) {
  switch (mode) {
    case 'CBC': return cbcDecrypt(key, ivOrNonce, ciphertext);
    case 'OFB': return ofbDecrypt(key, ivOrNonce, ciphertext);
    case 'CTR': return ctrDecrypt(key, ivOrNonce, ciphertext);
    default: throw new Error(`Unknown mode: ${mode}`);
  }
}

// ─── Attack Demos ───────────────────────────────────────────────────────────

/**
 * CBC IV-reuse attack demo.
 * Encrypt two different messages with the same IV.
 * If M_i = M'_i, then C_i = C'_i (leaks equality).
 */
export function cbcIVReuseAttack(m1, m2) {
  const key = randomBytes(16);
  const iv = randomBytes(16); // Same IV for both

  const enc1 = cbcEncrypt(key, iv, m1);
  const enc2 = cbcEncrypt(key, iv, m2);

  // Find matching blocks
  const blocks1 = splitBlocks(enc1.ciphertext, 16, false);
  const blocks2 = splitBlocks(enc2.ciphertext, 16, false);
  const matches = [];

  const mb1 = splitBlocks(pkcs7Pad(m1, 16), 16, false);
  const mb2 = splitBlocks(pkcs7Pad(m2, 16), 16, false);

  for (let i = 0; i < Math.min(blocks1.length, blocks2.length); i++) {
    if (bytesToHex(blocks1[i]) === bytesToHex(blocks2[i])) {
      matches.push(i);
    }
  }

  return {
    enc1, enc2, matches,
    steps: [
      { label: 'Attack: CBC IV Reuse', value: 'Same IV used for two messages' },
      { label: 'IV', value: bytesToHex(iv) },
      { label: 'Message 1', value: bytesToHex(m1).slice(0, 32) },
      { label: 'Message 2', value: bytesToHex(m2).slice(0, 32) },
      { label: 'CT 1', value: bytesToHex(enc1.ciphertext).slice(0, 32) },
      { label: 'CT 2', value: bytesToHex(enc2.ciphertext).slice(0, 32) },
      { label: 'Matching CT blocks', value: matches.length > 0 ? `Blocks ${matches.join(', ')} match! Leaks M_i = M'_i` : 'No matches (different messages)' },
    ]
  };
}

/**
 * OFB keystream-reuse attack demo.
 * Encrypt two messages with the same IV in OFB mode.
 * C1 ⊕ C2 = M1 ⊕ M2 (leaks XOR of plaintexts).
 */
export function ofbKeystreamReuseAttack(m1, m2) {
  const key = randomBytes(16);
  const iv = randomBytes(16);

  const enc1 = ofbEncrypt(key, iv, m1);
  const enc2 = ofbEncrypt(key, iv, m2);

  const ctXor = xorBytes(enc1.ciphertext.slice(0, Math.min(m1.length, m2.length)),
                         enc2.ciphertext.slice(0, Math.min(m1.length, m2.length)));
  const ptXor = xorBytes(m1.slice(0, Math.min(m1.length, m2.length)),
                         m2.slice(0, Math.min(m1.length, m2.length)));

  const xorMatch = bytesToHex(ctXor) === bytesToHex(ptXor);

  return {
    enc1, enc2, ctXor, ptXor,
    steps: [
      { label: 'Attack: OFB Keystream Reuse', value: 'Same IV used for two messages' },
      { label: 'C₁ ⊕ C₂', value: bytesToHex(ctXor).slice(0, 32) },
      { label: 'M₁ ⊕ M₂', value: bytesToHex(ptXor).slice(0, 32) },
      { label: 'C₁⊕C₂ = M₁⊕M₂?', value: xorMatch ? '✓ YES — plaintext XOR leaked!' : '✗ No (unexpected)' },
      { label: 'Conclusion', value: 'IV reuse in OFB leaks the XOR of plaintexts' },
    ]
  };
}

/**
 * Bit-flip error propagation demo.
 * Flip a bit in the ciphertext and see how it affects the decrypted plaintext.
 * CBC: corrupts 2 blocks (current + next)
 * OFB: corrupts only the same block (single bit flip)
 * CTR: corrupts only the same block (single bit flip)
 */
export function bitFlipDemo(mode, key, iv, message, blockIdx = 0, bitIdx = 0) {
  let encResult;
  if (mode === 'CBC') encResult = cbcEncrypt(key, iv, message);
  else if (mode === 'OFB') encResult = ofbEncrypt(key, iv, message);
  else encResult = ctrEncrypt(key, message, iv);

  const ct = new Uint8Array(encResult.ciphertext);

  // Flip the specified bit
  const bytePos = blockIdx * 16 + Math.floor(bitIdx / 8);
  const bitPos = bitIdx % 8;
  if (bytePos < ct.length) {
    ct[bytePos] ^= (1 << (7 - bitPos));
  }

  let decOriginal, decCorrupted;
  if (mode === 'CBC') {
    decOriginal = cbcDecrypt(key, iv, encResult.ciphertext);
    decCorrupted = cbcDecrypt(key, iv, ct);
  } else if (mode === 'OFB') {
    decOriginal = ofbDecrypt(key, iv, encResult.ciphertext);
    decCorrupted = ofbDecrypt(key, iv, ct);
  } else {
    const nonce = encResult.nonce || iv;
    decOriginal = ctrDecrypt(key, nonce, encResult.ciphertext);
    decCorrupted = ctrDecrypt(key, nonce, ct);
  }

  // Find corrupted blocks
  const origBlocks = splitBlocks(pkcs7Pad(decOriginal.plaintext, 16), 16, false);
  const corrBlocks = splitBlocks(pkcs7Pad(decCorrupted.plaintext, 16), 16, false);
  const corruptedBlocks = [];
  for (let i = 0; i < Math.min(origBlocks.length, corrBlocks.length); i++) {
    if (bytesToHex(origBlocks[i]) !== bytesToHex(corrBlocks[i])) {
      corruptedBlocks.push(i);
    }
  }

  return {
    original: decOriginal.plaintext,
    corrupted: decCorrupted.plaintext,
    corruptedBlocks,
    steps: [
      { label: `Bit flip in ${mode}`, value: `Flipped bit ${bitIdx} of block ${blockIdx}` },
      { label: 'Corrupted blocks', value: corruptedBlocks.join(', ') || 'None' },
      { label: 'Expected pattern', value: mode === 'CBC' ? '2 blocks affected' : '1 block affected (stream cipher behavior)' },
    ]
  };
}

/**
 * Run correctness tests for all modes.
 * Tests sub-block, one-block, and multi-block messages.
 */
export function runCorrectnessTests() {
  const key = randomBytes(16);
  const iv = randomBytes(16);
  const results = [];

  const testMessages = [
    { label: 'Sub-block (5 bytes)', data: randomBytes(5) },
    { label: 'One block (16 bytes)', data: randomBytes(16) },
    { label: 'Multi-block (48 bytes)', data: randomBytes(48) },
  ];

  for (const mode of ['CBC', 'OFB', 'CTR']) {
    for (const { label, data } of testMessages) {
      try {
        const enc = mode === 'CTR' ? ctrEncrypt(key, data) : (mode === 'CBC' ? cbcEncrypt(key, iv, data) : ofbEncrypt(key, iv, data));
        const ivOrNonce = mode === 'CTR' ? enc.nonce : iv;
        const dec = mode === 'CBC' ? cbcDecrypt(key, ivOrNonce, enc.ciphertext) : (mode === 'OFB' ? ofbDecrypt(key, ivOrNonce, enc.ciphertext) : ctrDecrypt(key, ivOrNonce, enc.ciphertext));

        const match = bytesToHex(data) === bytesToHex(dec.plaintext);
        results.push({ mode, label, pass: match });
      } catch (e) {
        results.push({ mode, label, pass: false, error: e.message });
      }
    }
  }

  return results;
}
