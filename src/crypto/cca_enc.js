/**
 * PA#6: CCA-Secure Symmetric Encryption (Encrypt-then-MAC).
 */

import { cpaEncrypt, cpaDecrypt } from './cpa_enc.js';
import { cbcMac, macVerify } from './mac.js';
import { concatBytes, bytesToHex } from './utils.js';

/**
 * Encrypt-then-MAC using CPA-Enc and CBC-MAC.
 */
export function ccaEncrypt(kE, kM, message) {
  const enc = cpaEncrypt(kE, message);
  const macInput = concatBytes(enc.nonce, enc.ciphertext);
  const tag = cbcMac(kM, macInput);
  return {
    nonce: enc.nonce,
    ciphertext: enc.ciphertext,
    tag,
    steps: [
      ...enc.steps,
      { label: 'MAC input', value: bytesToHex(macInput).slice(0, 64) + (macInput.length > 32 ? '...' : '') },
      { label: 'Tag (CBC-MAC)', value: bytesToHex(tag) },
    ]
  };
}

/**
 * Verify then decrypt.
 */
export function ccaDecrypt(kE, kM, nonce, ciphertext, tag) {
  const macInput = concatBytes(nonce, ciphertext);
  const valid = macVerify(kM, macInput, tag, 'cbc');
  if (!valid) {
    return { valid: false, plaintext: new Uint8Array(0), steps: [{ label: 'MAC verify', value: 'reject' }] };
  }

  const dec = cpaDecrypt(kE, nonce, ciphertext);
  return {
    valid: true,
    plaintext: dec.plaintext,
    steps: [{ label: 'MAC verify', value: 'accept' }, ...dec.steps],
  };
}

export const PA_NUMBER = 6;
export const STUB = false;