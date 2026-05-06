/**
 * PA#17: CCA-hardened packaging via Encrypt-then-Sign.
 *
 * Lineage (no external crypto libs):
 *   PA#17 → PA#16 ElGamal (`elgamal.js`) + PA#15 RSA signatures (`rsa_sig.js`)
 *   → PA#8 CRHF (`crhf.js` via Sign) + PA#11 DLP params (`owf.js` via ElGamal)
 *   → PA#12/13 RSA modulus (`prime.js` / Miller–Rabin).
 *
 * Decrypt order is mandatory: Verify(CE, σ) first; only on success run ElGamal.Dec.
 */

import { Enc as elGamalEnc, Dec as elGamalDec } from './elgamal.js';
import { Sign, verifyWithTrace } from './rsa_sig.js';
import { bigIntToBytes, bytesToBigInt, concatBytes } from './utils.js';

/** Byte length of one ElGamal component mod p (fixed-width big-endian). */
export function elGamalComponentByteLength(p) {
  return Math.ceil(p.toString(16).length / 2);
}

/** Canonical encoding of CE = (c₁, c₂) for signing / verification. */
export function serializeElGamalCiphertext(c1, c2, p) {
  const len = elGamalComponentByteLength(p);
  return concatBytes(bigIntToBytes(c1, len), bigIntToBytes(c2, len));
}

export function deserializeElGamalCiphertext(bytes, p) {
  const len = elGamalComponentByteLength(p);
  if (bytes.length !== 2 * len) {
    throw new Error(`Expected ${2 * len} bytes for ElGamal CE over this p; got ${bytes.length}`);
  }
  const c1 = bytesToBigInt(bytes.subarray(0, len)) % p;
  const c2 = bytesToBigInt(bytes.subarray(len)) % p;
  return { c1, c2 };
}

/** Flip one bit of one byte (default: first byte, LSB) — CCA adversary toy tamper. */
export function tamperCeEncoding(ceBytes, byteIndex = 0) {
  const out = Uint8Array.from(ceBytes);
  const i = ((byteIndex % out.length) + out.length) % out.length;
  out[i] ^= 1;
  return out;
}

/**
 * CCA PKC encrypt: CE ← ElGamal.Enc(pk, m); σ ← Sign(sk, serialize(CE)).
 * @param {{ p: bigint, g: bigint, q: bigint, h: bigint }} elGamalPk
 * @param {{ N: bigint, d: bigint, e: bigint }} rsaSk
 * @param {bigint} m
 */
export function ccaPkcEnc(elGamalPk, rsaSk, m) {
  const { c1, c2 } = elGamalEnc(elGamalPk, m);
  const ceBytes = serializeElGamalCiphertext(c1, c2, elGamalPk.p);
  const { sigma } = Sign(rsaSk, ceBytes, { useHash: true });
  return { c1, c2, sigma, ceBytes };
}

/**
 * CCA PKC decrypt: verify σ on serialized CE; if invalid return ⊥; else ElGamal.Dec.
 * @returns {{ ok: true, plaintext: bigint } | { ok: false, plaintext: null, reason: string }}
 */
export function ccaPkcDec(elGamalSk, elGamalPk, rsaVk, c1, c2, sigma) {
  const ceBytes = serializeElGamalCiphertext(c1, c2, elGamalPk.p);
  if (!verifyWithTrace(rsaVk, ceBytes, sigma, { useHash: true }).valid) {
    return {
      ok: false,
      plaintext: null,
      reason: 'Signature invalid — decryption aborted (⊥). Verify must precede Dec.',
    };
  }
  try {
    const plaintext = elGamalDec(elGamalSk, c1, c2, elGamalPk.p);
    return { ok: true, plaintext, reason: null };
  } catch (e) {
    return {
      ok: false,
      plaintext: null,
      reason: `ElGamal decryption error after valid signature: ${e.message || e}`,
    };
  }
}

/**
 * Same as `ccaPkcDec`, but returns RSA verification intermediates for the UI.
 */
export function ccaPkcDecWithTrace(elGamalSk, elGamalPk, rsaVk, c1, c2, sigma) {
  const ceBytes = serializeElGamalCiphertext(c1, c2, elGamalPk.p);
  const v = verifyWithTrace(rsaVk, ceBytes, sigma, { useHash: true });

  const steps = [
    { label: 'Step 1 — serialized CE (hex, prefix)', value: `${bufferToHexPrefix(ceBytes, 48)}…` },
    { label: 'Step 1 — Verify σ on CE', value: v.valid ? 'VALID' : 'INVALID' },
    { label: 'H(CE) rep mod N', value: v.representative?.toString?.() ?? '' },
    { label: 'σ^e mod N', value: v.sigmaPowE?.toString?.() ?? '' },
  ];

  if (!v.valid) {
    steps.push({
      label: 'Step 2 — ElGamal.Dec',
      value: 'Skipped (signature check failed). Output ⊥.',
      className: 'error',
    });
    return {
      ok: false,
      plaintext: null,
      reason: 'Signature invalid — decryption aborted (⊥).',
      steps,
      verifyTrace: v,
    };
  }

  try {
    const plaintext = elGamalDec(elGamalSk, c1, c2, elGamalPk.p);
    steps.push({
      label: 'Step 2 — ElGamal.Dec',
      value: `m = ${plaintext.toString()}`,
      className: 'success',
    });
    return {
      ok: true,
      plaintext,
      reason: null,
      steps,
      verifyTrace: v,
    };
  } catch (e) {
    steps.push({
      label: 'Step 2 — ElGamal.Dec',
      value: `Error: ${e.message || e}`,
      className: 'error',
    });
    return {
      ok: false,
      plaintext: null,
      reason: e.message || String(e),
      steps,
      verifyTrace: v,
    };
  }
}

function bufferToHexPrefix(u8, maxChars) {
  let h = '';
  for (let i = 0; i < u8.length && h.length < maxChars; i++) {
    h += u8[i].toString(16).padStart(2, '0');
  }
  return h;
}

/**
 * IND-CCA2-style decryption oracle (counts queries).
 */
export function createCca2Oracle(elGamalSk, elGamalPk, rsaVk) {
  let queries = 0;
  return {
    query(c1, c2, sigma) {
      queries += 1;
      return { queryId: queries, ...ccaPkcDecWithTrace(elGamalSk, elGamalPk, rsaVk, c1, c2, sigma) };
    },
    get queryCount() {
      return queries;
    },
    reset() {
      queries = 0;
    },
  };
}

export const PA_NUMBER = 17;
export const STUB = false;
