/**
 * PA#18: 1-out-of-2 Oblivious Transfer (Bellare–Micali / EGL).
 *
 * Lineage (no external crypto libs):
 *   PA#18 → PA#16 ElGamal (`elgamal.js`) → PA#11 DLP params (`owf.js`).
 *
 * Construction over the prime-order subgroup G = ⟨g⟩ ⊂ ℤₚ* of order q from PA#16:
 *
 *   Public setup: a fixed group element C ∈ G whose discrete log (log_g C) is
 *   *unknown* to both parties.  We sample C = g^z and immediately discard z so
 *   no one in the protocol can use it.
 *
 *   Receiver (choice bit b):
 *     1. x ← ℤ_q*; sk_b = x, pk_b = g^x mod p.
 *     2. pk_{1-b} = C · (pk_b)^{-1} mod p   (no trapdoor — would need log_g C).
 *     3. Send (pk_0, pk_1).
 *
 *   Sender (messages m_0, m_1 ∈ ℤₚ*):
 *     Sanity: pk_0 · pk_1 ≡ C (mod p).
 *     For i = 0,1: r_i ← ℤ_q, c_i = (g^{r_i} mod p,  m_i · pk_i^{r_i} mod p).
 *     Send (c_0, c_1).
 *
 *   Receiver: m_b = c_b.v · (c_b.u)^{-x} mod p (ElGamal decryption with sk_b).
 *
 * Security:
 *   • Receiver privacy — pk_0·pk_1 ≡ C always, so the sender's view is identical
 *     for b=0 and b=1.
 *   • Sender privacy — decrypting c_{1-b} requires log_g(pk_{1-b}), reducing to DLP/CDH.
 *
 * Bit-message encoding for OT-of-bits (used by PA#19 / PA#20):
 *   bit 0 ↔ group element 1 ∈ ℤₚ*
 *   bit 1 ↔ group element 2 ∈ ℤₚ*
 */

import { ELGAMAL_DEFAULT_PARAMS, sampleExponentNonZero } from './elgamal.js';
import { modPow, modInverse, bytesToBigInt, randomBytes } from './utils.js';

// ─── Bit ↔ group-element encoding for OT-of-bits ─────────────────────────────

export const BIT_ZERO_ENCODING = 1n;
export const BIT_ONE_ENCODING = 2n;

/** Encode a single bit b ∈ {0,1} as a non-zero element of ℤₚ*. */
export function encodeBit(b) {
  if (b === 0 || b === 0n || b === false) return BIT_ZERO_ENCODING;
  if (b === 1 || b === 1n || b === true) return BIT_ONE_ENCODING;
  throw new Error(`encodeBit: expected 0 or 1, got ${b}`);
}

/** Decode a group element back to a bit (or null if unrecognised). */
export function decodeBit(m) {
  const v = typeof m === 'bigint' ? m : BigInt(m);
  if (v === BIT_ZERO_ENCODING) return 0;
  if (v === BIT_ONE_ENCODING) return 1;
  return null;
}

// ─── Public setup: fixed C with unknown DLP ──────────────────────────────────

/**
 * Generate a public group element C with no party retaining log_g(C).
 * We deliberately throw away the witness z immediately after deriving C.
 *
 * @param {{ p: bigint, q: bigint, g: bigint }} [params]
 */
export function generatePublicConstant(params = ELGAMAL_DEFAULT_PARAMS) {
  const { p, q, g } = params;
  const z = sampleExponentNonZero(q);
  const C = modPow(g, z, p);
  // z is local-only and never returned; the witness vanishes when this scope exits.
  // For the toy demo, we expose `witnessHint` (the bit-length of z) so the UI
  // can confirm something nontrivial was sampled, but never z itself.
  return { C, witnessBits: z.toString(2).length, params };
}

/** Default OT parameter bundle (matches PA#16 ElGamal group). */
export function defaultOtParams() {
  return generatePublicConstant(ELGAMAL_DEFAULT_PARAMS);
}

// ─── Step 1: Receiver builds (pk_0, pk_1) given choice bit b ────────────────

/**
 * @param {0|1} b — receiver's choice bit
 * @param {{ C: bigint, params: { p: bigint, q: bigint, g: bigint } }} otParams
 * @returns {{ pk0: bigint, pk1: bigint, state: { b: 0|1, sk_b: bigint, p: bigint } }}
 */
export function otReceiverStep1(b, otParams = defaultOtParams()) {
  if (b !== 0 && b !== 1) throw new Error(`otReceiverStep1: choice bit b must be 0 or 1, got ${b}`);
  const { C, params } = otParams;
  const { p, q, g } = params;

  const x = sampleExponentNonZero(q);
  const pkB = modPow(g, x, p);
  const pkOther = (C * modInverse(pkB, p)) % p;

  const pk0 = b === 0 ? pkB : pkOther;
  const pk1 = b === 0 ? pkOther : pkB;

  return {
    pk0,
    pk1,
    state: { b, sk_b: x, p, q, g, C },
  };
}

// ─── Step 2: Sender encrypts both messages ───────────────────────────────────

/**
 * @param {bigint} pk0
 * @param {bigint} pk1
 * @param {bigint} m0 — group-element-encoded message for index 0
 * @param {bigint} m1 — group-element-encoded message for index 1
 * @param {{ C: bigint, params: { p: bigint, q: bigint, g: bigint } }} otParams
 */
export function otSenderStep(pk0, pk1, m0, m1, otParams = defaultOtParams()) {
  const { C, params } = otParams;
  const { p, q, g } = params;

  // Sender check: pk_0 · pk_1 ≡ C (mod p). If receiver cheats (picks both
  // public keys with known DLPs), this product would solve DLP — see security note.
  const product = (pk0 * pk1) % p;
  if (product !== C) {
    throw new Error(
      `otSenderStep: pk_0 · pk_1 (mod p) ≠ C — receiver malformed keys (would need log_g C to cheat).`
    );
  }

  const r0 = sampleExponentNonZero(q);
  const r1 = sampleExponentNonZero(q);

  const u0 = modPow(g, r0, p);
  const v0 = (m0 * modPow(pk0, r0, p)) % p;
  const u1 = modPow(g, r1, p);
  const v1 = (m1 * modPow(pk1, r1, p)) % p;

  return {
    c0: { u: u0, v: v0 },
    c1: { u: u1, v: v1 },
  };
}

// ─── Step 3: Receiver decrypts c_b ───────────────────────────────────────────

/**
 * @param {{ b: 0|1, sk_b: bigint, p: bigint }} state
 * @param {{ u: bigint, v: bigint }} c0
 * @param {{ u: bigint, v: bigint }} c1
 * @returns {bigint} m_b
 */
export function otReceiverStep2(state, c0, c1) {
  const { b, sk_b: x, p } = state;
  const c = b === 0 ? c0 : c1;
  const s = modPow(c.u, x, p);
  const sInv = modInverse(s, p);
  return (c.v * sInv) % p;
}

// ─── Cheat attempt (sender privacy demo) ─────────────────────────────────────

/**
 * Attempt to decrypt the *other* ciphertext c_{1-b}. Without log_g(pk_{1-b})
 * the receiver gets a uniformly-distributed group element — i.e. garbage that
 * does not match either bit encoding.
 */
export function otReceiverCheatAttempt(state, c0, c1) {
  const { b, sk_b: x, p } = state;
  const c = b === 0 ? c1 : c0;
  // Receiver only has sk_b; using it on the wrong ciphertext produces
  //   v_{1-b} · (u_{1-b})^{-x}  =  m_{1-b} · pk_{1-b}^{r_{1-b}} · g^{-r_{1-b}·x}
  //                            =  m_{1-b} · (pk_{1-b} · g^{-x})^{r_{1-b}}
  //                            =  m_{1-b} · (C · pk_b^{-2})^{r_{1-b}}  (random in G)
  const s = modPow(c.u, x, p);
  const sInv = modInverse(s, p);
  return (c.v * sInv) % p;
}

// ─── End-to-end convenience wrapper for tests / demos ────────────────────────

/**
 * Run the full 3-message OT protocol locally (for tests / single-process demos).
 * @param {0|1} b
 * @param {bigint} m0
 * @param {bigint} m1
 * @param {ReturnType<typeof generatePublicConstant>} [otParams]
 */
export function runOt(b, m0, m1, otParams = defaultOtParams()) {
  const { pk0, pk1, state } = otReceiverStep1(b, otParams);
  const { c0, c1 } = otSenderStep(pk0, pk1, m0, m1, otParams);
  const recovered = otReceiverStep2(state, c0, c1);
  const cheat = otReceiverCheatAttempt(state, c0, c1);
  return { pk0, pk1, c0, c1, state, recovered, cheat };
}

/** Specialisation for OT-of-bits: m_0, m_1 ∈ {0,1}. */
export function runOtBits(b, m0Bit, m1Bit, otParams = defaultOtParams()) {
  const r = runOt(b, encodeBit(m0Bit), encodeBit(m1Bit), otParams);
  const decoded = decodeBit(r.recovered);
  return { ...r, recoveredBit: decoded };
}

// ─── Self-test (used by PA#19 / PA#20 demos to confirm wiring) ──────────────

/** Run all four (b, (m0,m1)) combinations and assert correctness. */
export function selfTestOtBits(otParams = defaultOtParams()) {
  const results = [];
  for (const b of [0, 1]) {
    for (const m0 of [0, 1]) {
      for (const m1 of [0, 1]) {
        const r = runOtBits(b, m0, m1, otParams);
        const expected = b === 0 ? m0 : m1;
        results.push({
          b,
          m0,
          m1,
          expected,
          recovered: r.recoveredBit,
          ok: r.recoveredBit === expected,
        });
      }
    }
  }
  return {
    results,
    passed: results.every(r => r.ok),
  };
}

export const PA_NUMBER = 18;
export const STUB = false;
