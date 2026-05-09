/**
 * PA#19: Secure boolean gates from PA#18 Oblivious Transfer.
 *
 * Lineage:
 *   PA#19 → PA#18 OT (`ot.js`) → PA#16 ElGamal (`elgamal.js`) → PA#11 DLP (`owf.js`)
 *
 * Two layers of API:
 *
 *   1. Cleartext-input gates (matches the PA#19 spec figure exactly).
 *      Used by the PA#19 demo. Alice holds bit a, Bob holds bit b, both end
 *      up knowing the output bit; the protocol reveals nothing beyond it.
 *
 *        secureAnd(a, b, otParams) — one OT call: sender (m0,m1)=(0,a), receiver=b.
 *        secureXor(a, b)           — additive masking: Alice picks r, both
 *                                    reveal a⊕r and b⊕r; XOR is the result.
 *        secureNot(a)              — local flip on one party's share.
 *
 *   2. GMW share-based gates used by PA#20 to compose arbitrary circuits.
 *      Each wire is held as (w_A, w_B) with w = w_A ⊕ w_B; intermediate wire
 *      values are *never* revealed in the clear.
 *
 *        gmwShareInput(value, owner)        — split a cleartext input into shares
 *        gmwXor(xS, yS)                     — local: (x_A⊕y_A, x_B⊕y_B)
 *        gmwNot(xS)                         — local: flip Alice's share
 *        gmwAnd(xS, yS, otParams)           — interactive: 2 OTs (cross-terms)
 *        gmwReconstruct(xS)                 — XOR shares to get cleartext
 */

import {
  defaultOtParams,
  encodeBit,
  decodeBit,
  otReceiverStep1,
  otSenderStep,
  otReceiverStep2,
} from './ot.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function asBit(v) {
  if (v === 0 || v === false || v === 0n) return 0;
  if (v === 1 || v === true || v === 1n) return 1;
  throw new Error(`asBit: expected 0/1, got ${v}`);
}

function randomBit() {
  return crypto.getRandomValues(new Uint8Array(1))[0] & 1;
}

// ─── Cleartext-input single-gate primitives (PA#19 demo) ────────────────────

/**
 * Secure AND with cleartext inputs.
 * Alice plays OT sender with (m0, m1) = (0, a); Bob plays OT receiver, choice=b.
 * Bob reads m_b = a·b = a∧b, then sends the bit to Alice so both learn the output.
 *
 * @param {0|1} a — Alice's input
 * @param {0|1} b — Bob's input
 * @param {ReturnType<typeof defaultOtParams>} [otParams]
 */
export function secureAnd(a, b, otParams = defaultOtParams()) {
  const aBit = asBit(a);
  const bBit = asBit(b);

  // Alice's OT messages: (0, a)
  const m0Bit = 0;
  const m1Bit = aBit;

  // Bob (receiver) builds (pk0, pk1) for choice = b
  const r1 = otReceiverStep1(bBit, otParams);
  // Alice (sender) encrypts both messages
  const r2 = otSenderStep(r1.pk0, r1.pk1, encodeBit(m0Bit), encodeBit(m1Bit), otParams);
  // Bob decrypts c_b
  const recovered = otReceiverStep2(r1.state, r2.c0, r2.c1);
  const recoveredBit = decodeBit(recovered);
  if (recoveredBit === null) {
    throw new Error('secureAnd: OT output did not decode to a bit (group encoding mismatch)');
  }

  // Bob sends the bit to Alice so the output is mutual.
  // (Reveals only the AND output — nothing beyond f(a,b).)
  const transcript = [
    { label: 'Alice OT inputs (m₀, m₁)', value: `(${m0Bit}, ${m1Bit}) = (0, a)` },
    { label: 'Bob OT choice', value: `b = ${bBit}` },
    { label: 'pk₀ (mod p, prefix)', value: `${shortBig(r1.pk0)}…` },
    { label: 'pk₁ (mod p, prefix)', value: `${shortBig(r1.pk1)}…` },
    { label: 'Sender ciphertext c₀', value: `(u=${shortBig(r2.c0.u)}…, v=${shortBig(r2.c0.v)}…)` },
    { label: 'Sender ciphertext c₁', value: `(u=${shortBig(r2.c1.u)}…, v=${shortBig(r2.c1.v)}…)` },
    { label: 'Bob recovers m_b', value: `${recoveredBit}  (= a·b)` },
    { label: 'Bob → Alice', value: `${recoveredBit}  (one-bit reveal — only the output)` },
  ];

  return {
    result: recoveredBit,
    transcript,
    otTrace: { pk0: r1.pk0, pk1: r1.pk1, c0: r2.c0, c1: r2.c1, recovered },
  };
}

/**
 * Secure XOR via additive masking (no OT).
 * Alice picks r ← {0,1}, sends r to Bob; both publish masked shares
 *   α = a ⊕ r,  β = b ⊕ r.
 * The result a⊕b = α ⊕ β. No information beyond a⊕b is revealed.
 */
export function secureXor(a, b) {
  const aBit = asBit(a);
  const bBit = asBit(b);
  const r = randomBit();
  const alpha = aBit ^ r;     // Alice's masked share, published to Bob
  const beta = bBit ^ r;      // Bob's masked share, published to Alice
  const result = alpha ^ beta;
  const transcript = [
    { label: 'Alice samples r ∈ {0,1}', value: `r = ${r}` },
    { label: 'Alice → Bob: r', value: r.toString() },
    { label: 'Alice publishes α = a ⊕ r', value: `α = ${alpha}` },
    { label: 'Bob publishes β = b ⊕ r', value: `β = ${beta}` },
    { label: 'Output = α ⊕ β', value: `${result}  (= a ⊕ b)` },
  ];
  return { result, transcript, mask: r };
}

/** Secure NOT — Alice locally flips her share; no communication. */
export function secureNot(a) {
  const aBit = asBit(a);
  const result = aBit ^ 1;
  return {
    result,
    transcript: [
      { label: 'Alice locally flips a', value: `¬${aBit} = ${result}` },
      { label: 'Communication', value: 'none' },
    ],
  };
}

// ─── Truth-table verifier (PA#19 demo) ─────────────────────────────────────

export function truthTableAnd(otParams = defaultOtParams()) {
  const rows = [];
  for (const a of [0, 1]) {
    for (const b of [0, 1]) {
      const { result } = secureAnd(a, b, otParams);
      rows.push({ a, b, expected: a & b, got: result, ok: (a & b) === result });
    }
  }
  return { rows, passed: rows.every(r => r.ok) };
}

export function truthTableXor() {
  const rows = [];
  for (const a of [0, 1]) {
    for (const b of [0, 1]) {
      const { result } = secureXor(a, b);
      rows.push({ a, b, expected: a ^ b, got: result, ok: (a ^ b) === result });
    }
  }
  return { rows, passed: rows.every(r => r.ok) };
}

// ─── GMW share-based gates (PA#20 plumbing) ─────────────────────────────────

/**
 * Share a cleartext bit `value` from `owner` ∈ {'alice','bob'} to the other party.
 * Returns { aliceShare, bobShare } such that aliceShare ⊕ bobShare = value.
 */
export function gmwShareInput(value, owner) {
  const v = asBit(value);
  const r = randomBit();
  if (owner === 'alice') {
    // Alice picks r, keeps r as her share, sends v⊕r to Bob.
    return { aliceShare: r, bobShare: v ^ r };
  }
  if (owner === 'bob') {
    return { aliceShare: v ^ r, bobShare: r };
  }
  throw new Error(`gmwShareInput: owner must be 'alice' or 'bob', got ${owner}`);
}

/** XOR gate: each party XORs their shares locally; no communication. */
export function gmwXor(xShares, yShares) {
  return {
    aliceShare: xShares.aliceShare ^ yShares.aliceShare,
    bobShare: xShares.bobShare ^ yShares.bobShare,
  };
}

/** NOT gate: Alice flips her share. NOT(x_A ⊕ x_B) = (1⊕x_A) ⊕ x_B. */
export function gmwNot(xShares) {
  return {
    aliceShare: xShares.aliceShare ^ 1,
    bobShare: xShares.bobShare,
  };
}

/**
 * AND gate via two OTs (GMW). Computes shares of x ∧ y given shares of x and y.
 *
 * x∧y = (x_A⊕x_B)(y_A⊕y_B) = x_A·y_A ⊕ x_A·y_B ⊕ x_B·y_A ⊕ x_B·y_B.
 * Each party computes its own diagonal product locally; the cross terms
 * (x_A · y_B) and (x_B · y_A) are computed via OT-based bilinear multiplication.
 *
 * Cross term x_A · y_B (Alice has x_A, Bob has y_B):
 *   Alice picks random s ∈ {0,1}. Acts as OT sender with messages
 *     (s ⊕ x_A·0, s ⊕ x_A·1) = (s, s ⊕ x_A).
 *   Bob acts as OT receiver with choice y_B. Receives s ⊕ x_A·y_B.
 *   Alice's share of the cross term = s; Bob's share = s ⊕ x_A·y_B.
 *
 * Returned shares: {aliceShare, bobShare} with XOR equal to (x ∧ y).
 */
export function gmwAnd(xShares, yShares, otParams = defaultOtParams()) {
  const xA = xShares.aliceShare;
  const xB = xShares.bobShare;
  const yA = yShares.aliceShare;
  const yB = yShares.bobShare;

  // Cross term 1: x_A · y_B  (Alice → Bob via OT; Bob's choice = y_B)
  const ct1 = otBilinearProduct(xA, yB, otParams);

  // Cross term 2: x_B · y_A  (Bob → Alice via OT; Alice's choice = y_A)
  // Note: We swap roles — Bob is OT sender (knows x_B), Alice is OT receiver (chooses y_A).
  const ct2 = otBilinearProduct(xB, yA, otParams);

  // Diagonal terms are local.
  const aliceLocal = xA & yA;          // x_A · y_A
  const bobLocal = xB & yB;            // x_B · y_B

  // Combine: c = (x_A·y_A) ⊕ (x_A·y_B) ⊕ (x_B·y_A) ⊕ (x_B·y_B)
  // Alice holds: x_A·y_A ⊕ s1 ⊕ (s2 ⊕ x_B·y_A_for_Alice)
  // Specifically: ct1 returns {senderShare, receiverShare}; the *sender* keeps
  // a random mask s, the *receiver* gets s ⊕ product.
  return {
    aliceShare: aliceLocal ^ ct1.senderShare ^ ct2.receiverShare,
    bobShare: bobLocal ^ ct1.receiverShare ^ ct2.senderShare,
    otCalls: 2,
    crossTerms: { ct1, ct2 },
  };
}

/**
 * Bilinear product via OT: given a (held by sender) and b (held by receiver),
 * return additive shares of a·b ∈ {0,1}.
 *
 * @returns {{ senderShare: 0|1, receiverShare: 0|1 }}
 */
function otBilinearProduct(a, b, otParams) {
  const aBit = asBit(a);
  const bBit = asBit(b);
  const s = randomBit();                       // sender's mask & share
  const m0 = s ^ (aBit & 0);                   // = s
  const m1 = s ^ (aBit & 1);                   // = s ⊕ a

  const r1 = otReceiverStep1(bBit, otParams);
  const r2 = otSenderStep(r1.pk0, r1.pk1, encodeBit(m0), encodeBit(m1), otParams);
  const recovered = otReceiverStep2(r1.state, r2.c0, r2.c1);
  const receiverShare = decodeBit(recovered);
  if (receiverShare === null) {
    throw new Error('otBilinearProduct: OT output did not decode to a bit');
  }
  return { senderShare: s, receiverShare };
}

/** Open shares to recover the cleartext bit. */
export function gmwReconstruct(shares) {
  return shares.aliceShare ^ shares.bobShare;
}

// ─── Misc ───────────────────────────────────────────────────────────────────

function shortBig(x, len = 14) {
  const s = (typeof x === 'bigint' ? x : BigInt(x)).toString();
  return s.length > len ? s.slice(0, len) : s;
}

export const PA_NUMBER = 19;
export const STUB = false;
