/**
 * PA#20: All 2-Party Secure Computation (GMW protocol).
 *
 * Lineage:
 *   PA#20 → PA#19 secure gates (`secure_gates.js`)
 *         → PA#18 OT (`ot.js`)
 *         → PA#16 ElGamal (`elgamal.js`) → PA#11 DLP (`owf.js`)
 *
 * A boolean Circuit is a DAG of gates. Inputs are assigned to either Alice or
 * Bob; intermediate wires are kept secret-shared between them via GMW. XOR
 * and NOT are local; AND triggers two OT calls (one per cross term). Output
 * wires are reconstructed by exchanging shares.
 *
 * Three test circuits are provided (Millionaire's, equality, n-bit addition).
 */

import {
  defaultOtParams,
  selfTestOtBits,
} from './ot.js';
import {
  gmwShareInput,
  gmwXor,
  gmwNot,
  gmwAnd,
  gmwReconstruct,
} from './secure_gates.js';

// ─── Circuit representation ─────────────────────────────────────────────────
//
// A circuit is an array of nodes, indexed implicitly by position. Each node:
//   { type: 'INPUT', owner: 'alice'|'bob', label }
//   { type: 'XOR' | 'AND' | 'NOT', inputs: [wireIdx, ...] }
// Plus a list of output wire indices.
//
// Wires are referenced by their integer index = position of the producing node.

export class Circuit {
  constructor() {
    this.nodes = [];
    this.outputs = [];
  }

  addInput(owner, label = null) {
    const idx = this.nodes.length;
    this.nodes.push({ type: 'INPUT', owner, label: label ?? `${owner}_in${idx}` });
    return idx;
  }

  addAnd(x, y) {
    return this._addGate('AND', [x, y]);
  }

  addXor(x, y) {
    return this._addGate('XOR', [x, y]);
  }

  addNot(x) {
    return this._addGate('NOT', [x]);
  }

  /** OR(x,y) = NOT(AND(NOT x, NOT y)) — exposed for circuit-builder convenience. */
  addOr(x, y) {
    const nx = this.addNot(x);
    const ny = this.addNot(y);
    const both = this.addAnd(nx, ny);
    return this.addNot(both);
  }

  setOutputs(outputs) {
    this.outputs = Array.isArray(outputs) ? [...outputs] : [outputs];
    return this;
  }

  _addGate(type, inputs) {
    for (const w of inputs) {
      if (w < 0 || w >= this.nodes.length) {
        throw new Error(`Circuit._addGate: input wire ${w} is undefined`);
      }
    }
    const idx = this.nodes.length;
    this.nodes.push({ type, inputs });
    return idx;
  }

  /** Cleartext (insecure) evaluation — used as ground truth for tests. */
  evalCleartext(aliceBits, bobBits) {
    const aQueue = [...aliceBits];
    const bQueue = [...bobBits];
    const wires = new Array(this.nodes.length);
    for (let i = 0; i < this.nodes.length; i++) {
      const n = this.nodes[i];
      if (n.type === 'INPUT') {
        if (n.owner === 'alice') {
          if (aQueue.length === 0) throw new Error('evalCleartext: not enough Alice inputs');
          wires[i] = aQueue.shift() & 1;
        } else {
          if (bQueue.length === 0) throw new Error('evalCleartext: not enough Bob inputs');
          wires[i] = bQueue.shift() & 1;
        }
      } else if (n.type === 'AND') {
        wires[i] = wires[n.inputs[0]] & wires[n.inputs[1]];
      } else if (n.type === 'XOR') {
        wires[i] = wires[n.inputs[0]] ^ wires[n.inputs[1]];
      } else if (n.type === 'NOT') {
        wires[i] = wires[n.inputs[0]] ^ 1;
      } else {
        throw new Error(`evalCleartext: unknown gate type ${n.type}`);
      }
    }
    return this.outputs.map(w => wires[w]);
  }

  countGates() {
    const counts = { INPUT: 0, AND: 0, XOR: 0, NOT: 0 };
    for (const n of this.nodes) counts[n.type] = (counts[n.type] || 0) + 1;
    return counts;
  }
}

// ─── Secure GMW evaluator ────────────────────────────────────────────────────

/**
 * Securely evaluate a circuit.
 *
 *   xAlice — Alice's input bits, in the order of her INPUT nodes.
 *   yBob   — Bob's input bits,   in the order of his INPUT nodes.
 *
 * Returns the output bits (computed by reconstructing both parties' shares
 * for each output wire), plus a transcript and gate-by-gate trace.
 */
export function secureEval(circuit, xAlice, yBob, otParams = defaultOtParams()) {
  const aliceQueue = [...xAlice];
  const bobQueue = [...yBob];

  // Each wire is held as { aliceShare, bobShare } with XOR = wire value.
  const shares = new Array(circuit.nodes.length);
  const trace = [];
  let otCalls = 0;
  let andCount = 0;
  let xorCount = 0;
  let notCount = 0;

  for (let i = 0; i < circuit.nodes.length; i++) {
    const n = circuit.nodes[i];
    if (n.type === 'INPUT') {
      let v;
      if (n.owner === 'alice') {
        if (aliceQueue.length === 0) throw new Error('secureEval: not enough Alice inputs');
        v = aliceQueue.shift() & 1;
      } else {
        if (bobQueue.length === 0) throw new Error('secureEval: not enough Bob inputs');
        v = bobQueue.shift() & 1;
      }
      shares[i] = gmwShareInput(v, n.owner);
      trace.push({
        wire: i,
        gate: `INPUT(${n.owner})`,
        detail: `share-input → (a:${shares[i].aliceShare}, b:${shares[i].bobShare})`,
        cost: 'local',
      });
    } else if (n.type === 'XOR') {
      shares[i] = gmwXor(shares[n.inputs[0]], shares[n.inputs[1]]);
      xorCount++;
      trace.push({
        wire: i,
        gate: `XOR(w${n.inputs[0]}, w${n.inputs[1]})`,
        detail: `local: shares (a:${shares[i].aliceShare}, b:${shares[i].bobShare})`,
        cost: 'free',
      });
    } else if (n.type === 'NOT') {
      shares[i] = gmwNot(shares[n.inputs[0]]);
      notCount++;
      trace.push({
        wire: i,
        gate: `NOT(w${n.inputs[0]})`,
        detail: `local flip on Alice's share → (a:${shares[i].aliceShare}, b:${shares[i].bobShare})`,
        cost: 'free',
      });
    } else if (n.type === 'AND') {
      const out = gmwAnd(shares[n.inputs[0]], shares[n.inputs[1]], otParams);
      shares[i] = { aliceShare: out.aliceShare, bobShare: out.bobShare };
      andCount++;
      otCalls += out.otCalls;
      trace.push({
        wire: i,
        gate: `AND(w${n.inputs[0]}, w${n.inputs[1]})`,
        detail: `2 OTs → shares (a:${out.aliceShare}, b:${out.bobShare})`,
        cost: '2× OT',
      });
    } else {
      throw new Error(`secureEval: unknown gate type ${n.type}`);
    }
  }

  // Output reconstruction: each party publishes their share of each output wire.
  const outputs = circuit.outputs.map(w => gmwReconstruct(shares[w]));

  return {
    outputs,
    trace,
    stats: { otCalls, andGates: andCount, xorGates: xorCount, notGates: notCount },
    shares,
  };
}

// ─── Privacy / simulator-style transcript view (PA#20 spec item 4) ──────────
//
// The protocol transcript consists of, for each AND gate, two OT executions.
// Each OT exposes {pk0, pk1, c0, c1}. Crucially:
//   • The masks (sender's randomness s) are uniform & not in the transcript.
//   • The OT messages decoded via the unintended sk_b are uniformly distributed
//     in the group (`otReceiverCheatAttempt`), so a party's view of the *other*
//     party's share is independent of the other party's input.
// A simulator therefore only needs the output bits to reproduce the marginal
// view of each party.  We expose a helper that enumerates each party's view
// so the demo can visualise this property.

export function partyViewAlice(secureEvalResult) {
  return secureEvalResult.shares.map((s, i) => ({ wire: i, share: s.aliceShare }));
}

export function partyViewBob(secureEvalResult) {
  return secureEvalResult.shares.map((s, i) => ({ wire: i, share: s.bobShare }));
}

// ─── Test circuit #1: Millionaire's problem (x > y over n-bit unsigned) ────
//
// Greater-than circuit. Process bits MSB → LSB and maintain two state bits:
//   eq  — all bits seen so far are equal
//   gt  — x is strictly greater (decided at the first differing bit)
// Update at each bit i:
//   gt'  = gt ∨ (eq ∧ x_i ∧ ¬y_i)        // first time x_i > y_i seen while equal
//   eq'  = eq ∧ ¬(x_i ⊕ y_i)              // still equal iff x_i = y_i
// Initial: gt = 0, eq = 1.

export function buildMillionaireCircuit(nBits) {
  const c = new Circuit();
  const xWires = [];
  const yWires = [];
  // Inputs MSB first
  for (let i = 0; i < nBits; i++) xWires.push(c.addInput('alice', `x${nBits - 1 - i}`));
  for (let i = 0; i < nBits; i++) yWires.push(c.addInput('bob', `y${nBits - 1 - i}`));

  // gt = 0 (x0 ⊕ x0); eq = 1 (NOT(x0 ⊕ x0))
  const zero = c.addXor(xWires[0], xWires[0]);
  let gt = zero;
  let eq = c.addNot(zero);

  for (let i = 0; i < nBits; i++) {
    const xi = xWires[i];
    const yi = yWires[i];
    const notYi = c.addNot(yi);
    const xi_and_notYi = c.addAnd(xi, notYi);                // strict-greater this bit
    const eqStrict = c.addAnd(eq, xi_and_notYi);             // … given still-equal so far
    gt = c.addOr(gt, eqStrict);

    const eqBit = c.addNot(c.addXor(xi, yi));                // 1 iff x_i = y_i
    eq = c.addAnd(eq, eqBit);
  }
  c.setOutputs([gt]);
  return c;
}

// ─── Test circuit #2: bitwise equality (x = y) ─────────────────────────────

export function buildEqualityCircuit(nBits) {
  const c = new Circuit();
  const xs = [];
  const ys = [];
  for (let i = 0; i < nBits; i++) xs.push(c.addInput('alice', `x${i}`));
  for (let i = 0; i < nBits; i++) ys.push(c.addInput('bob', `y${i}`));
  // eq = AND_i ¬(x_i ⊕ y_i)
  let eq = c.addNot(c.addXor(xs[0], ys[0]));
  for (let i = 1; i < nBits; i++) {
    const eqI = c.addNot(c.addXor(xs[i], ys[i]));
    eq = c.addAnd(eq, eqI);
  }
  c.setOutputs([eq]);
  return c;
}

// ─── Test circuit #3: n-bit addition (mod 2^n) ─────────────────────────────
//
// Ripple-carry adder with full-adder cells:
//   sum_i  = x_i ⊕ y_i ⊕ c_i
//   c_{i+1} = (x_i ∧ y_i) ⊕ ((x_i ⊕ y_i) ∧ c_i)

export function buildAdderCircuit(nBits) {
  const c = new Circuit();
  const xs = [];
  const ys = [];
  for (let i = 0; i < nBits; i++) xs.push(c.addInput('alice', `x${i}`));
  for (let i = 0; i < nBits; i++) ys.push(c.addInput('bob', `y${i}`));

  // initial carry = 0 = x0 ⊕ x0
  let carry = c.addXor(xs[0], xs[0]);
  const sums = [];
  for (let i = 0; i < nBits; i++) {
    const xy = c.addXor(xs[i], ys[i]);
    const sumI = c.addXor(xy, carry);
    const xAndY = c.addAnd(xs[i], ys[i]);
    const xy_and_carry = c.addAnd(xy, carry);
    carry = c.addXor(xAndY, xy_and_carry);
    sums.push(sumI);
  }
  c.setOutputs(sums);
  return c;
}

// ─── Helpers for integer ↔ bit list (LSB first) ────────────────────────────

export function intToBits(value, nBits) {
  const v = value | 0;
  const out = [];
  for (let i = 0; i < nBits; i++) out.push((v >> i) & 1);
  return out;
}

export function bitsToInt(bits) {
  let v = 0;
  for (let i = 0; i < bits.length; i++) v |= ((bits[i] & 1) << i);
  return v;
}

// ─── Lineage trace (PA#20 spec item 5) ─────────────────────────────────────

export function lineageTrace() {
  return [
    { layer: 'PA#20', module: 'mpc.js', call: 'secureEval(circuit, x, y)' },
    { layer: 'PA#19', module: 'secure_gates.js', call: 'gmwAnd(xS, yS) — invokes 2×OT' },
    { layer: 'PA#18', module: 'ot.js', call: 'otReceiverStep1 → otSenderStep → otReceiverStep2' },
    { layer: 'PA#16', module: 'elgamal.js', call: 'modPow / modInverse for ElGamal-style ciphertexts' },
    { layer: 'PA#11', module: 'owf.js (DLP_PARAMS)', call: 'safe-prime subgroup G = ⟨g⟩' },
    { layer: 'PA#13', module: 'prime.js', call: 'Miller–Rabin (used to generate the safe prime ahead of time)' },
  ];
}

// ─── Combined self-test (used by demo "All-OK" indicator) ──────────────────

export function runEndToEndSelfTest() {
  const otParams = defaultOtParams();
  const otOk = selfTestOtBits(otParams);

  const millCirc = buildMillionaireCircuit(4);
  const eqCirc = buildEqualityCircuit(4);
  const addCirc = buildAdderCircuit(4);

  const samples = [
    { x: 7, y: 12 },
    { x: 13, y: 5 },
    { x: 9, y: 9 },
    { x: 0, y: 1 },
  ];

  const millResults = samples.map(({ x, y }) => {
    const xb = intToBits(x, 4); xb.reverse(); // MSB first for builder above
    const yb = intToBits(y, 4); yb.reverse();
    const r = secureEval(millCirc, xb, yb, otParams);
    return { x, y, secure: r.outputs[0], expected: x > y ? 1 : 0, otCalls: r.stats.otCalls };
  });

  const eqResults = samples.map(({ x, y }) => {
    const xb = intToBits(x, 4);
    const yb = intToBits(y, 4);
    const r = secureEval(eqCirc, xb, yb, otParams);
    return { x, y, secure: r.outputs[0], expected: x === y ? 1 : 0, otCalls: r.stats.otCalls };
  });

  const addResults = samples.map(({ x, y }) => {
    const xb = intToBits(x, 4);
    const yb = intToBits(y, 4);
    const r = secureEval(addCirc, xb, yb, otParams);
    const got = bitsToInt(r.outputs);
    return { x, y, secure: got, expected: (x + y) & 0xf, otCalls: r.stats.otCalls };
  });

  return {
    otOk,
    mill: millResults,
    eq: eqResults,
    add: addResults,
    allPassed:
      otOk.passed &&
      millResults.every(r => r.secure === r.expected) &&
      eqResults.every(r => r.secure === r.expected) &&
      addResults.every(r => r.secure === r.expected),
  };
}

export const PA_NUMBER = 20;
export const STUB = false;
