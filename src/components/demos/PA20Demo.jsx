import React, { useCallback, useMemo, useState } from 'react';
import StepDisplay from '../StepDisplay.jsx';
import { defaultOtParams } from '../../crypto/ot.js';
import {
  buildMillionaireCircuit,
  buildEqualityCircuit,
  buildAdderCircuit,
  secureEval,
  intToBits,
  bitsToInt,
  lineageTrace,
  runEndToEndSelfTest,
} from '../../crypto/mpc.js';

// 7-bit width so the wealth slider can range up to 100 as the PA#20 spec asks
// (2^7 = 128 ≥ 100). Each AND gate triggers 2 OTs; the millionaire's circuit
// is still well under a second in-browser at this width.
const N_BITS = 7;
const SLIDER_MIN = 1;
const SLIDER_MAX = 100;

const CIRCUITS = [
  { id: 'mill', label: "Millionaire's (x > y)", build: buildMillionaireCircuit, msbFirst: true,
    expected: (x, y) => (x > y ? 1 : 0), describe: (x, y, out) =>
      out === 1 ? `Alice (x=${x}) is richer` : (x === y ? `Equal (x = y = ${x})` : `Bob (y=${y}) is richer`) },
  { id: 'eq', label: 'Equality (x = y)', build: buildEqualityCircuit, msbFirst: false,
    expected: (x, y) => (x === y ? 1 : 0), describe: (x, y, out) =>
      out === 1 ? `x = y = ${x}` : `x ≠ y` },
  { id: 'add', label: 'Bit addition (x + y mod 2ⁿ)', build: buildAdderCircuit, msbFirst: false,
    expected: (x, y) => (x + y) & ((1 << N_BITS) - 1),
    describe: (x, y, out) => `${x} + ${y} ≡ ${out} (mod 2^${N_BITS})` },
];

function bitsForCircuit(value, msbFirst) {
  const lsbBits = intToBits(value, N_BITS);
  return msbFirst ? lsbBits.slice().reverse() : lsbBits;
}

function intFromOutputs(outputs, isAdder) {
  if (isAdder) return bitsToInt(outputs);
  return outputs[0];
}

export default function PA20Demo() {
  const [paramNonce, setParamNonce] = useState(0);
  const otParams = useMemo(() => defaultOtParams(), [paramNonce]);

  const [circuitId, setCircuitId] = useState('mill');
  const circuitDef = CIRCUITS.find(c => c.id === circuitId);
  const circuit = useMemo(() => circuitDef.build(N_BITS), [circuitDef]);

  const [x, setX] = useState(42);
  const [y, setY] = useState(73);
  const [evalRes, setEvalRes] = useState(null);
  const [busy, setBusy] = useState(false);

  const [selfTest, setSelfTest] = useState(null);
  const [selfBusy, setSelfBusy] = useState(false);

  const handleEvaluate = useCallback(() => {
    setBusy(true);
    setTimeout(() => {
      try {
        const xb = bitsForCircuit(x, circuitDef.msbFirst);
        const yb = bitsForCircuit(y, circuitDef.msbFirst);
        const r = secureEval(circuit, xb, yb, otParams);
        const got = intFromOutputs(r.outputs, circuitDef.id === 'add');
        const expected = circuitDef.expected(x, y);
        setEvalRes({
          ...r,
          got,
          expected,
          ok: got === expected,
          message: circuitDef.describe(x, y, got),
        });
      } catch (e) {
        setEvalRes({ error: e.message || String(e) });
      } finally {
        setBusy(false);
      }
    }, 0);
  }, [x, y, circuit, circuitDef, otParams]);

  const handleSelfTest = useCallback(() => {
    setSelfBusy(true);
    setTimeout(() => {
      try {
        setSelfTest(runEndToEndSelfTest());
      } catch (e) {
        setSelfTest({ error: e.message || String(e) });
      } finally {
        setSelfBusy(false);
      }
    }, 0);
  }, []);

  const counts = circuit.countGates();

  // Choose which trace rows to display (cap to avoid noisy output for big circuits).
  const traceRows = evalRes && !evalRes.error
    ? evalRes.trace.slice(0, 24).map((t, i) => ({
        label: `w${t.wire} · ${t.gate}`,
        value: t.detail,
        className: t.cost === '2× OT' ? 'warning' : t.cost === 'free' ? 'success' : '',
      }))
    : null;

  return (
    <div>
      <div className="demo-panel__title">PA#20: All 2-Party MPC via GMW (Yao-style circuit evaluation)</div>
      <div className="demo-panel__desc">
        Wires are GMW-shared between Alice and Bob: w = w_A ⊕ w_B. XOR / NOT are local; each AND triggers two PA#18 OTs.
        End-to-end stack: <strong>PA#20 → PA#19 → PA#18 → PA#16 → PA#11</strong>.
      </div>

      <div
        style={{
          fontSize: '0.72rem',
          color: 'var(--text-secondary)',
          marginBottom: '14px',
          padding: '10px 12px',
          background: 'var(--bg-primary)',
          borderRadius: 'var(--radius-md)',
          lineHeight: 1.45,
        }}
      >
        <strong>Lineage call stack (single AND gate):</strong>{' '}
        {lineageTrace().map(l => `${l.layer} (${l.module})`).join('  →  ')}
      </div>

      {/* Circuit selector */}
      <div className="btn-group" style={{ flexWrap: 'wrap', marginBottom: '14px' }}>
        {CIRCUITS.map(c => (
          <button
            type="button"
            key={c.id}
            className={`btn ${c.id === circuitId ? 'btn-primary' : ''}`}
            onClick={() => { setCircuitId(c.id); setEvalRes(null); }}
          >
            {c.label}
          </button>
        ))}
        <span style={{ flex: 1 }} />
        <button type="button" className="btn" onClick={() => setParamNonce(n => n + 1)}>
          Resample OT parameters
        </button>
      </div>

      {/* Inputs */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '24px', marginBottom: '14px' }}>
        <div style={{ flex: '1 1 240px', minWidth: 220, padding: '14px 16px', background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)' }}>
          <div style={{ fontWeight: 600, marginBottom: '6px', color: 'var(--accent-amber)' }}>
            Alice — x ∈ [{SLIDER_MIN}, {SLIDER_MAX}]
          </div>
          <input
            type="range"
            min={SLIDER_MIN}
            max={SLIDER_MAX}
            value={x}
            onChange={e => setX(parseInt(e.target.value, 10))}
            style={{ width: '100%' }}
          />
          <div style={{ marginTop: '6px', fontFamily: 'var(--font-mono)' }}>
            x = {x} <span style={{ color: 'var(--text-secondary)' }}>(bits LSB→MSB: {intToBits(x, N_BITS).join('')})</span>
          </div>
        </div>
        <div style={{ flex: '1 1 240px', minWidth: 220, padding: '14px 16px', background: 'var(--bg-card)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)' }}>
          <div style={{ fontWeight: 600, marginBottom: '6px', color: 'var(--accent-cyan)' }}>
            Bob — y ∈ [{SLIDER_MIN}, {SLIDER_MAX}]
          </div>
          <input
            type="range"
            min={SLIDER_MIN}
            max={SLIDER_MAX}
            value={y}
            onChange={e => setY(parseInt(e.target.value, 10))}
            style={{ width: '100%' }}
          />
          <div style={{ marginTop: '6px', fontFamily: 'var(--font-mono)' }}>
            y = {y} <span style={{ color: 'var(--text-secondary)' }}>(bits LSB→MSB: {intToBits(y, N_BITS).join('')})</span>
          </div>
        </div>
      </div>

      <div className="btn-group" style={{ marginBottom: '14px', flexWrap: 'wrap' }}>
        <button type="button" className="btn btn-primary" disabled={busy} onClick={handleEvaluate}>
          {busy ? 'Evaluating circuit…' : `Securely evaluate ${circuitDef.label}`}
        </button>
        <button type="button" className="btn" disabled={selfBusy} onClick={handleSelfTest}>
          {selfBusy ? 'Running self-test…' : 'End-to-end self-test (OT + 3 circuits × 4 inputs)'}
        </button>
      </div>

      {/* Circuit shape */}
      <div className="test-results" style={{ marginBottom: '14px' }}>
        <div className="test-row">
          <span className="test-name">Circuit shape</span>
          <span className="test-value">
            {counts.INPUT} inputs · {counts.AND} AND · {counts.XOR} XOR · {counts.NOT} NOT · {circuit.outputs.length} output(s)
          </span>
        </div>
      </div>

      {/* Result */}
      {evalRes && !evalRes.error && (
        <div className="game-panel" style={{ marginBottom: '14px' }}>
          <div className="game-panel__label">Secure evaluation result</div>
          <div style={{ fontSize: '1.1rem', marginBottom: '8px' }}>{evalRes.message}</div>
          <div className={`counter ${evalRes.ok ? 'good' : 'bad'}`}>
            secure={String(evalRes.got)} · cleartext_expected={String(evalRes.expected)} {evalRes.ok ? '✓' : '✗'}
          </div>
          <div style={{ marginTop: '10px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            <strong>OT calls:</strong> {evalRes.stats.otCalls} · <strong>AND gates:</strong> {evalRes.stats.andGates} ·{' '}
            <strong>XOR (free):</strong> {evalRes.stats.xorGates} · <strong>NOT (free):</strong> {evalRes.stats.notGates}
          </div>
          <div style={{ marginTop: '10px', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
            Each party's view of any non-output wire is a uniformly random share — neither learns the other's input.
          </div>

          {traceRows && (
            <details style={{ marginTop: '12px' }}>
              <summary style={{ cursor: 'pointer', fontSize: '0.85rem', color: 'var(--accent-cyan)' }}>
                Gate-by-gate trace ({Math.min(evalRes.trace.length, 24)}{evalRes.trace.length > 24 ? ` of ${evalRes.trace.length}` : ''})
              </summary>
              <StepDisplay steps={traceRows} />
            </details>
          )}
        </div>
      )}

      {evalRes?.error && (
        <div className="counter bad" style={{ marginBottom: '14px' }}>{evalRes.error}</div>
      )}

      {/* Self-test results */}
      {selfTest && !selfTest.error && (
        <div className="test-results" style={{ marginBottom: '12px' }}>
          <div className="test-row">
            <span className="test-name">OT bit-self-test (8 / 8)</span>
            <span className="test-value" style={{ color: selfTest.otOk.passed ? 'var(--accent-cyan)' : 'var(--accent-rose)' }}>
              {selfTest.otOk.passed ? 'PASSED' : 'FAILED'}
            </span>
          </div>
          {selfTest.mill.map((r, i) => (
            <div className="test-row" key={`m-${i}`}>
              <span className="test-name">x &gt; y · x={r.x}, y={r.y}</span>
              <span className="test-value" style={{ color: r.secure === r.expected ? 'var(--accent-cyan)' : 'var(--accent-rose)' }}>
                secure={r.secure} expected={r.expected} · OTs={r.otCalls}
              </span>
            </div>
          ))}
          {selfTest.eq.map((r, i) => (
            <div className="test-row" key={`e-${i}`}>
              <span className="test-name">x = y · x={r.x}, y={r.y}</span>
              <span className="test-value" style={{ color: r.secure === r.expected ? 'var(--accent-cyan)' : 'var(--accent-rose)' }}>
                secure={r.secure} expected={r.expected} · OTs={r.otCalls}
              </span>
            </div>
          ))}
          {selfTest.add.map((r, i) => (
            <div className="test-row" key={`a-${i}`}>
              <span className="test-name">x + y · x={r.x}, y={r.y}</span>
              <span className="test-value" style={{ color: r.secure === r.expected ? 'var(--accent-cyan)' : 'var(--accent-rose)' }}>
                secure={r.secure} expected={r.expected} · OTs={r.otCalls}
              </span>
            </div>
          ))}
          <div className="test-row" style={{ marginTop: '6px' }}>
            <span className="test-name">Overall</span>
            <span className="test-value" style={{ color: selfTest.allPassed ? 'var(--accent-cyan)' : 'var(--accent-rose)' }}>
              {selfTest.allPassed ? 'ALL PASSED' : 'SOME FAILURES'}
            </span>
          </div>
        </div>
      )}

      {selfTest?.error && (
        <div className="counter bad" style={{ marginBottom: '14px' }}>{selfTest.error}</div>
      )}

      <div style={{ marginTop: '18px', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
        API: <code>buildMillionaireCircuit / buildEqualityCircuit / buildAdderCircuit</code>,{' '}
        <code>secureEval(circuit, xAlice, yBob)</code> — see <code>src/crypto/mpc.js</code>.
      </div>
    </div>
  );
}
