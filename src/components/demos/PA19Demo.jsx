import React, { useCallback, useMemo, useState } from 'react';
import StepDisplay from '../StepDisplay.jsx';
import { defaultOtParams } from '../../crypto/ot.js';
import {
  secureAnd,
  secureXor,
  secureNot,
  truthTableAnd,
  truthTableXor,
} from '../../crypto/secure_gates.js';

export default function PA19Demo() {
  const [paramNonce, setParamNonce] = useState(0);
  const otParams = useMemo(() => defaultOtParams(), [paramNonce]);

  const [a, setA] = useState(1);
  const [b, setB] = useState(1);

  const [andRes, setAndRes] = useState(null);
  const [xorRes, setXorRes] = useState(null);
  const [notRes, setNotRes] = useState(null);

  const [andTable, setAndTable] = useState(null);
  const [xorTable, setXorTable] = useState(null);

  const handleAnd = useCallback(() => {
    setAndRes(secureAnd(a, b, otParams));
  }, [a, b, otParams]);

  const handleXor = useCallback(() => {
    setXorRes(secureXor(a, b));
  }, [a, b]);

  const handleNot = useCallback(() => {
    setNotRes(secureNot(a));
  }, [a]);

  const handleRunAll = useCallback(() => {
    setAndTable(truthTableAnd(otParams));
    setXorTable(truthTableXor());
  }, [otParams]);

  return (
    <div>
      <div className="demo-panel__title">PA#19: Secure boolean gates from Oblivious Transfer</div>
      <div className="demo-panel__desc">
        AND uses one PA#18 OT call ({'(m₀, m₁) = (0, a)'}, choice = b → m_b = a∧b). XOR is free via additive masking. NOT
        is a local flip. Together {'{AND, XOR, NOT}'} are functionally complete — PA#20 builds any 2-party MPC on top.
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
        <strong>Lineage:</strong> PA#19 → <code>secure_gates.js</code> → <code>ot.js</code> (PA#18) →{' '}
        <code>elgamal.js</code> (PA#16) → <code>owf.js</code> (PA#11). No external crypto.
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '24px', marginBottom: '18px' }}>
        <div
          style={{
            flex: '1 1 240px',
            minWidth: 220,
            padding: '14px 16px',
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
          }}
        >
          <div style={{ fontWeight: 600, marginBottom: '8px', color: 'var(--accent-amber)' }}>Alice — input bit a</div>
          <div className="btn-group">
            <button type="button" className={`btn ${a === 0 ? 'btn-primary' : ''}`} onClick={() => setA(0)}>0</button>
            <button type="button" className={`btn ${a === 1 ? 'btn-primary' : ''}`} onClick={() => setA(1)}>1</button>
          </div>
        </div>
        <div
          style={{
            flex: '1 1 240px',
            minWidth: 220,
            padding: '14px 16px',
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
          }}
        >
          <div style={{ fontWeight: 600, marginBottom: '8px', color: 'var(--accent-cyan)' }}>Bob — input bit b</div>
          <div className="btn-group">
            <button type="button" className={`btn ${b === 0 ? 'btn-primary' : ''}`} onClick={() => setB(0)}>0</button>
            <button type="button" className={`btn ${b === 1 ? 'btn-primary' : ''}`} onClick={() => setB(1)}>1</button>
          </div>
        </div>
      </div>

      <div className="btn-group" style={{ flexWrap: 'wrap', marginBottom: '14px' }}>
        <button type="button" className="btn btn-primary" onClick={handleAnd}>Compute AND (1 OT)</button>
        <button type="button" className="btn" onClick={handleXor}>Compute XOR (free)</button>
        <button type="button" className="btn" onClick={handleNot}>Compute NOT(a) (local)</button>
        <button type="button" className="btn" onClick={handleRunAll}>Run all 4 (a, b) combos</button>
        <button type="button" className="btn" onClick={() => setParamNonce(n => n + 1)}>Resample OT parameters</button>
      </div>

      {andRes && (
        <div className="game-panel" style={{ marginBottom: '14px' }}>
          <div className="game-panel__label">Secure AND — transcript</div>
          <StepDisplay steps={andRes.transcript} />
          <div className={`counter ${andRes.result === (a & b) ? 'good' : 'bad'}`} style={{ marginTop: '10px' }}>
            Output a ∧ b = {andRes.result} {andRes.result === (a & b) ? '✓' : '✗'}
          </div>
          <div style={{ marginTop: '8px', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
            Privacy — Alice's view in the transcript reveals nothing about b beyond a ∧ b: the only bit she gets back is the
            output. Bob's view (pk's, ciphertexts) reveals nothing about a beyond what is implied by a ∧ b (OT sender privacy).
          </div>
        </div>
      )}

      {xorRes && (
        <div className="game-panel" style={{ marginBottom: '14px' }}>
          <div className="game-panel__label">Secure XOR — transcript</div>
          <StepDisplay steps={xorRes.transcript} />
          <div className={`counter ${xorRes.result === (a ^ b) ? 'good' : 'bad'}`} style={{ marginTop: '10px' }}>
            Output a ⊕ b = {xorRes.result} {xorRes.result === (a ^ b) ? '✓' : '✗'}
          </div>
        </div>
      )}

      {notRes && (
        <div className="game-panel" style={{ marginBottom: '14px' }}>
          <div className="game-panel__label">Secure NOT — local flip</div>
          <StepDisplay steps={notRes.transcript} />
          <div className={`counter ${notRes.result === (a ^ 1) ? 'good' : 'bad'}`} style={{ marginTop: '10px' }}>
            Output ¬a = {notRes.result} {notRes.result === (a ^ 1) ? '✓' : '✗'}
          </div>
        </div>
      )}

      {(andTable || xorTable) && (
        <div className="test-results" style={{ marginBottom: '12px' }}>
          {andTable && (
            <>
              <div className="test-row">
                <span className="test-name">AND truth table (4 OT runs)</span>
                <span className="test-value" style={{ color: andTable.passed ? 'var(--accent-cyan)' : 'var(--accent-rose)' }}>
                  {andTable.passed ? 'PASSED' : 'FAILED'}
                </span>
              </div>
              {andTable.rows.map((r, i) => (
                <div className="test-row" key={`and-${i}`}>
                  <span className="test-name">a={r.a}, b={r.b}</span>
                  <span className="test-value">expected {r.expected}, got {r.got} {r.ok ? '✓' : '✗'}</span>
                </div>
              ))}
            </>
          )}
          {xorTable && (
            <>
              <div className="test-row" style={{ marginTop: '8px' }}>
                <span className="test-name">XOR truth table</span>
                <span className="test-value" style={{ color: xorTable.passed ? 'var(--accent-cyan)' : 'var(--accent-rose)' }}>
                  {xorTable.passed ? 'PASSED' : 'FAILED'}
                </span>
              </div>
              {xorTable.rows.map((r, i) => (
                <div className="test-row" key={`xor-${i}`}>
                  <span className="test-name">a={r.a}, b={r.b}</span>
                  <span className="test-value">expected {r.expected}, got {r.got} {r.ok ? '✓' : '✗'}</span>
                </div>
              ))}
            </>
          )}
        </div>
      )}

      <div style={{ marginTop: '20px', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
        API: <code>secureAnd(a, b)</code>, <code>secureXor(a, b)</code>, <code>secureNot(a)</code>; GMW share variants{' '}
        <code>gmwAnd / gmwXor / gmwNot</code> drive PA#20 — see <code>src/crypto/secure_gates.js</code>.
      </div>
    </div>
  );
}
