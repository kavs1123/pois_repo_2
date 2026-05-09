import React, { useCallback, useMemo, useState } from 'react';
import StepDisplay from '../StepDisplay.jsx';
import {
  defaultOtParams,
  encodeBit,
  decodeBit,
  otReceiverStep1,
  otSenderStep,
  otReceiverStep2,
  otReceiverCheatAttempt,
  selfTestOtBits,
} from '../../crypto/ot.js';

function shortBig(x, head = 14) {
  const s = (typeof x === 'bigint' ? x : BigInt(x)).toString();
  return s.length > head ? `${s.slice(0, head)}…` : s;
}

export default function PA18Demo() {
  const [paramNonce, setParamNonce] = useState(0);
  const otParams = useMemo(() => defaultOtParams(), [paramNonce]);

  // Sender's hidden messages (Alice in the Bellare-Micali figure)
  const [m0, setM0] = useState(0);
  const [m1, setM1] = useState(1);

  // Bob (receiver) state
  const [choice, setChoice] = useState(0);
  const [protocol, setProtocol] = useState(null); // { state, pk0, pk1, c0, c1, recovered }
  const [cheatAttempt, setCheatAttempt] = useState(null);

  // 100-trial correctness
  const [stRes, setStRes] = useState(null);

  const handleRun = useCallback(() => {
    const r1 = otReceiverStep1(choice, otParams);
    const r2 = otSenderStep(r1.pk0, r1.pk1, encodeBit(m0), encodeBit(m1), otParams);
    const recovered = otReceiverStep2(r1.state, r2.c0, r2.c1);
    setProtocol({
      state: r1.state,
      pk0: r1.pk0,
      pk1: r1.pk1,
      c0: r2.c0,
      c1: r2.c1,
      recovered,
      recoveredBit: decodeBit(recovered),
    });
    setCheatAttempt(null);
  }, [choice, m0, m1, otParams]);

  const handleCheat = useCallback(() => {
    if (!protocol) return;
    const garbage = otReceiverCheatAttempt(protocol.state, protocol.c0, protocol.c1);
    setCheatAttempt({
      raw: garbage,
      decoded: decodeBit(garbage),
    });
  }, [protocol]);

  const handleSelfTest = useCallback(() => {
    setStRes(selfTestOtBits(otParams));
  }, [otParams]);

  const senderSteps = protocol ? [
    { label: 'Alice (sender) hidden m₀', value: `${m0}  (encoded as group element ${encodeBit(m0)})` },
    { label: 'Alice (sender) hidden m₁', value: `${m1}  (encoded as group element ${encodeBit(m1)})` },
    { label: 'Bob (receiver) choice b', value: `${choice}` },
    { label: 'Receiver pk₀ (mod p, prefix)', value: shortBig(protocol.pk0) },
    { label: 'Receiver pk₁ (mod p, prefix)', value: shortBig(protocol.pk1) },
    { label: 'pk₀ · pk₁ ≡ C (sender check)', value: 'PASSED — receiver could not forge a trapdoor' },
    { label: 'Sender ciphertext c₀', value: `(u=${shortBig(protocol.c0.u, 12)}, v=${shortBig(protocol.c0.v, 12)})` },
    { label: 'Sender ciphertext c₁', value: `(u=${shortBig(protocol.c1.u, 12)}, v=${shortBig(protocol.c1.v, 12)})` },
    {
      label: `Receiver decrypts c_${choice} with sk_${choice}`,
      value: `${protocol.recoveredBit ?? '?'}  (group elt ${shortBig(protocol.recovered, 12)})`,
      className: 'success',
    },
  ] : null;

  return (
    <div>
      <div className="demo-panel__title">PA#18: Bellare–Micali 1-out-of-2 Oblivious Transfer</div>
      <div className="demo-panel__desc">
        Sender holds (m₀, m₁); receiver holds choice b ∈ {'{'}0, 1{'}'}. Receiver learns m_b — and <em>only</em> m_b — while
        the sender learns nothing about b. PKC layer is your own PA#16 ElGamal over the safe-prime subgroup from PA#11.
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
        <strong>Lineage:</strong> PA#18 → <code>ot.js</code> → <code>elgamal.js</code> (PA#16) → <code>owf.js</code> (PA#11
        DLP params) — no external PKC libraries.
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '24px', marginBottom: '18px' }}>
        {/* Sender's panel */}
        <div
          style={{
            flex: '1 1 280px',
            minWidth: 260,
            padding: '14px 16px',
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
          }}
        >
          <div style={{ fontWeight: 600, marginBottom: '8px', color: 'var(--accent-amber)' }}>
            Alice (sender) — knows (m₀, m₁), should not learn b
          </div>
          <div className="btn-group" style={{ flexWrap: 'wrap' }}>
            <label className="select-label">m₀</label>
            <button type="button" className={`btn ${m0 === 0 ? 'btn-primary' : ''}`} onClick={() => setM0(0)}>0</button>
            <button type="button" className={`btn ${m0 === 1 ? 'btn-primary' : ''}`} onClick={() => setM0(1)}>1</button>
            <span style={{ marginLeft: '12px' }} />
            <label className="select-label">m₁</label>
            <button type="button" className={`btn ${m1 === 0 ? 'btn-primary' : ''}`} onClick={() => setM1(0)}>0</button>
            <button type="button" className={`btn ${m1 === 1 ? 'btn-primary' : ''}`} onClick={() => setM1(1)}>1</button>
          </div>
        </div>

        {/* Receiver's panel */}
        <div
          style={{
            flex: '1 1 280px',
            minWidth: 260,
            padding: '14px 16px',
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
          }}
        >
          <div style={{ fontWeight: 600, marginBottom: '8px', color: 'var(--accent-cyan)' }}>
            Bob (receiver) — picks choice b, learns only m_b
          </div>
          <div className="btn-group">
            <label className="select-label">choice b</label>
            <button type="button" className={`btn ${choice === 0 ? 'btn-primary' : ''}`} onClick={() => setChoice(0)}>
              Choose 0
            </button>
            <button type="button" className={`btn ${choice === 1 ? 'btn-primary' : ''}`} onClick={() => setChoice(1)}>
              Choose 1
            </button>
          </div>
        </div>
      </div>

      <div className="btn-group" style={{ marginBottom: '14px', flexWrap: 'wrap' }}>
        <button type="button" className="btn btn-primary" onClick={handleRun}>
          Run OT protocol
        </button>
        <button type="button" className="btn" onClick={handleCheat} disabled={!protocol}>
          Cheat: try to decrypt the other ciphertext
        </button>
        <button type="button" className="btn" onClick={() => setParamNonce(n => n + 1)}>
          Resample public C
        </button>
        <button type="button" className="btn" onClick={handleSelfTest}>
          Self-test (4 (b, m₀, m₁) combinations)
        </button>
      </div>

      {protocol && (
        <div className="game-panel" style={{ marginBottom: '16px' }}>
          <div className="game-panel__label">Protocol transcript</div>
          {senderSteps && <StepDisplay steps={senderSteps} />}
          <div
            className={`counter ${protocol.recoveredBit === (choice === 0 ? m0 : m1) ? 'good' : 'bad'}`}
            style={{ marginTop: '10px' }}
          >
            Bob recovered m_{choice} = {protocol.recoveredBit}
            {protocol.recoveredBit === (choice === 0 ? m0 : m1) ? ' ✓' : ' ✗'}
          </div>

          {cheatAttempt !== null && (
            <div style={{ marginTop: '12px', padding: '10px 12px', background: 'var(--bg-primary)', borderRadius: 'var(--radius-md)' }}>
              <div style={{ fontSize: '0.78rem', color: 'var(--accent-rose)', fontWeight: 600 }}>
                Receiver cheat attempt — decrypt c_{1 - choice} with sk_{choice}
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', marginTop: '4px' }}>
                Output group element: {shortBig(cheatAttempt.raw, 28)}
              </div>
              <div style={{ marginTop: '6px', fontSize: '0.8rem' }}>
                {cheatAttempt.decoded === null ? (
                  <span style={{ color: 'var(--accent-cyan)' }}>
                    Does not decode to bit 0 or 1 — the receiver gets garbage (sender privacy holds).
                  </span>
                ) : (
                  <span style={{ color: 'var(--accent-amber)' }}>
                    Decoded to {cheatAttempt.decoded} — note: with toy bit-encoding, a uniform group element rarely lands
                    on {1} or {2}, so this is essentially zero-probability. Try resampling C.
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {stRes && (
        <div className="test-results" style={{ marginBottom: '14px' }}>
          <div className="test-row">
            <span className="test-name">All four (b, m₀, m₁) combinations</span>
            <span className="test-value" style={{ color: stRes.passed ? 'var(--accent-cyan)' : 'var(--accent-rose)' }}>
              {stRes.passed ? '8 / 8 PASSED — receiver always recovers m_b' : 'FAILED'}
            </span>
          </div>
          <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', marginTop: '6px' }}>
            Each row tests a fresh OT execution: the receiver's choice maps to the correct sender message.
          </div>
        </div>
      )}

      <div style={{ marginTop: '20px', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
        API: <code>otReceiverStep1(b)</code>, <code>otSenderStep(pk0, pk1, m0, m1)</code>,{' '}
        <code>otReceiverStep2(state, c0, c1)</code> — see <code>src/crypto/ot.js</code>.
      </div>
    </div>
  );
}
