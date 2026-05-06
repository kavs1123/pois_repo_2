import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import StepDisplay from '../StepDisplay.jsx';
import {
  elgamalKeygen,
  Enc,
  Dec,
  malleateMultiplyC2,
  ELGAMAL_DEFAULT_PARAMS,
  ELGAMAL_TINY_PARAMS,
  indCpaChallenge,
  indCpaGuessBitTiny,
} from '../../crypto/elgamal.js';
import { modPow } from '../../crypto/utils.js';

function randomBit() {
  return (crypto.getRandomValues(new Uint8Array(1))[0] & 1) === 0 ? 0 : 1;
}

function randomScalarZpq(q) {
  const buf = crypto.getRandomValues(new Uint8Array(32));
  let x = 0n;
  for (const b of buf) x = (x << 8n) | BigInt(b);
  const cap = q > 2n ? q - 1n : 1n;
  return (x % cap) + 1n;
}

function randomDistinctPair(pk) {
  const { p, g, q } = pk;
  let e0 = randomScalarZpq(q);
  let e1 = randomScalarZpq(q);
  let m0 = modPow(g, e0, p);
  let m1 = modPow(g, e1, p);
  let guard = 0;
  while (m1 === m0 && guard++ < 64) {
    e1 = randomScalarZpq(q);
    m1 = modPow(g, e1, p);
  }
  return { m0, m1 };
}

function runCpaLarge(rounds) {
  let correct = 0;
  for (let i = 0; i < rounds; i++) {
    const { pk } = elgamalKeygen(ELGAMAL_DEFAULT_PARAMS);
    const { m0, m1 } = randomDistinctPair(pk);
    const b = randomBit();
    const { c1, c2 } = indCpaChallenge(pk, m0, m1, b);
    const guess = randomBit(); // naive distinguisher
    if (guess === b) correct++;
  }
  const advantage = Math.abs(correct / rounds - 0.5);
  return { rounds, correct, advantage };
}

function runCpaTiny(rounds) {
  let correct = 0;
  for (let i = 0; i < rounds; i++) {
    const { pk } = elgamalKeygen(ELGAMAL_TINY_PARAMS);
    const { m0, m1 } = randomDistinctPair(pk);
    const b = randomBit();
    const { c1, c2 } = indCpaChallenge(pk, m0, m1, b);
    const inferred = indCpaGuessBitTiny(pk, m0, m1, c1, c2);
    const guess = inferred === null ? randomBit() : inferred;
    if (guess === b) correct++;
  }
  const advantage = Math.abs(correct / rounds - 0.5);
  return { rounds, correct, advantage };
}

export default function PA16Demo() {
  const [keyNonce, setKeyNonce] = useState(0);
  const { sk, pk } = useMemo(() => elgamalKeygen(ELGAMAL_DEFAULT_PARAMS), [keyNonce]);

  const countedMalKeyRef = useRef(null);

  useEffect(() => {
    setCt(null);
    setMalCt(null);
    setDecOriginal(null);
    setDecMalleated(null);
    setMallSteps(null);
    setOracleNote(null);
    setMallHits(0);
    countedMalKeyRef.current = null;
  }, [keyNonce]);

  const [mStr, setMStr] = useState('42');
  const [ct, setCt] = useState(null);
  const [malCt, setMalCt] = useState(null);
  const [decOriginal, setDecOriginal] = useState(null);
  const [decMalleated, setDecMalleated] = useState(null);
  const [mallHits, setMallHits] = useState(0);
  const [mallSteps, setMallSteps] = useState(null);

  const [cpaLargeRes, setCpaLargeRes] = useState(null);
  const [cpaTinyRes, setCpaTinyRes] = useState(null);
  const [cpaBusy, setCpaBusy] = useState(false);
  const [oracleNote, setOracleNote] = useState(null);

  const parsePlaintext = useCallback(() => {
    const t = mStr.trim();
    if (!t) throw new Error('Enter a plaintext integer.');
    const v = BigInt(t);
    if (v <= 0n || v >= pk.p) throw new Error(`Plaintext must satisfy 1 ≤ m < p (p has ${pk.p.toString(2).length} bits).`);
    return v;
  }, [mStr, pk.p]);

  const handleEncrypt = useCallback(() => {
    const m = parsePlaintext();
    const { c1, c2 } = Enc(pk, m);
    setCt({ c1, c2 });
    setMalCt(null);
    setDecOriginal(null);
    setDecMalleated(null);
    setMallSteps(null);
    setOracleNote(null);
    countedMalKeyRef.current = null;
  }, [parsePlaintext, pk]);

  const handleMultiplyC2 = useCallback(() => {
    if (!ct) return;
    const next = malleateMultiplyC2(ct.c1, ct.c2, 2n, pk.p);
    setMalCt(next);
    setDecMalleated(null);
    setOracleNote(null);
    setMallSteps([
      { label: 'Original C', value: `(c₁, c₂) = (${ct.c1}, ${ct.c2})` },
      { label: 'Malleated', value: `(c₁, 2·c₂ mod p) = (${next.c1}, ${next.c2})` },
      {
        label: 'Property',
        value: 'Same c₁ —oracle cannot tell we tweaked only c₂ until decryption.',
      },
    ]);
  }, [ct, pk.p]);

  const handleDecryptOriginal = useCallback(() => {
    if (!ct) return;
    const m = Dec(sk, ct.c1, ct.c2, pk.p);
    setDecOriginal(m);
  }, [ct, sk, pk.p]);

  const handleDecryptMalleated = useCallback(() => {
    if (!malCt || !ct) return;
    const m0 = Dec(sk, ct.c1, ct.c2, pk.p);
    const m2 = Dec(sk, malCt.c1, malCt.c2, pk.p);
    setDecOriginal(m0);
    setDecMalleated(m2);
    const expected = (2n * m0) % pk.p;
    const ok = m2 === expected;
    const malKey = `${malCt.c1}-${malCt.c2}`;
    if (ok && countedMalKeyRef.current !== malKey) {
      countedMalKeyRef.current = malKey;
      setMallHits(h => h + 1);
    }
    setOracleNote(
      ok
        ? 'Decryption oracle returned 2·m — this is exactly what a CCA adversary learns from a decryption oracle on the tweaked ciphertext.'
        : 'Unexpected mismatch (report as bug).'
    );
  }, [malCt, ct, sk, pk.p]);

  const handleRunCpaLarge = useCallback(() => {
    setCpaBusy(true);
    setTimeout(() => {
      setCpaLargeRes(runCpaLarge(48));
      setCpaBusy(false);
    }, 0);
  }, []);

  const handleRunCpaTiny = useCallback(() => {
    setCpaBusy(true);
    setTimeout(() => {
      setCpaTinyRes(runCpaTiny(48));
      setCpaBusy(false);
    }, 0);
  }, []);

  const bitLen = pk.p.toString(2).length;
  const qBits = pk.q.toString(2).length;

  return (
    <div>
      <div className="demo-panel__title">PA#16: ElGamal public-key encryption</div>
      <div className="demo-panel__desc">
        CPA security under DDH; textbook ElGamal is <strong>malleable</strong>: (c₁, k·c₂) decrypts to k·m mod p.
        Subgroup generator g′ = g² mod p (order q) from the PA#11 safe-prime parameters.
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '28px', alignItems: 'flex-start' }}>
        {/* ── Malleability column (avoid stacking over the side panel on narrow layouts) ── */}
        <div style={{ flex: '1 1 340px', minWidth: 280, position: 'relative', zIndex: 1 }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '10px' }}>
            |p| ≈ {bitLen} bits · |q| ≈ {qBits} bits ·{' '}
            <button type="button" className="btn" style={{ padding: '2px 8px', fontSize: '0.75rem' }} onClick={() => setKeyNonce(n => n + 1)}>
              New keypair
            </button>
          </div>

          <div className="hex-input-wrapper">
            <label className="select-label">Plaintext m (integer in ℤₚ*)</label>
            <input className="hex-input" type="text" inputMode="numeric" value={mStr} onChange={e => setMStr(e.target.value)} />
          </div>

          <div className="btn-group" style={{ flexWrap: 'wrap' }}>
            <button type="button" className="btn btn-primary" onClick={handleEncrypt}>
              Encrypt
            </button>
            <button type="button" className="btn" onClick={handleDecryptOriginal} disabled={!ct}>
              Decrypt original
            </button>
          </div>

          {ct && (
            <div style={{ marginTop: '12px', marginBottom: '12px' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Ciphertext</div>
              <div className="test-value" style={{ fontFamily: 'var(--font-mono)', wordBreak: 'break-all', fontSize: '0.8rem' }}>
                c₁ = {ct.c1.toString()}
                <br />
                c₂ = {ct.c2.toString()}
              </div>
            </div>
          )}

          {decOriginal !== null && ct && (
            <div style={{ marginBottom: '12px' }}>
              <span className="test-name">Dec(c₁, c₂)</span>{' '}
              <span className="test-value">{decOriginal.toString()}</span>
            </div>
          )}

          <div className="btn-group">
            <button type="button" className="btn btn-primary" onClick={handleMultiplyC2} disabled={!ct}>
              Multiply c₂ by 2
            </button>
            <button type="button" className="btn" onClick={handleDecryptMalleated} disabled={!malCt}>
              Decrypt (oracle on tweaked CT)
            </button>
          </div>

          {mallSteps && <StepDisplay steps={mallSteps} />}

          {malCt && decMalleated !== null && decOriginal !== null && (
            <div className="game-panel" style={{ marginTop: '14px' }}>
              <div className="game-panel__label">Malleability check</div>
              <div style={{ fontSize: '0.85rem', lineHeight: 1.5 }}>
                <div>
                  <code>Dec(c₁, 2·c₂)</code> = <strong>{decMalleated.toString()}</strong>
                </div>
                <div>
                  <code>2 · Dec(c₁, c₂) mod p</code> = <strong>{((2n * decOriginal) % pk.p).toString()}</strong>
                </div>
              </div>
              <div className={`counter ${decMalleated === ((2n * decOriginal) % pk.p) ? 'good' : 'bad'}`} style={{ marginTop: '10px' }}>
                {decMalleated === ((2n * decOriginal) % pk.p)
                  ? 'Dec(c₁, 2·c₂) = 2·m — relation holds'
                  : 'Mismatch'}
              </div>
              <div style={{ marginTop: '10px', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                Successful malleability demos (relation verified):{' '}
                <strong style={{ color: 'var(--accent-cyan)' }}>{mallHits}</strong>
              </div>
            </div>
          )}

          {oracleNote && (
            <p style={{ marginTop: '12px', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>{oracleNote}</p>
          )}
        </div>

        {/* ── CCA note (side panel) ── */}
        <div
          style={{
            flex: '1 1 280px',
            minWidth: 260,
            borderLeft: '1px solid var(--border-subtle)',
            paddingLeft: '24px',
            position: 'relative',
            zIndex: 2,
          }}
        >
          <div className="demo-panel__title" style={{ fontSize: '1rem', marginBottom: '8px' }}>
            Why not CCA?
          </div>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
            A decryption oracle accepts any valid-looking pair (c₁, c₂). After encrypting m, query the oracle on (c₁, 2·c₂): you
            receive <code>2·m mod p</code> without knowing the secret key — textbook ElGamal fails IND-CCA2.
          </p>
        </div>
      </div>

      {/* Full-width CPA block so buttons are never covered by the taller malleability column */}
      <div
        className="pa16-cpa-block"
        style={{
          marginTop: '24px',
          paddingTop: '20px',
          borderTop: '1px solid var(--border-subtle)',
          position: 'relative',
          zIndex: 2,
        }}
      >
        <div className="demo-panel__title" style={{ fontSize: '1rem', marginBottom: '8px' }}>
          IND-CPA simulation
        </div>
        <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '12px', maxWidth: '720px' }}>
          Challenger encrypts m_b for random b ∈ {'{'}0,1{'}'}. A <em>naive</em> random guess has advantage ≈ 0 on large q (DDH
          toy). With tiny q ≈ 2¹⁰, brute-force recovery of r breaks indistinguishability. Only <strong>click the buttons</strong>{' '}
          below (not this paragraph).
        </p>

        <div className="btn-group pa16-cpa-buttons" style={{ flexDirection: 'column', alignItems: 'stretch', maxWidth: '560px' }}>
          <button
            type="button"
            className="btn"
            disabled={cpaBusy}
            onClick={handleRunCpaLarge}
            style={{ minHeight: '44px', justifyContent: 'center' }}
          >
            Run 48 rounds — large q (~{qBits} bits), random guess
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={cpaBusy}
            onClick={handleRunCpaTiny}
            style={{ minHeight: '44px', justifyContent: 'center' }}
          >
            Run 48 rounds — tiny q (~{ELGAMAL_TINY_PARAMS.q.toString(2).length} bits), brute-force distinguisher
          </button>
        </div>

        {cpaBusy && (
          <p style={{ fontSize: '0.8rem', color: 'var(--accent-amber)', marginTop: '10px' }}>Running 48-round simulation…</p>
        )}

        {cpaLargeRes && (
          <div className="test-results" style={{ marginTop: '14px', maxWidth: '560px' }}>
            <div className="test-row">
              <span className="test-name">Large q</span>
              <span className="test-value">
                Correct bit rate {((cpaLargeRes.correct / cpaLargeRes.rounds) * 100).toFixed(1)}% · |adv| ≈{' '}
                {cpaLargeRes.advantage.toFixed(3)}
              </span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '6px' }}>
              With only 48 rounds, rates swing around 50% (e.g. 58% vs 42%) — that is normal variance for a coin-flip adversary,
              not a bug.
            </div>
          </div>
        )}

        {cpaTinyRes && (
          <div className="test-results" style={{ marginTop: '14px', maxWidth: '560px' }}>
            <div className="test-row">
              <span className="test-name">Tiny q</span>
              <span className="test-value">
                Correct bit rate {((cpaTinyRes.correct / cpaTinyRes.rounds) * 100).toFixed(1)}% · |adv| ≈{' '}
                {cpaTinyRes.advantage.toFixed(3)}
              </span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '6px' }}>
              Brute force over r ∈ ℤ_q recovers m ∈ {'{'}m₀, m₁{'}'} — distinguisher approaches optimal (~100% correct).
            </div>
          </div>
        )}
      </div>

      <div style={{ marginTop: '22px', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
        PA#17 API: <code>Enc(pk, m)</code> → <code>{'{'} c1, c2 {'}'}</code>,{' '}
        <code>Dec(sk, c1, c2, pk.p)</code> → <code>m</code> — see <code>src/crypto/elgamal.js</code>.
      </div>
    </div>
  );
}
