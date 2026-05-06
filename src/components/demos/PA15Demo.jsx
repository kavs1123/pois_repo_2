import React, { useCallback, useEffect, useMemo, useState } from 'react';
import StepDisplay from '../StepDisplay.jsx';
import {
  rsaKeyGen,
  Sign,
  verifyWithTrace,
  sigmaToHex,
  sigmaFromHex,
  createEufCmaChallenger,
  rawRsaMultiplicativeForge,
  rawProductRepresentative,
  sigmaByteLength,
} from '../../crypto/rsa_sig.js';
import { bytesToHex, randomBytes, stringToBytes, bytesToString, bigIntToBytes } from '../../crypto/utils.js';

/** Modulus size for responsive browser keygen (still uses Miller–Rabin primes). */
const DEMO_RSA_BITS = 448;
const MR_ROUNDS = 16;
const ORACLE_QUERIES = 50;

export default function PA15Demo() {
  const [keyNonce, setKeyNonce] = useState(0);
  const [keys, setKeys] = useState(null);
  const [keyError, setKeyError] = useState(null);
  const [keyLoading, setKeyLoading] = useState(true);

  useEffect(() => {
    setOracleLog([]);
    setForgeOutcome(null);
    setSigmaHex('');
    setVerifySteps(null);
  }, [keys?.N]);

  useEffect(() => {
    let alive = true;
    setKeyLoading(true);
    setKeys(null);
    setKeyError(null);
    const t = setTimeout(() => {
      try {
        const k = rsaKeyGen(DEMO_RSA_BITS, MR_ROUNDS);
        if (alive) {
          setKeys(k);
          setKeyLoading(false);
        }
      } catch (err) {
        if (alive) {
          setKeyError(err.message || String(err));
          setKeyLoading(false);
        }
      }
    }, 50);
    return () => {
      alive = false;
      clearTimeout(t);
    };
  }, [keyNonce]);

  const [rawSignMode, setRawSignMode] = useState(false);
  const [message, setMessage] = useState('hello PA#15');
  const [sigmaHex, setSigmaHex] = useState('');
  const [verifySteps, setVerifySteps] = useState(null);
  const [lastSignedBytes, setLastSignedBytes] = useState(null);

  const [m1, setM1] = useState('alpha');
  const [m2, setM2] = useState('beta');
  const [rawForgeResult, setRawForgeResult] = useState(null);

  const [eufGameId, setEufGameId] = useState(0);
  const challenger = useMemo(() => {
    if (!keys) return null;
    return createEufCmaChallenger(keys.sk, keys.vk, { maxQueries: ORACLE_QUERIES, useHash: true });
  }, [keys, eufGameId]);

  const [oracleLog, setOracleLog] = useState([]);
  const [forgeMsg, setForgeMsg] = useState('unseen');
  const [forgeSigmaHex, setForgeSigmaHex] = useState('');
  const [forgeOutcome, setForgeOutcome] = useState(null);

  const messageBytes = useMemo(() => stringToBytes(message), [message]);

  const handleSign = useCallback(() => {
    if (!keys) return;
    const bytes = stringToBytes(message);
    const { sigma } = Sign(keys.sk, bytes, { useHash: !rawSignMode });
    setSigmaHex(sigmaToHex(sigma, keys.N));
    setLastSignedBytes(bytes.slice());
    setVerifySteps(null);
  }, [keys, message, rawSignMode]);

  const handleVerify = useCallback(() => {
    if (!keys || !sigmaHex.trim()) return;
    const sigma = sigmaFromHex(sigmaHex, keys.N);
    const trace = verifyWithTrace(keys.vk, messageBytes, sigma, { useHash: !rawSignMode });
    const steps = [
      {
        label: rawSignMode ? 'm mod N (representative)' : 'H(m) digest (hex)',
        value: rawSignMode
          ? trace.representative.toString()
          : trace.digestHex || '(hash)',
      },
      { label: 'Representative mod N', value: trace.representative.toString() },
      { label: 'σ (parsed)', value: sigma.toString() },
      { label: 'σ^e mod N', value: trace.sigmaPowE.toString() },
      {
        label: 'Check',
        value: `${trace.sigmaPowE} ${trace.valid ? '==' : '≠'} ${trace.representative}`,
        className: trace.valid ? 'success' : 'error',
      },
    ];
    setVerifySteps({ trace, steps });
  }, [keys, sigmaHex, messageBytes, rawSignMode]);

  const handleTamper = useCallback(() => {
    if (!lastSignedBytes) return;
    const tampered = lastSignedBytes.slice();
    tampered[0] ^= 1;
    setMessage(bytesToString(tampered));
    setVerifySteps(null);
  }, [lastSignedBytes]);

  const handleRawForgeryDemo = useCallback(() => {
    if (!keys) return;
    const b1 = stringToBytes(m1);
    const b2 = stringToBytes(m2);
    const { sigma: s1 } = Sign(keys.sk, b1, { useHash: false });
    const { sigma: s2 } = Sign(keys.sk, b2, { useHash: false });
    const sigmaStar = rawRsaMultiplicativeForge(s1, s2, keys.N);
    const repStar = rawProductRepresentative(b1, b2, keys.N);
    const len = sigmaByteLength(keys.N);
    const forgedMsgBytes = bigIntToBytes(repStar, len);
    const valid = verifyWithTrace(keys.vk, forgedMsgBytes, sigmaStar, { useHash: false }).valid;
    setRawForgeResult({
      sigma1Hex: sigmaToHex(s1, keys.N),
      sigma2Hex: sigmaToHex(s2, keys.N),
      sigmaStarHex: sigmaToHex(sigmaStar, keys.N),
      repStar: repStar.toString(),
      forgedMsgHex: bytesToHex(forgedMsgBytes),
      valid,
    });
  }, [keys, m1, m2]);

  const handleFillOracle = useCallback(() => {
    if (!challenger) return;
    const rows = [];
    for (let i = 0; i < ORACLE_QUERIES; i++) {
      const msg = randomBytes(12 + (i % 5));
      const sigma = challenger.signingOracle(msg);
      rows.push({ msgHex: bytesToHex(msg), sigmaHex: sigmaToHex(sigma, keys.N) });
    }
    setOracleLog(rows);
    setForgeOutcome(null);
  }, [challenger, keys]);

  const handleSubmitForgery = useCallback(() => {
    if (!challenger || !keys) return;
    const bytes = stringToBytes(forgeMsg);
    const sigma = forgeSigmaHex.trim() ? sigmaFromHex(forgeSigmaHex, keys.N) : 0n;
    const result = challenger.checkForgery(bytes, sigma);
    setForgeOutcome(result);
  }, [challenger, keys, forgeMsg, forgeSigmaHex]);

  const handleRandomForgeryGuess = useCallback(() => {
    if (!challenger || !keys) return;
    const bytes = randomBytes(14);
    const sigma = bytesToBigInt(randomBytes(sigmaByteLength(keys.N))) % keys.N;
    const result = challenger.checkForgery(bytes, sigma);
    setForgeMsg(bytesToString(bytes));
    setForgeSigmaHex(sigmaToHex(sigma, keys.N));
    setForgeOutcome(result);
  }, [challenger, keys]);

  if (keyLoading) {
    return (
      <div>
        <div className="demo-panel__title">PA#15: Digital Signatures (RSA)</div>
        <p className="demo-panel__desc">Generating RSA modulus ({DEMO_RSA_BITS} bits, Miller–Rabin primes)…</p>
      </div>
    );
  }

  if (keyError || !keys) {
    return (
      <div>
        <div className="demo-panel__title">PA#15: Digital Signatures (RSA)</div>
        <p className="demo-panel__desc" style={{ color: 'var(--accent-rose)' }}>
          Key generation failed: {keyError}
        </p>
        <button type="button" className="btn btn-primary" onClick={() => setKeyNonce(n => n + 1)}>
          Retry
        </button>
      </div>
    );
  }

  const vk = keys.vk;
  const traceValid = verifySteps?.trace.valid;

  return (
    <div>
      <div className="demo-panel__title">PA#15: Digital Signatures (RSA)</div>
      <div className="demo-panel__desc">
        Hash-then-sign with PA#8 <code>dlpHash</code>: σ = H(m)<sup>d</sup> mod N; verify σ<sup>e</sup> ≡ H(m) (mod N).
        Raw RSA (no hash) enables a multiplicative existential forgery.
      </div>

      <div className="btn-group" style={{ marginBottom: '12px', flexWrap: 'wrap' }}>
        <button type="button" className="btn" onClick={() => setKeyNonce(n => n + 1)}>
          Regenerate RSA keys
        </button>
        <label className="select-label" style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
          <input
            type="checkbox"
            checked={rawSignMode}
            onChange={e => {
              setRawSignMode(e.target.checked);
              setSigmaHex('');
              setVerifySteps(null);
            }}
          />
          Raw RSA sign (no hash)
        </label>
      </div>

      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '16px' }}>
        |N| = {keys.N.toString(2).length} bits · public e = {vk.e.toString()} ·{' '}
        <span style={{ fontFamily: 'var(--font-mono)' }}>N = {keys.N.toString().slice(0, 24)}…</span>
      </div>

      {/* —— Sign / Verify —— */}
      <div className="hex-input-wrapper">
        <label className="select-label">Message</label>
        <input className="hex-input" type="text" value={message} onChange={e => setMessage(e.target.value)} />
      </div>

      <div className="btn-group" style={{ marginBottom: '8px' }}>
        <button type="button" className="btn btn-primary" onClick={handleSign}>
          Sign
        </button>
        <button type="button" className="btn" onClick={handleVerify}>
          Verify
        </button>
        <button type="button" className="btn" onClick={handleTamper} disabled={!lastSignedBytes}>
          Tamper (flip 1 bit)
        </button>
      </div>

      {sigmaHex && (
        <div style={{ marginBottom: '12px' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>σ (hex)</div>
          <div className="test-value" style={{ wordBreak: 'break-all', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
            {sigmaHex}
          </div>
        </div>
      )}

      {verifySteps && (
        <div className="game-panel" style={{ marginBottom: '20px' }}>
          <div className="game-panel__label">Verification</div>
          <StepDisplay steps={verifySteps.steps} />
          <div
            className={`counter ${traceValid ? 'good' : 'bad'}`}
            style={{ marginTop: '12px', fontSize: '1rem' }}
          >
            {traceValid ? 'Valid' : 'Invalid'}
          </div>
        </div>
      )}

      {/* —— Raw RSA multiplicative forgery —— */}
      <div className="demo-panel__title" style={{ marginTop: '24px', fontSize: '1rem' }}>
        Multiplicative forgery (raw RSA only)
      </div>
      <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
        Given σ₁ = m₁<sup>d</sup> and σ₂ = m₂<sup>d</sup>, set σ* = σ₁·σ₂ mod N. Then σ*<sup>e</sup> ≡ m₁·m₂ (mod N), a valid
        signature on the product representative — without d.
      </p>
      <div className="hex-input-wrapper">
        <label className="select-label">m₁</label>
        <input className="hex-input" type="text" value={m1} onChange={e => setM1(e.target.value)} />
      </div>
      <div className="hex-input-wrapper">
        <label className="select-label">m₂</label>
        <input className="hex-input" type="text" value={m2} onChange={e => setM2(e.target.value)} />
      </div>
      <button type="button" className="btn btn-primary" onClick={handleRawForgeryDemo}>
        Forge signature on m₁·m₂
      </button>
      {rawForgeResult && (
        <div className="test-results" style={{ marginTop: '12px' }}>
          <div className="test-row">
            <span className="test-name">σ₁</span>
            <span className="test-value" style={{ fontFamily: 'var(--font-mono)' }}>
              {rawForgeResult.sigma1Hex.slice(0, 48)}…
            </span>
          </div>
          <div className="test-row">
            <span className="test-name">σ₂</span>
            <span className="test-value" style={{ fontFamily: 'var(--font-mono)' }}>
              {rawForgeResult.sigma2Hex.slice(0, 48)}…
            </span>
          </div>
          <div className="test-row">
            <span className="test-name">σ* = σ₁σ₂ mod N</span>
            <span className="test-value" style={{ fontFamily: 'var(--font-mono)' }}>
              {rawForgeResult.sigmaStarHex.slice(0, 48)}…
            </span>
          </div>
          <div className="test-row">
            <span className="test-name">m* (bytes, length |N|)</span>
            <span className="test-value" style={{ fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
              {rawForgeResult.forgedMsgHex}
            </span>
          </div>
          <div className="test-row">
            <span className="test-name">m* mod N</span>
            <span className="test-value">{rawForgeResult.repStar}</span>
          </div>
          <div className="test-row">
            <span className="test-name">Verify(m*, σ*)</span>
            <span className={`counter ${rawForgeResult.valid ? 'good' : 'bad'}`}>
              {rawForgeResult.valid ? 'Valid (forged)' : 'Invalid'}
            </span>
          </div>
        </div>
      )}

      {/* —— EUF-CMA —— */}
      <div className="demo-panel__title" style={{ marginTop: '28px', fontSize: '1rem' }}>
        EUF-CMA game (hash-then-sign)
      </div>
      <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
        After up to {ORACLE_QUERIES} signing oracle queries, produce (m*, σ*) where m* was never signed. Random guesses
        almost always fail; hashing prevents the raw-RSA homomorphism attack.
      </p>
      <div className="btn-group">
        <button type="button" className="btn btn-primary" onClick={handleFillOracle}>
          Run oracle ({ORACLE_QUERIES} random messages)
        </button>
        <button type="button" className="btn" onClick={() => { setEufGameId(id => id + 1); setOracleLog([]); setForgeOutcome(null); }}>
          Reset challenger
        </button>
      </div>

      {oracleLog.length > 0 && (
        <div style={{ marginTop: '12px', marginBottom: '12px' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
            Oracle transcripts (first 6)
          </div>
          <div className="test-results">
            {oracleLog.slice(0, 6).map((row, i) => (
              <div className="test-row" key={i}>
                <span className="test-name">#{i}</span>
                <span className="test-value mono">{row.msgHex.slice(0, 40)}…</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="hex-input-wrapper">
        <label className="select-label">Forgery message m*</label>
        <input className="hex-input" type="text" value={forgeMsg} onChange={e => setForgeMsg(e.target.value)} />
      </div>
      <div className="hex-input-wrapper">
        <label className="select-label">Forgery σ* (hex)</label>
        <input
          className="hex-input"
          type="text"
          value={forgeSigmaHex}
          onChange={e => setForgeSigmaHex(e.target.value.replace(/[^0-9a-fA-F]/g, ''))}
        />
      </div>
      <div className="btn-group">
        <button type="button" className="btn" onClick={handleSubmitForgery}>
          Submit forgery
        </button>
        <button type="button" className="btn" onClick={handleRandomForgeryGuess}>
          Random (m*, σ*) guess
        </button>
      </div>

      {forgeOutcome && (
        <div className="game-panel" style={{ marginTop: '12px' }}>
          <div className="game-panel__label">Challenger</div>
          <div className={`counter ${forgeOutcome.wins ? 'bad' : 'good'}`}>
            {forgeOutcome.wins ? 'Adversary wins (unexpected for random attempts)' : 'Adversary loses'}
          </div>
          <p style={{ marginTop: '8px', fontSize: '0.85rem' }}>{forgeOutcome.reason}</p>
        </div>
      )}

      <div style={{ marginTop: '20px', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
        API for PA#17: <code>Sign(sk, messageBytes, {'{'} useHash {'}'})</code>,{' '}
        <code>Verify(vk, messageBytes, sigma, {'{'} useHash {'}'})</code> in{' '}
        <code>src/crypto/rsa_sig.js</code>.
      </div>
    </div>
  );
}
