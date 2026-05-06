import React, { useCallback, useEffect, useMemo, useState } from 'react';
import StepDisplay from '../StepDisplay.jsx';
import { elgamalKeygen, Enc, Dec, malleateMultiplyC2, ELGAMAL_DEFAULT_PARAMS } from '../../crypto/elgamal.js';
import { rsaKeyGen, sigmaToHex } from '../../crypto/rsa_sig.js';
import {
  ccaPkcEnc,
  deserializeElGamalCiphertext,
  tamperCeEncoding,
  createCca2Oracle,
} from '../../crypto/signcrypt.js';

const RSA_BITS = 416;
const MR_ROUNDS = 14;

export default function PA17Demo() {
  const eg = useMemo(() => elgamalKeygen(ELGAMAL_DEFAULT_PARAMS), []);

  const [rsaKeys, setRsaKeys] = useState(null);
  const [rsaLoading, setRsaLoading] = useState(true);
  const [rsaErr, setRsaErr] = useState(null);

  useEffect(() => {
    let alive = true;
    setRsaLoading(true);
    setRsaErr(null);
    const t = setTimeout(() => {
      try {
        const k = rsaKeyGen(RSA_BITS, MR_ROUNDS);
        if (alive) {
          setRsaKeys(k);
          setRsaLoading(false);
        }
      } catch (e) {
        if (alive) {
          setRsaErr(e.message || String(e));
          setRsaLoading(false);
        }
      }
    }, 40);
    return () => {
      alive = false;
      clearTimeout(t);
    };
  }, []);

  const ccaOracle = useMemo(() => {
    if (!rsaKeys) return null;
    return createCca2Oracle(eg.sk, eg.pk, rsaKeys.vk);
  }, [eg.sk, eg.pk, rsaKeys]);

  const [mStr, setMStr] = useState('1337');
  const [pkg, setPkg] = useState(null);
  const [tampered, setTampered] = useState(null);
  const [ccaOracleTrace, setCcaOracleTrace] = useState(null);

  const [plainCe, setPlainCe] = useState(null);
  const [plainMall, setPlainMall] = useState(null);
  const [plainOracleMsg, setPlainOracleMsg] = useState(null);

  const parseM = useCallback(() => {
    const v = BigInt(mStr.trim() || '0');
    if (v <= 0n || v >= eg.pk.p) throw new Error(`m must satisfy 1 ≤ m < p (|p| ≈ ${eg.pk.p.toString(2).length} bits).`);
    return v;
  }, [mStr, eg.pk.p]);

  const handleSigncrypt = useCallback(() => {
    if (!rsaKeys) return;
    const m = parseM();
    const out = ccaPkcEnc(eg.pk, rsaKeys.sk, m);
    setPkg({ ...out, m });
    setTampered(null);
    setCcaOracleTrace(null);
    ccaOracle?.reset?.();
  }, [parseM, rsaKeys, eg.pk, ccaOracle]);

  const handleTamperCe = useCallback(() => {
    if (!pkg) return;
    const raw = tamperCeEncoding(pkg.ceBytes, 0);
    const pair = deserializeElGamalCiphertext(raw, eg.pk.p);
    setTampered(pair);
    setCcaOracleTrace(null);
  }, [pkg, eg.pk.p]);

  const handleRestoreCe = useCallback(() => {
    setTampered(null);
    setCcaOracleTrace(null);
  }, []);

  const handleCcaOracle = useCallback(() => {
    if (!pkg || !rsaKeys || !ccaOracle) return;
    const c1 = tampered ? tampered.c1 : pkg.c1;
    const c2 = tampered ? tampered.c2 : pkg.c2;
    const res = ccaOracle.query(c1, c2, pkg.sigma);
    setCcaOracleTrace(res);
  }, [pkg, tampered, rsaKeys, ccaOracle]);

  const handlePlainEncrypt = useCallback(() => {
    const m = parseM();
    const ce = Enc(eg.pk, m);
    setPlainCe({ ...ce, m });
    setPlainMall(null);
    setPlainOracleMsg(null);
  }, [parseM, eg.pk]);

  const handlePlainMalleate = useCallback(() => {
    if (!plainCe) return;
    setPlainMall(malleateMultiplyC2(plainCe.c1, plainCe.c2, 2n, eg.pk.p));
    setPlainOracleMsg(null);
  }, [plainCe, eg.pk.p]);

  const handlePlainOracle = useCallback(() => {
    const ce = plainMall || plainCe;
    if (!ce) return;
    const out = Dec(eg.sk, ce.c1, ce.c2, eg.pk.p);
    setPlainOracleMsg(out);
  }, [plainCe, plainMall, eg.sk, eg.pk.p]);

  if (rsaLoading) {
    return (
      <div>
        <div className="demo-panel__title">PA#17: CCA-safe signcryption</div>
        <p className="demo-panel__desc">Generating RSA signing keys ({RSA_BITS}-bit modulus, Miller–Rabin)…</p>
      </div>
    );
  }

  if (rsaErr || !rsaKeys) {
    return (
      <div>
        <div className="demo-panel__title">PA#17: CCA-safe signcryption</div>
        <p className="demo-panel__desc" style={{ color: 'var(--accent-rose)' }}>{rsaErr || 'RSA key generation failed.'}</p>
      </div>
    );
  }

  const sigmaHex = pkg ? sigmaToHex(pkg.sigma, rsaKeys.N) : '';

  return (
    <div>
      <div className="demo-panel__title">PA#17: CCA-safe signcryption (Encrypt-then-Sign)</div>
      <div className="demo-panel__desc">
        <strong>CE</strong> ← ElGamal(PA#16) · <strong>σ</strong> ← RSA Sign(PA#15) on <code>serialize(CE)</code>. Decrypt{' '}
        <strong>must</strong> verify σ first; otherwise output ⊥ (never decrypt a rejected package).
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
        <strong>Lineage:</strong> PA#17 → <code>signcrypt.js</code> → <code>elgamal.js</code> (PA#16, PA#11 via{' '}
        <code>owf.js</code>) + <code>rsa_sig.js</code> (PA#15 → PA#8 <code>crhf.js</code>, PA#12 via <code>prime.js</code> /
        Miller–Rabin).
      </div>

      <div className="hex-input-wrapper">
        <label className="select-label">Message m (integer in ℤₚ*)</label>
        <input className="hex-input" type="text" inputMode="numeric" value={mStr} onChange={e => setMStr(e.target.value)} />
      </div>

      <div className="btn-group" style={{ flexWrap: 'wrap', marginBottom: '16px' }}>
        <button type="button" className="btn btn-primary" onClick={handleSigncrypt}>
          Encrypt-then-Sign (build CE, σ)
        </button>
      </div>

      {pkg && (
        <div className="game-panel" style={{ marginBottom: '20px' }}>
          <div className="game-panel__label">Package (CE, σ)</div>
          <div style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
            <div>c₁ = {pkg.c1.toString()}</div>
            <div>c₂ = {pkg.c2.toString()}</div>
            <div style={{ marginTop: '8px' }}>σ (hex) = {sigmaHex}</div>
            <div style={{ marginTop: '8px', color: 'var(--text-secondary)', fontSize: '0.72rem' }}>
              Serialized CE length: {pkg.ceBytes.length} bytes
            </div>
          </div>

          <div className="btn-group" style={{ marginTop: '12px', flexWrap: 'wrap' }}>
            <button type="button" className="btn" onClick={handleTamperCe}>
              Tamper with CE (flip one bit in encoding)
            </button>
            <button type="button" className="btn" onClick={handleRestoreCe} disabled={!tampered}>
              Restore original CE
            </button>
            <button type="button" className="btn btn-primary" onClick={handleCcaOracle}>
              Submit to decryption oracle
            </button>
          </div>

          {tampered && (
            <p style={{ marginTop: '10px', fontSize: '0.8rem', color: 'var(--accent-amber)' }}>
              Tampered CE active — σ still binds the <em>original</em> encoding; verification should fail.
            </p>
          )}

          {ccaOracleTrace && (
            <div style={{ marginTop: '14px' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                IND-CCA2 oracle query #{ccaOracleTrace.queryId} · total queries: {ccaOracle.queryCount}
              </div>
              <StepDisplay steps={ccaOracleTrace.steps} />
              <div className={`counter ${ccaOracleTrace.ok ? 'good' : 'bad'}`} style={{ marginTop: '10px' }}>
                {ccaOracleTrace.ok ? `Plaintext: ${ccaOracleTrace.plaintext?.toString?.() ?? ''}` : '⊥ — Signature invalid, decryption aborted'}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Contrast: plain ElGamal */}
      <div className="demo-panel__title" style={{ fontSize: '1rem', marginTop: '8px' }}>
        Contrast — plain ElGamal (PA#16, no signature)
      </div>
      <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '12px', maxWidth: '720px' }}>
        Same keys and message: encrypt with ElGamal only, then apply the PA#16 malleability <code>(c₁, 2c₂)</code>. A decryption
        oracle returns <strong>2·m mod p</strong> — the packaging above blocks this because verification fails before Dec.
      </p>

      <div className="btn-group" style={{ flexWrap: 'wrap', marginBottom: '12px' }}>
        <button type="button" className="btn" onClick={handlePlainEncrypt}>
          Plain ElGamal encrypt m
        </button>
        <button type="button" className="btn" onClick={handlePlainMalleate} disabled={!plainCe}>
          Malleate: multiply c₂ by 2
        </button>
        <button type="button" className="btn btn-primary" onClick={handlePlainOracle} disabled={!plainCe}>
          Plain decryption oracle
        </button>
      </div>

      {plainCe && (
        <div className="test-results">
          <div className="test-row">
            <span className="test-name">Original CE</span>
            <span className="test-value" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>
              c₁={plainCe.c1.toString().slice(0, 14)}… c₂={plainCe.c2.toString().slice(0, 14)}…
            </span>
          </div>
          {plainMall && (
            <div className="test-row">
              <span className="test-name">Malleated CE</span>
              <span className="test-value" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>
                c₁={plainMall.c1.toString().slice(0, 14)}… c₂={plainMall.c2.toString().slice(0, 14)}…
              </span>
            </div>
          )}
          {plainOracleMsg !== null && plainCe && (
            <div className="test-row">
              <span className="test-name">Oracle output</span>
              <span className="test-value">
                {plainOracleMsg.toString()}
                {plainMall ? (
                  <span style={{ color: 'var(--accent-rose)', marginLeft: '8px' }}>
                    (= 2·m mod p — CCA leak)
                  </span>
                ) : (
                  <span style={{ color: 'var(--accent-cyan)', marginLeft: '8px' }}>(= m)</span>
                )}
              </span>
            </div>
          )}
        </div>
      )}

      <div style={{ marginTop: '22px', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
        API: <code>ccaPkcEnc(elGamalPk, rsaSk, m)</code>,{' '}
        <code>ccaPkcDec(elGamalSk, elGamalPk, rsaVk, c1, c2, sigma)</code> —{' '}
        <code>src/crypto/signcrypt.js</code>.
      </div>
    </div>
  );
}
