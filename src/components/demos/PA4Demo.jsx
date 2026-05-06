import React, { useState, useMemo } from 'react';
import StepDisplay from '../StepDisplay.jsx';
import {
  cbcEncrypt, cbcDecrypt,
  ofbEncrypt, ofbDecrypt,
  ctrEncrypt, ctrDecrypt,
  cbcIVReuseAttack, ofbKeystreamReuseAttack,
  bitFlipDemo, runCorrectnessTests
} from '../../crypto/modes.js';
import { hexToBytes, bytesToHex, stringToBytes, bytesToString, randomBytes, splitBlocks, pkcs7Pad } from '../../crypto/utils.js';

export default function PA4Demo({ keyHex }) {
  const [mode, setMode] = useState('CBC');
  const [plaintext, setPlaintext] = useState('Attack at dawn!!');
  const [encResult, setEncResult] = useState(null);
  const [flipBlock, setFlipBlock] = useState(0);
  const [flipBit, setFlipBit] = useState(0);
  const [flipResult, setFlipResult] = useState(null);
  const [ivAttackResult, setIvAttackResult] = useState(null);
  const [correctnessResults, setCorrectnessResults] = useState(null);

  const key = useMemo(() => hexToBytes(keyHex.slice(0, 32).padEnd(32, '0')), [keyHex]);
  const iv = useMemo(() => randomBytes(16), []);

  const handleEncrypt = () => {
    try {
      const msg = stringToBytes(plaintext);
      let result;
      if (mode === 'CBC') result = cbcEncrypt(key, iv, msg);
      else if (mode === 'OFB') result = ofbEncrypt(key, iv, msg);
      else result = ctrEncrypt(key, msg);
      setEncResult(result);
      setFlipResult(null);
    } catch (e) {
      setEncResult({ steps: [{ label: 'Error', value: e.message, className: 'error' }] });
    }
  };

  const handleBitFlip = () => {
    try {
      const msg = stringToBytes(plaintext);
      const result = bitFlipDemo(mode, key, iv, msg, flipBlock, flipBit);
      setFlipResult(result);
    } catch (e) {
      setFlipResult({ steps: [{ label: 'Error', value: e.message, className: 'error' }] });
    }
  };

  const handleIVAttack = () => {
    const m1 = stringToBytes(plaintext.padEnd(16, ' ').slice(0, 16));
    const m2 = stringToBytes(('Second message!!').padEnd(16, ' ').slice(0, 16));
    if (mode === 'CBC') {
      setIvAttackResult(cbcIVReuseAttack(m1, m2));
    } else if (mode === 'OFB') {
      setIvAttackResult(ofbKeystreamReuseAttack(m1, m2));
    } else {
      setIvAttackResult({ steps: [{ label: 'CTR', value: 'Nonce reuse in CTR mode is equivalent to stream cipher key reuse' }] });
    }
  };

  const handleCorrectnessTests = () => {
    setCorrectnessResults(runCorrectnessTests());
  };

  return (
    <div>
      <div className="demo-panel__title">PA#4: Modes of Operation</div>
      <div className="demo-panel__desc">
        Explore CBC, OFB, and CTR modes. See how each mode encrypts, and test error propagation and IV reuse attacks.
      </div>

      {/* Mode selector */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
        {['CBC', 'OFB', 'CTR'].map(m => (
          <button
            key={m}
            id={`pa4-mode-${m.toLowerCase()}`}
            className={`demo-tab ${mode === m ? 'active' : ''}`}
            onClick={() => { setMode(m); setEncResult(null); setFlipResult(null); }}
          >
            {m}
          </button>
        ))}
      </div>

      {/* Mode comparison table */}
      <table className="mode-table">
        <thead>
          <tr><th>Mode</th><th>Par. Enc</th><th>Par. Dec</th><th>Rand Access</th><th>Error Prop</th><th>IV Reuse</th></tr>
        </thead>
        <tbody>
          <tr style={mode === 'CBC' ? { background: 'var(--accent-blue-dim)' } : {}}>
            <td>CBC</td><td>✗</td><td>✓</td><td>✗</td><td>2 blocks</td><td>Fatal</td>
          </tr>
          <tr style={mode === 'OFB' ? { background: 'var(--accent-blue-dim)' } : {}}>
            <td>OFB</td><td>✗</td><td>✗</td><td>✗</td><td>None</td><td>Fatal</td>
          </tr>
          <tr style={mode === 'CTR' ? { background: 'var(--accent-blue-dim)' } : {}}>
            <td>CTR</td><td>✓</td><td>✓</td><td>✓</td><td>None</td><td>Fatal</td>
          </tr>
        </tbody>
      </table>

      <div className="hex-input-wrapper" style={{ marginTop: '16px' }}>
        <label className="select-label">Plaintext</label>
        <input
          id="pa4-plaintext"
          className="hex-input"
          type="text"
          value={plaintext}
          onChange={e => setPlaintext(e.target.value)}
        />
      </div>

      <div className="btn-group" style={{ marginBottom: '16px' }}>
        <button id="pa4-encrypt" className="btn btn-primary" onClick={handleEncrypt}>
          🔐 Encrypt ({mode})
        </button>
        <button id="pa4-bitflip" className="btn" onClick={handleBitFlip}>
          🔀 Flip Bit (block {flipBlock}, bit {flipBit})
        </button>
        <button id="pa4-iv-attack" className="btn btn-danger" onClick={handleIVAttack}>
          ⚡ IV/Nonce Reuse Attack
        </button>
        <button className="btn btn-sm" onClick={handleCorrectnessTests}>
          ✅ Correctness Tests
        </button>
      </div>

      {/* Bit flip controls */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '12px' }}>
        <div className="slider-wrapper">
          <label>Flip Block Index: {flipBlock}</label>
          <input type="range" min="0" max="3" value={flipBlock} onChange={e => setFlipBlock(Number(e.target.value))} />
        </div>
        <div className="slider-wrapper">
          <label>Flip Bit Index: {flipBit}</label>
          <input type="range" min="0" max="7" value={flipBit} onChange={e => setFlipBit(Number(e.target.value))} />
        </div>
      </div>

      {/* Encryption result */}
      {encResult && (
        <div style={{ marginTop: '8px' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px' }}>
            {mode} Encryption Result
          </div>
          <StepDisplay steps={encResult.steps} />

          {/* Block visualization */}
          {encResult.blocks && (
            <div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '8px', marginBottom: '4px' }}>
                Ciphertext Blocks:
              </div>
              <div className="block-viz">
                {encResult.blocks.map((block, i) => (
                  <div key={i} className="block-box">
                    <div style={{ fontSize: '0.6rem', color: 'var(--text-dim)', marginBottom: '2px' }}>C{i}</div>
                    {bytesToHex(block).slice(0, 8)}...
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Bit flip result */}
      {flipResult && (
        <div style={{ marginTop: '16px' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--accent-amber)', marginBottom: '4px' }}>
            Bit Flip Error Propagation ({mode})
          </div>
          <StepDisplay steps={flipResult.steps} />
          {flipResult.corruptedBlocks && (
            <div className="block-viz" style={{ marginTop: '8px' }}>
              {Array.from({ length: Math.ceil(plaintext.length / 16) + 1 }).map((_, i) => (
                <div key={i} className={`block-box ${flipResult.corruptedBlocks.includes(i) ? 'corrupted' : ''}`}>
                  <div style={{ fontSize: '0.6rem', marginBottom: '2px' }}>
                    Block {i}
                  </div>
                  {flipResult.corruptedBlocks.includes(i) ? '✗ CORRUPTED' : '✓ OK'}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* IV Attack Result */}
      {ivAttackResult && (
        <div style={{ marginTop: '16px' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--accent-rose)', marginBottom: '4px' }}>
            {mode} IV/Nonce Reuse Attack
          </div>
          <StepDisplay steps={ivAttackResult.steps} />
        </div>
      )}

      {/* Correctness Tests */}
      {correctnessResults && (
        <div style={{ marginTop: '16px' }}>
          <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px' }}>
            Correctness Tests: Dec(k, Enc(k, m)) = m
          </div>
          <div className="test-results">
            {correctnessResults.map((r, i) => (
              <div className="test-row" key={i}>
                <span className={`test-badge ${r.pass ? 'pass' : 'fail'}`}>{r.pass ? 'PASS' : 'FAIL'}</span>
                <span className="test-name">{r.mode} — {r.label}</span>
                {r.error && <span className="test-value" style={{ color: 'var(--accent-rose)' }}>{r.error}</span>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
