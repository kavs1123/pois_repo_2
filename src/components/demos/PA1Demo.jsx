import React, { useState, useMemo } from 'react';
import StepDisplay from '../StepDisplay.jsx';
import { prgFromAES, prgFromDLP, runNISTTests, createPRG } from '../../crypto/prg.js';
import { verifyHardness, DLP_PARAMS } from '../../crypto/owf.js';
import { hexToBytes, bytesToHex, bytesToBits, randomBytes } from '../../crypto/utils.js';

export default function PA1Demo({ foundation, keyHex }) {
  const [seedHex, setSeedHex] = useState(() => bytesToHex(randomBytes(16)));
  const [outputLen, setOutputLen] = useState(32);
  const [testResults, setTestResults] = useState(null);
  const [hardnessResult, setHardnessResult] = useState(null);

  const isAES = foundation.type === 'aes';

  const prgResult = useMemo(() => {
    try {
      const seedBytes = hexToBytes(seedHex.slice(0, 32).padEnd(32, '0'));
      if (isAES) {
        return prgFromAES(seedBytes, outputLen);
      } else {
        let val = 0n;
        for (const b of seedBytes) val = (val << 8n) | BigInt(b);
        val = val % DLP_PARAMS.q;
        return prgFromDLP(val, outputLen * 8);
      }
    } catch (e) {
      return { output: new Uint8Array(0), steps: [{ label: 'Error', value: e.message, className: 'error' }] };
    }
  }, [seedHex, outputLen, isAES]);

  const handleRunTests = () => {
    const bits = bytesToBits(prgResult.output);
    const results = runNISTTests(bits);
    setTestResults(results);
  };

  const handleVerifyHardness = () => {
    const result = verifyHardness(isAES ? 'aes' : 'dlp', 100);
    setHardnessResult(result);
  };

  return (
    <div>
      <div className="demo-panel__title">PA#1: One-Way Functions & Pseudorandom Generators</div>
      <div className="demo-panel__desc">
        Live PRG output viewer. Change the seed or output length to see the PRG output update in real time.
        Foundation: <strong>{foundation.name}</strong>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
        <div className="hex-input-wrapper">
          <label className="select-label">Seed (hex, 16 bytes)</label>
          <input
            id="pa1-seed-input"
            className="hex-input"
            type="text"
            value={seedHex}
            onChange={e => setSeedHex(e.target.value.replace(/[^0-9a-fA-F]/g, ''))}
            placeholder="e.g. a3f2b1c9..."
            maxLength={32}
          />
        </div>

        <div className="slider-wrapper">
          <label>Output Length: {outputLen} bytes ({outputLen * 8} bits)</label>
          <input
            id="pa1-length-slider"
            type="range"
            min="8"
            max="128"
            value={outputLen}
            onChange={e => setOutputLen(Number(e.target.value))}
          />
        </div>
      </div>

      <StepDisplay steps={prgResult.steps} />

      <div className="btn-group" style={{ marginTop: '16px' }}>
        <button id="pa1-nist-test" className="btn btn-primary" onClick={handleRunTests}>
          🧪 Run NIST Tests
        </button>
        <button id="pa1-hardness-test" className="btn" onClick={handleVerifyHardness}>
          🔒 Verify OWF Hardness
        </button>
        <button className="btn btn-sm" onClick={() => setSeedHex(bytesToHex(randomBytes(16)))}>
          🎲 Random Seed
        </button>
      </div>

      {/* NIST Test Results */}
      {testResults && (
        <div style={{ marginTop: '16px' }}>
          <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px' }}>
            NIST SP 800-22 Statistical Tests
          </div>
          <div className="test-results">
            {testResults.map((test, i) => (
              <div className="test-row" key={i}>
                <span className={`test-badge ${test.pass ? 'pass' : 'fail'}`}>
                  {test.pass ? 'PASS' : 'FAIL'}
                </span>
                <span className="test-name">{test.name}</span>
                <span className="test-value">p={test.pValue}</span>
                {test.ratio !== undefined && (
                  <span className="test-value">ratio={test.ratio}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Hardness Result */}
      {hardnessResult && (
        <div style={{ marginTop: '16px' }}>
          <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px' }}>
            OWF Hardness Verification
          </div>
          <StepDisplay steps={hardnessResult.steps} />
        </div>
      )}
    </div>
  );
}
