import React, { useState, useMemo } from 'react';
import StepDisplay from '../StepDisplay.jsx';
import { ggmPRF, prfDistinguishGame, prgFromPRF } from '../../crypto/prf.js';
import { hexToBytes, bytesToHex, randomBytes } from '../../crypto/utils.js';

export default function PA2Demo({ keyHex }) {
  const [queryHex, setQueryHex] = useState(() => bytesToHex(randomBytes(16)));
  const [treeDepth, setTreeDepth] = useState(8);
  const [gameResult, setGameResult] = useState(null);

  const keyBytes = useMemo(() => hexToBytes(keyHex.slice(0, 32).padEnd(32, '0')), [keyHex]);
  const queryBytes = useMemo(() => hexToBytes(queryHex.slice(0, 32).padEnd(32, '0')), [queryHex]);

  const prfResult = useMemo(() => {
    try {
      return ggmPRF(keyBytes, queryBytes, treeDepth);
    } catch (e) {
      return { output: new Uint8Array(16), steps: [{ label: 'Error', value: e.message, className: 'error' }] };
    }
  }, [keyBytes, queryBytes, treeDepth]);

  const backwardResult = useMemo(() => {
    try {
      return prgFromPRF(keyBytes);
    } catch (e) {
      return { steps: [{ label: 'Error', value: e.message }] };
    }
  }, [keyBytes]);

  const handleDistinguishGame = () => {
    const result = prfDistinguishGame(50, 20);
    setGameResult(result);
  };

  return (
    <div>
      <div className="demo-panel__title">PA#2: PRF via GGM Tree</div>
      <div className="demo-panel__desc">
        Evaluate the GGM tree PRF, run the distinguishing game, and see the backward PRF→PRG construction.
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
        <div className="hex-input-wrapper">
          <label className="select-label">Query x (hex)</label>
          <input
            id="pa2-query-input"
            className="hex-input"
            type="text"
            value={queryHex}
            onChange={e => setQueryHex(e.target.value.replace(/[^0-9a-fA-F]/g, ''))}
            maxLength={32}
          />
        </div>
        <div className="slider-wrapper">
          <label>Tree Depth: {treeDepth} levels</label>
          <input
            type="range"
            min="1"
            max="16"
            value={treeDepth}
            onChange={e => setTreeDepth(Number(e.target.value))}
          />
        </div>
      </div>

      {/* GGM PRF evaluation */}
      <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px' }}>
        GGM Tree Evaluation: F_k(x)
      </div>
      <StepDisplay steps={prfResult.steps} />

      {/* Backward PRF→PRG */}
      <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginTop: '16px', marginBottom: '4px' }}>
        Backward: PRF → PRG
      </div>
      <StepDisplay steps={backwardResult.steps} />

      <div className="btn-group" style={{ marginTop: '16px' }}>
        <button id="pa2-distinguish-game" className="btn btn-primary" onClick={handleDistinguishGame}>
          🎯 Run PRF Distinguishing Game
        </button>
        <button className="btn btn-sm" onClick={() => setQueryHex(bytesToHex(randomBytes(16)))}>
          🎲 Random Query
        </button>
      </div>

      {/* Game Result */}
      {gameResult && (
        <div style={{ marginTop: '16px' }}>
          <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px' }}>
            PRF Distinguishing Game Results
          </div>
          <StepDisplay steps={gameResult.steps} />
          <div className="counter good" style={{ marginTop: '8px' }}>
            Advantage: {gameResult.advantage} (expected ≈ 0)
          </div>
        </div>
      )}
    </div>
  );
}
