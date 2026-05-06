import React, { useState } from 'react';
import StepDisplay from '../StepDisplay.jsx';
import { cpaEncrypt, cpaDecrypt, indCPARound, nonceReuseAttack } from '../../crypto/cpa_enc.js';
import { hexToBytes, bytesToHex, stringToBytes, randomBytes } from '../../crypto/utils.js';

export default function PA3Demo({ keyHex }) {
  const [m0Text, setM0Text] = useState('Hello, world!!!!' );
  const [m1Text, setM1Text] = useState('Goodbye, world!!' );
  const [gameRounds, setGameRounds] = useState([]);
  const [totalCorrect, setTotalCorrect] = useState(0);
  const [brokenMode, setBrokenMode] = useState(false);
  const [nonceAttackResult, setNonceAttackResult] = useState(null);
  const [encDecResult, setEncDecResult] = useState(null);

  const handlePlayRound = () => {
    const m0 = stringToBytes(m0Text.padEnd(16, ' ').slice(0, 16));
    const m1 = stringToBytes(m1Text.padEnd(16, ' ').slice(0, 16));
    const result = indCPARound(m0, m1, null, brokenMode);

    setGameRounds(prev => [result, ...prev].slice(0, 20));
    setTotalCorrect(prev => result.correct ? prev + 1 : prev);
  };

  const handleNonceAttack = () => {
    const m0 = stringToBytes(m0Text.padEnd(16, ' ').slice(0, 16));
    const m1 = stringToBytes(m1Text.padEnd(16, ' ').slice(0, 16));
    setNonceAttackResult(nonceReuseAttack(m0, m1));
  };

  const handleEncDec = () => {
    const key = hexToBytes(keyHex.slice(0, 32).padEnd(32, '0'));
    const msg = stringToBytes(m0Text);
    const { nonce, ciphertext, steps: encSteps } = cpaEncrypt(key, msg);
    const { plaintext, steps: decSteps } = cpaDecrypt(key, nonce, ciphertext);
    setEncDecResult({
      encSteps,
      decSteps,
      match: bytesToHex(msg) === bytesToHex(plaintext)
    });
  };

  const totalRounds = gameRounds.length;
  const advantage = totalRounds > 0 ? Math.abs(totalCorrect / totalRounds - 0.5) : 0;

  return (
    <div>
      <div className="demo-panel__title">PA#3: CPA-Secure Encryption</div>
      <div className="demo-panel__desc">
        Play the IND-CPA game as the adversary. Try to guess which message was encrypted.
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
        <div className="hex-input-wrapper">
          <label className="select-label">Message m₀</label>
          <input
            id="pa3-m0-input"
            className="hex-input"
            type="text"
            value={m0Text}
            onChange={e => setM0Text(e.target.value)}
          />
        </div>
        <div className="hex-input-wrapper">
          <label className="select-label">Message m₁</label>
          <input
            id="pa3-m1-input"
            className="hex-input"
            type="text"
            value={m1Text}
            onChange={e => setM1Text(e.target.value)}
          />
        </div>
      </div>

      <div className="btn-group" style={{ marginBottom: '16px' }}>
        <button id="pa3-play-round" className="btn btn-primary" onClick={handlePlayRound}>
          🎮 Play Round
        </button>
        <button id="pa3-enc-dec" className="btn" onClick={handleEncDec}>
          🔐 Encrypt / Decrypt
        </button>
        <button id="pa3-nonce-attack" className="btn btn-danger" onClick={handleNonceAttack}>
          ⚡ Nonce Reuse Attack
        </button>
        <button
          className={`btn btn-sm ${brokenMode ? 'btn-danger' : ''}`}
          onClick={() => setBrokenMode(!brokenMode)}
        >
          {brokenMode ? '🔓 Broken Mode ON' : '🔒 Secure Mode'}
        </button>
        <button className="btn btn-sm" onClick={() => { setGameRounds([]); setTotalCorrect(0); }}>
          ↺ Reset
        </button>
      </div>

      {/* Game stats */}
      {totalRounds > 0 && (
        <div className="game-panel">
          <div style={{ display: 'flex', gap: '16px', alignItems: 'center', flexWrap: 'wrap' }}>
            <div>
              <div className="game-panel__label">Rounds Played</div>
              <div className="counter good">{totalRounds}</div>
            </div>
            <div>
              <div className="game-panel__label">Correct Guesses</div>
              <div className="counter good">{totalCorrect}/{totalRounds}</div>
            </div>
            <div>
              <div className="game-panel__label">Advantage</div>
              <div className={`counter ${advantage > 0.3 ? 'bad' : 'good'}`}>
                |{(totalCorrect / totalRounds).toFixed(2)} - 0.5| = {advantage.toFixed(4)}
              </div>
            </div>
            <div>
              <div className="game-panel__label">Mode</div>
              <div className={`counter ${brokenMode ? 'bad' : 'good'}`}>
                {brokenMode ? '🔓 BROKEN' : '🔒 SECURE'}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Latest round */}
      {gameRounds.length > 0 && (
        <div style={{ marginTop: '8px' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px' }}>
            Latest Round
          </div>
          <StepDisplay steps={gameRounds[0].steps} />
        </div>
      )}

      {/* Enc/Dec result */}
      {encDecResult && (
        <div style={{ marginTop: '16px' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px' }}>
            Encryption Steps
          </div>
          <StepDisplay steps={encDecResult.encSteps} />
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginTop: '8px', marginBottom: '4px' }}>
            Decryption Steps
          </div>
          <StepDisplay steps={encDecResult.decSteps} />
          <div className={`counter ${encDecResult.match ? 'good' : 'bad'}`} style={{ marginTop: '8px' }}>
            Dec(k, Enc(k, m)) = m? {encDecResult.match ? '✓ YES' : '✗ NO'}
          </div>
        </div>
      )}

      {/* Nonce reuse attack */}
      {nonceAttackResult && (
        <div style={{ marginTop: '16px' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--accent-rose)', marginBottom: '4px' }}>
            Nonce Reuse Attack Results
          </div>
          <StepDisplay steps={nonceAttackResult.steps} />
        </div>
      )}
    </div>
  );
}
