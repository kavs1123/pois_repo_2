import React, { useState, useEffect, useRef } from 'react';
import StepDisplay from '../StepDisplay.jsx';
import { dlpHash } from '../../crypto/crhf.js';
import { bytesToHex, stringToBytes } from '../../crypto/utils.js';

export default function PA8Demo() {
  const [message, setMessage] = useState('dlp hash');
  const [collision, setCollision] = useState(null);
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [fastMode, setFastMode] = useState(false);
  
  const digest = dlpHash(stringToBytes(message)).digest;
  
  // Use refs to store state across the async loop
  const huntState = useRef({
    evaluations: 0,
    seen: new Map(),
    seenInputs: new Set()
  });
  
  const fastModeRef = useRef(fastMode);
  useEffect(() => {
    fastModeRef.current = fastMode;
  }, [fastMode]);

  const handleCollision = () => {
    if (isRunning) return;
    setIsRunning(true);
    setCollision(null);
    setProgress(0);
    
    huntState.current = {
      evaluations: 0,
      seen: new Map(),
      seenInputs: new Set()
    };
    
    const maxIterations = 5000;
    const outputBits = 16;
    const inputLen = 2; // 16 bits is 2 bytes
    
    const step = () => {
      const state = huntState.current;
      const isFast = fastModeRef.current;
      const chunkSize = isFast ? 100 : 1;
      
      for (let i = 0; i < chunkSize; i++) {
        if (state.evaluations >= maxIterations) {
          setIsRunning(false);
          setCollision({ found: false, evaluations: state.evaluations });
          return;
        }
        
        let input;
        let inputHex;
        // Ensure we never sample the same input twice
        do {
          input = window.crypto.getRandomValues(new Uint8Array(inputLen));
          inputHex = bytesToHex(input);
        } while (state.seenInputs.has(inputHex));
        
        state.seenInputs.add(inputHex);
        
        const currentDigest = dlpHash(input, { outputBits }).digest;
        const key = bytesToHex(currentDigest);
        
        if (state.seen.has(key)) {
          const other = state.seen.get(key);
          setCollision({
            found: true,
            evaluations: state.evaluations,
            input1: other,
            input2: input,
            digest: currentDigest
          });
          setProgress(100);
          setIsRunning(false);
          return;
        }
        
        state.seen.set(key, input);
        state.evaluations++;
      }
      
      // Update progress bar
      const expected = 300;
      const prog = Math.min(99, (state.evaluations / expected) * 100);
      setProgress(prog);
      
      setTimeout(step, isFast ? 0 : 16);
    };
    
    setTimeout(step, fastModeRef.current ? 0 : 16);
  };

  return (
    <div>
      <div className="demo-panel__title">PA#8: DLP-Based CRHF</div>
      <div className="demo-panel__desc">
        DLP-based compression with a Merkle-Damgard hash.
      </div>

      <div className="hex-input-wrapper">
        <label className="select-label">Message</label>
        <input
          className="hex-input"
          type="text"
          value={message}
          onChange={e => setMessage(e.target.value)}
        />
      </div>

      <StepDisplay steps={[{ label: 'Digest', value: bytesToHex(digest) }]} />

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '16px' }}>
        <div className="btn-group">
          <button 
            className="btn btn-primary" 
            onClick={handleCollision}
            disabled={isRunning}
          >
            {isRunning ? 'Hunting...' : 'Collision Hunt (16-bit)'}
          </button>
        </div>
        
        <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.8rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
          <input 
            type="checkbox" 
            checked={fastMode} 
            onChange={e => setFastMode(e.target.checked)} 
            style={{ cursor: 'pointer' }}
          />
          Fast Mode (no sleep)
        </label>
      </div>

      {(isRunning || progress > 0) && !collision && (
        <div style={{ marginTop: '16px' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
            Searching... (Evaluations: {huntState.current.evaluations})
          </div>
          <div style={{ width: '100%', height: '8px', background: 'var(--bg-glass)', borderRadius: '4px', overflow: 'hidden' }}>
            <div style={{ 
              width: `${progress}%`, 
              height: '100%', 
              background: 'var(--accent-cyan)', 
              transition: 'width 0.1s linear' 
            }} />
          </div>
        </div>
      )}

      {collision && (
        <div style={{ marginTop: '16px', padding: '16px', background: 'var(--bg-glass)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-active)' }}>
          <h4 style={{ color: 'var(--accent-cyan)', marginBottom: '12px', fontSize: '0.9rem' }}>
            {collision.found ? 'Collision Found!' : 'No Collision Found'}
          </h4>
          
          <StepDisplay steps={[
            { label: 'Evaluations needed', value: `${collision.evaluations}` },
            collision.found ? { label: 'Input 1', value: bytesToHex(collision.input1) } : null,
            collision.found ? { label: 'Input 2', value: bytesToHex(collision.input2) } : null,
            collision.found ? { label: 'Matching Hash', value: bytesToHex(collision.digest) } : null
          ].filter(Boolean)} />
        </div>
      )}
    </div>
  );
}
