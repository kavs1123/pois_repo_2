import React, { useState, useEffect, useRef } from 'react';
import StepDisplay from '../StepDisplay.jsx';
import { birthdayAttack } from '../../crypto/birthday.js';
import { dlpHash } from '../../crypto/crhf.js';
import { bytesToHex, stringToBytes } from '../../crypto/utils.js';

export default function PA9Demo() {
  const [bits, setBits] = useState(12);
  const [result, setResult] = useState(null);
  
  // Progress bar and running states
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [fastMode, setFastMode] = useState(false);
  
  // Plotting state
  const [plotData, setPlotData] = useState(null);
  const [isPlotting, setIsPlotting] = useState(false);

  const huntState = useRef({
    evaluations: 0,
    seen: new Map(),
    seenInputs: new Set()
  });

  const fastModeRef = useRef(fastMode);
  useEffect(() => {
    fastModeRef.current = fastMode;
  }, [fastMode]);

  const handleRun = () => {
    if (isRunning || isPlotting) return;
    setIsRunning(true);
    setResult(null);
    setProgress(0);
    setPlotData(null);
    
    huntState.current = {
      evaluations: 0,
      seen: new Map(),
      seenInputs: new Set()
    };
    
    const maxIterations = 200000;
    const expected = Math.sqrt(Math.PI / 2) * Math.pow(2, bits / 2);
    // Sleep duration to make expected iterations take 5 seconds (5000ms)
    const delayMs = 5000 / expected;
    const inputLen = 16; // 16 bytes ensures a massive input space, preventing identical random samples
    
    const step = () => {
      const state = huntState.current;
      const isFast = fastModeRef.current;
      const chunkSize = isFast ? 100 : 1;
      
      for (let i = 0; i < chunkSize; i++) {
        if (state.evaluations >= maxIterations) {
          setIsRunning(false);
          setResult({ found: false, evaluations: state.evaluations });
          return;
        }
        
        let input;
        let inputHex;
        do {
          input = window.crypto.getRandomValues(new Uint8Array(inputLen));
          inputHex = bytesToHex(input);
        } while (state.seenInputs.has(inputHex));
        state.seenInputs.add(inputHex);
        
        const currentDigest = dlpHash(input, { outputBits: bits }).digest;
        const key = bytesToHex(currentDigest);
        
        if (state.seen.has(key)) {
          const other = state.seen.get(key);
          if (bytesToHex(other) !== bytesToHex(input)) {
            setResult({
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
        } else {
          state.seen.set(key, input);
        }
        
        state.evaluations++;
      }
      
      const prog = Math.min(99, (state.evaluations / expected) * 100);
      setProgress(prog);
      
      setTimeout(step, isFast ? 0 : delayMs);
    };
    
    setTimeout(step, fastModeRef.current ? 0 : delayMs);
  };

  const handlePlot = async () => {
    if (isRunning || isPlotting) return;
    setIsPlotting(true);
    setResult(null);
    setPlotData(null);
    setProgress(0);
    
    const results = [];
    const sizes = [8, 10, 12, 14, 16];
    
    for (const n of sizes) {
      let totalEvals = 0;
      // Yield to event loop to allow UI to render the processing message
      await new Promise(resolve => setTimeout(resolve, 20));
      
      for (let i = 0; i < 100; i++) {
        // Use synchronous birthdayAttack function for plotting speed
        const res = birthdayAttack((input) => dlpHash(input, { outputBits: n }).digest, n, 200000);
        totalEvals += res.evaluations;
      }
      
      const avg = totalEvals / 100;
      const expectedCount = Math.sqrt(Math.PI / 2) * Math.pow(2, n / 2);
      results.push({ n, avg, expected: expectedCount });
    }
    
    setPlotData(results);
    setIsPlotting(false);
  };

  return (
    <div>
      <div className="demo-panel__title">PA#9: Birthday Attack</div>
      <div className="demo-panel__desc">
        Run the birthday attack on a truncated hash and compare to the bound.
      </div>

      <div className="slider-wrapper">
        <label>Output bits: {bits}</label>
        <input
          type="range"
          min="8"
          max="16"
          step="2"
          value={bits}
          onChange={e => setBits(Number(e.target.value))}
          style={{ width: '200px' }}
          disabled={isRunning || isPlotting}
        />
      </div>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '16px', marginBottom: '12px' }}>
        <div className="btn-group">
          <button 
            className="btn btn-primary" 
            onClick={handleRun}
            disabled={isRunning || isPlotting}
          >
            {isRunning ? 'Hunting...' : `Collision Hunt (${bits}-bit)`}
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

      {(isRunning || progress > 0) && !result && (
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

      {result && (
        <div style={{ marginTop: '16px', padding: '16px', background: 'var(--bg-glass)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-active)' }}>
          <h4 style={{ color: 'var(--accent-cyan)', marginBottom: '12px', fontSize: '0.9rem' }}>
            {result.found ? 'Collision Found!' : 'No Collision Found'}
          </h4>
          
          <StepDisplay steps={[
            { label: 'Evaluations needed', value: `${result.evaluations}` },
            { label: 'Expected (~√(π/2) * 2^(n/2))', value: `${Math.round(Math.sqrt(Math.PI / 2) * Math.pow(2, bits/2))}` },
            result.found ? { label: 'Input 1', value: bytesToHex(result.input1) } : null,
            result.found ? { label: 'Input 2', value: bytesToHex(result.input2) } : null,
            result.found ? { label: 'Matching Hash', value: bytesToHex(result.digest) } : null
          ].filter(Boolean)} />
        </div>
      )}

      <hr style={{ border: 'none', borderTop: '1px solid var(--border-subtle)', margin: '24px 0' }} />

      <div className="btn-group">
        <button 
          className="btn" 
          style={{ background: 'var(--bg-glass)', borderColor: 'var(--accent-purple)', color: 'var(--accent-purple)' }}
          onClick={handlePlot}
          disabled={isRunning || isPlotting}
        >
          {isPlotting ? 'Running 100 Iterations...' : 'Plot Empirical Bounds'}
        </button>
      </div>
      
      {isPlotting && <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '8px' }}>Processing 100 iterations per size (this may take a moment)...</div>}

      {plotData && (
        <div style={{ marginTop: '20px' }}>
          <h4 style={{ color: 'var(--accent-cyan)', fontSize: '0.85rem', marginBottom: '12px' }}>Empirical vs Theoretical Bound (Avg of 100 runs)</h4>
          
          <div style={{ position: 'relative', marginTop: '20px', paddingBottom: '16px' }}>
            {(() => {
              const maxVal = Math.max(...plotData.map(x => Math.max(x.expected, x.avg)));
              return (
                <svg width="100%" height="220" viewBox="0 0 500 220" style={{ overflow: 'visible' }}>
                  {/* Base Line */}
                  <line x1="0" y1="190" x2="500" y2="190" stroke="var(--border-subtle)" strokeWidth="2" />

                  {/* Empirical Average Bars */}
                  {plotData.map((d, i) => {
                    const x = 50 + i * 100;
                    const y = 190 - (d.avg / maxVal) * 160;
                    const barHeight = 190 - y;
                    return (
                      <g key={`bar-${d.n}`}>
                        <rect x={x - 20} y={y} width="40" height={barHeight} fill="var(--accent-purple)" rx="2">
                          <title>Average: {d.avg.toFixed(1)}</title>
                        </rect>
                        <text x={x} y={210} textAnchor="middle" fill="var(--text-secondary)" fontSize="12" fontFamily="var(--font-sans)">n={d.n}</text>
                        <text x={x} y={y - 8} textAnchor="middle" fill="var(--text-muted)" fontSize="10" fontFamily="var(--font-mono)">{d.avg.toFixed(0)}</text>
                      </g>
                    );
                  })}

                  {/* Expected Average Line Graph */}
                  <polyline
                    fill="none"
                    stroke="var(--accent-cyan)"
                    strokeWidth="2"
                    strokeDasharray="4 4"
                    points={plotData.map((d, i) => `${50 + i * 100},${190 - (d.expected / maxVal) * 160}`).join(' ')}
                  />

                  {/* Expected Average Points */}
                  {plotData.map((d, i) => {
                    const x = 50 + i * 100;
                    const y = 190 - (d.expected / maxVal) * 160;
                    return (
                      <g key={`pt-${d.n}`}>
                        <circle cx={x} cy={y} r="4" fill="var(--bg-primary)" stroke="var(--accent-cyan)" strokeWidth="2">
                          <title>Expected: {d.expected.toFixed(1)}</title>
                        </circle>
                        <text x={x + 12} y={y - 6} fill="var(--accent-cyan)" fontSize="10" fontFamily="var(--font-mono)">{d.expected.toFixed(0)}</text>
                      </g>
                    );
                  })}
                </svg>
              );
            })()}
          </div>
          
          <div style={{ display: 'flex', justifyContent: 'center', gap: '24px', fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <svg width="24" height="12"><line x1="0" y1="6" x2="24" y2="6" stroke="var(--accent-cyan)" strokeWidth="2" strokeDasharray="4 4"/><circle cx="12" cy="6" r="3" fill="var(--bg-primary)" stroke="var(--accent-cyan)" strokeWidth="2"/></svg>
              Expected √(π/2) * 2^(n/2)
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <div style={{ width: '12px', height: '12px', background: 'var(--accent-purple)', borderRadius: '2px' }} /> 
              Empirical Average
            </div>
          </div>
          
          <table className="mode-table" style={{ marginTop: '20px' }}>
            <thead>
              <tr>
                <th>Bits (n)</th>
                <th>Expected</th>
                <th>Average</th>
                <th>Ratio</th>
              </tr>
            </thead>
            <tbody>
              {plotData.map(d => (
                <tr key={d.n}>
                  <td>{d.n}</td>
                  <td>{d.expected.toFixed(1)}</td>
                  <td>{d.avg.toFixed(1)}</td>
                  <td style={{ color: Math.abs(d.avg/d.expected - 1) < 0.2 ? 'var(--accent-cyan)' : 'var(--text-primary)' }}>
                    {(d.avg / d.expected).toFixed(2)}x
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
