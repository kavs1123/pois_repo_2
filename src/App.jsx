import React, { useState, useMemo, useCallback } from 'react';
import FoundationToggle from './components/FoundationToggle.jsx';
import BuildPanel from './components/BuildPanel.jsx';
import ReducePanel from './components/ReducePanel.jsx';
import ProofPanel from './components/ProofPanel.jsx';
import DemoSection from './components/DemoSection.jsx';
import { getFoundation } from './crypto/foundation.js';
import { getReductionChain, PRIMITIVES } from './crypto/routing.js';
import { randomBytes, bytesToHex } from './crypto/utils.js';

export default function App() {
  const [foundationType, setFoundationType] = useState('aes');
  const [sourcePrimitive, setSourcePrimitive] = useState('PRG');
  const [targetPrimitive, setTargetPrimitive] = useState('PRF');
  const [keyHex, setKeyHex] = useState(() => bytesToHex(randomBytes(16)));
  const [queryHex, setQueryHex] = useState(() => bytesToHex(randomBytes(16)));
  const [direction, setDirection] = useState('forward'); // 'forward' | 'backward'
  const [activeDemo, setActiveDemo] = useState(1);

  const foundation = useMemo(() => getFoundation(foundationType), [foundationType]);

  const effectiveSource = direction === 'forward' ? sourcePrimitive : targetPrimitive;
  const effectiveTarget = direction === 'forward' ? targetPrimitive : sourcePrimitive;

  const reductionChain = useMemo(
    () => getReductionChain(effectiveSource, effectiveTarget),
    [effectiveSource, effectiveTarget]
  );

  const handleFoundationChange = useCallback((type) => {
    setFoundationType(type);
  }, []);

  return (
    <div className="app-container">
      {/* ── Top Bar ── */}
      <header className="top-bar">
        <div>
          <h1 className="top-bar__title">Minicrypt Clique Explorer</h1>
          <p className="top-bar__subtitle">CS8.401 · Principles of Information Security</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div className="direction-toggle">
            <button
              className={`direction-btn ${direction === 'forward' ? 'active' : ''}`}
              onClick={() => setDirection('forward')}
            >
              Forward A→B
            </button>
            <button
              className={`direction-btn ${direction === 'backward' ? 'active' : ''}`}
              onClick={() => setDirection('backward')}
            >
              Backward B→A
            </button>
          </div>
          <FoundationToggle
            value={foundationType}
            onChange={handleFoundationChange}
          />
        </div>
      </header>

      {/* ── Two-Column Main Area ── */}
      <div className="main-columns">
        <BuildPanel
          foundation={foundation}
          sourcePrimitive={effectiveSource}
          onSourceChange={direction === 'forward' ? setSourcePrimitive : setTargetPrimitive}
          keyHex={keyHex}
          onKeyChange={setKeyHex}
        />
        <ReducePanel
          sourcePrimitive={effectiveSource}
          targetPrimitive={effectiveTarget}
          onTargetChange={direction === 'forward' ? setTargetPrimitive : setSourcePrimitive}
          queryHex={queryHex}
          onQueryChange={setQueryHex}
          reductionChain={reductionChain}
          keyHex={keyHex}
        />
      </div>

      {/* ── Bottom Proof Panel ── */}
      <ProofPanel
        source={effectiveSource}
        target={effectiveTarget}
        reductionChain={reductionChain}
        foundation={foundation}
      />

      {/* ── Demo Section ── */}
      <DemoSection
        activeDemo={activeDemo}
        onDemoChange={setActiveDemo}
        foundation={foundation}
        keyHex={keyHex}
      />
    </div>
  );
}
