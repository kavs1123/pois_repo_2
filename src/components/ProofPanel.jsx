import React, { useState } from 'react';
import { getProofChain, REDUCTION_PROOFS } from '../data/reductions.js';
import { getPrimitiveStatus } from '../crypto/routing.js';

export default function ProofPanel({ source, target, reductionChain, foundation }) {
  const [open, setOpen] = useState(false);

  const proofChain = reductionChain.supported && reductionChain.reductions
    ? getProofChain(reductionChain.reductions)
    : [];

  return (
    <div className="proof-panel">
      <div
        className="proof-panel__header"
        onClick={() => setOpen(!open)}
        id="proof-panel-toggle"
      >
        <div className="proof-panel__title">
          <span className="panel__title-icon proof" />
          Reduction Chain Summary
          <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', fontWeight: 400, marginLeft: '8px' }}>
            {foundation.name} → {source} → {target}
          </span>
        </div>
        <span className={`proof-panel__chevron ${open ? 'open' : ''}`}>▼</span>
      </div>

      <div className={`proof-panel__body ${open ? 'open' : ''}`}>
        <div className="proof-panel__content">
          {/* Chain visualization */}
          <div className="proof-chain">
            <span className="proof-node implemented">{foundation.name}</span>
            <span className="proof-arrow">→</span>
            {reductionChain.path && reductionChain.path.map((node, i) => {
              const status = getPrimitiveStatus(node);
              return (
                <React.Fragment key={i}>
                  <span className={`proof-node ${status.implemented ? 'implemented' : 'stub'}`}>
                    {node}
                    {!status.implemented && <span style={{ fontSize: '0.55rem' }}> ({status.label})</span>}
                  </span>
                  {i < reductionChain.path.length - 1 && <span className="proof-arrow">→</span>}
                </React.Fragment>
              );
            })}
          </div>

          {/* Proof details */}
          {proofChain.length > 0 ? proofChain.map((step, i) => (
            <div className="proof-detail" key={i}>
              <div className="proof-detail__theorem">
                {step.proof.theorem || 'Unknown'} (PA#{Array.isArray(step.proof.pa) ? step.proof.pa.join(', #') : step.proof.pa})
              </div>
              <div className="proof-detail__text">
                <strong>Statement:</strong> {step.proof.statement}
              </div>
              <div className="proof-detail__text">
                <strong>Security:</strong> {step.proof.security}
              </div>
              <div className="proof-detail__text" style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
                {step.proof.construction}
              </div>
            </div>
          )) : (
            <div className="proof-detail">
              <div className="proof-detail__theorem">
                {source === target ? 'Identity' : 'No reduction available'}
              </div>
              <div className="proof-detail__text">
                {source === target
                  ? 'Same primitive — no reduction needed.'
                  : reductionChain.message}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
