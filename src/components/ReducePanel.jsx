import React, { useMemo } from 'react';
import ReductionStages from './ReductionStages.jsx';
import { getPrimitiveStatus } from '../crypto/routing.js';
import { hexToBytes, bytesToHex } from '../crypto/utils.js';
import { ggmPRF, prfEvaluate, prgFromPRF } from '../crypto/prf.js';
import { createPRP, PRP_TO_PRF_PROOF } from '../crypto/prp.js';
import { prgFromAES } from '../crypto/prg.js';
import { prfMac, cbcMac } from '../crypto/mac.js';
import { dlpHash } from '../crypto/crhf.js';
import { hmacConstruct } from '../crypto/hmac.js';

const TARGET_PRIMITIVES = ['OWF', 'OWP', 'PRG', 'PRF', 'PRP', 'MAC', 'CRHF', 'HMAC'];

export default function ReducePanel({ sourcePrimitive, targetPrimitive, onTargetChange, queryHex, onQueryChange, reductionChain, keyHex }) {
  const stages = useMemo(() => {
    try {
      const queryBytes = hexToBytes(queryHex.slice(0, 32).padEnd(32, '0'));
      const keyBytes = hexToBytes(keyHex.slice(0, 32).padEnd(32, '0'));
      return computeReduceStages(sourcePrimitive, targetPrimitive, keyBytes, queryBytes, reductionChain);
    } catch (e) {
      return [{ from: 'Error', to: '?', steps: [{ label: 'Error', value: e.message, className: 'error' }] }];
    }
  }, [sourcePrimitive, targetPrimitive, queryHex, keyHex, reductionChain]);

  const targetStatus = getPrimitiveStatus(targetPrimitive);

  return (
    <div className="panel">
      <div className="panel__header">
        <div className="panel__title">
          <span className="panel__title-icon reduce" />
          Column 2 — Reduce to Target
        </div>
        <span className="panel__badge col2">Leg 2</span>
      </div>

      <div className="select-wrapper">
        <label className="select-label">Target Primitive B</label>
        <select
          id="target-primitive-select"
          className="select-input"
          value={targetPrimitive}
          onChange={e => onTargetChange(e.target.value)}
        >
          {TARGET_PRIMITIVES.map(p => {
            const s = getPrimitiveStatus(p);
            return (
              <option key={p} value={p}>
                {p} {s.implemented ? '' : `(stub — ${s.label})`}
              </option>
            );
          })}
        </select>
      </div>

      <div className="hex-input-wrapper">
        <label className="select-label">Query / Message (hex)</label>
        <input
          id="reduce-query-input"
          className="hex-input"
          type="text"
          value={queryHex}
          onChange={e => onQueryChange(e.target.value.replace(/[^0-9a-fA-F]/g, ''))}
          placeholder="e.g. deadbeef..."
          maxLength={64}
        />
      </div>

      <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginBottom: '8px' }}>
        {sourcePrimitive} → {targetPrimitive}
        {!reductionChain.supported && (
          <span style={{ color: 'var(--accent-rose)', marginLeft: '8px' }}>
            ✗ No reduction path available
          </span>
        )}
      </div>

      <ReductionStages stages={stages} />
    </div>
  );
}

// ─── Stage builders ─────────────────────────────────────────────────────────

function computeReduceStages(source, target, keyBytes, queryBytes, chain) {
  // Identity
  if (source === target) {
    return [{
      from: source, to: target,
      theorem: 'Identity',
      steps: [{ label: 'Observation', value: `${source} = ${target} — no reduction needed` }],
    }];
  }

  // No path
  if (!chain.supported) {
    return [{
      from: source, to: target,
      title: 'No path',
      steps: [
        { label: 'Error', value: chain.message, className: 'error' },
        { label: 'Suggestion', value: 'Try the bidirectional toggle or choose different primitives', className: 'warning' },
      ],
    }];
  }

  // Input header stage (always shown)
  const inputStage = {
    from: 'Input',
    to: source,
    theorem: 'Query / message provided by user',
    steps: [
      { label: 'Source primitive', value: source },
      { label: 'Query / message (hex)', value: bytesToHex(queryBytes) },
    ],
  };

  const key = `${source}→${target}`;

  try {
    switch (key) {

      case 'PRG→PRF': {
        const result = ggmPRF(keyBytes, queryBytes, 8);
        return [
          inputStage,
          {
            from: 'PRG', to: 'PRF',
            theorem: 'GGM Tree: F_k(x) = G_{xₙ}(…G_{x₁}(k))',
            steps: result.steps,
          },
        ];
      }

      case 'PRF→PRP': {
        const prp = createPRP(keyBytes);
        const result = prp.encrypt(queryBytes);
        return [
          inputStage,
          {
            from: 'PRF', to: 'PRP',
            theorem: 'Luby-Rackoff: 3-round Feistel',
            steps: result.steps,
          },
        ];
      }

      case 'PRF→MAC': {
        const tag = prfMac(keyBytes, queryBytes);
        return [
          inputStage,
          {
            from: 'PRF', to: 'MAC',
            theorem: 'PRF-MAC Security Theorem',
            steps: [
              { label: 'Construction', value: 'Mac_k(m) = F_k(m)' },
              { label: 'Tag = F_k(m)', value: bytesToHex(tag) },
            ],
          },
        ];
      }

      case 'PRP→PRF': {
        const out = prfEvaluate(keyBytes, queryBytes);
        return [
          inputStage,
          {
            from: 'PRP', to: 'PRF',
            theorem: 'PRP/PRF Switching Lemma',
            steps: [
              { label: 'Theorem', value: PRP_TO_PRF_PROOF.statement },
              { label: 'Advantage bound', value: 'ε ≤ q²/2ⁿ (negligible)' },
              { label: 'F_k(x) = PRP_k(x)', value: bytesToHex(out) },
            ],
          },
        ];
      }

      case 'PRP→MAC': {
        const prfOut = prfEvaluate(keyBytes, queryBytes);
        const macTag = prfMac(keyBytes, queryBytes);
        return [
          inputStage,
          {
            from: 'PRP', to: 'PRF',
            theorem: 'PRP/PRF Switching Lemma',
            steps: [
              { label: 'Theorem', value: PRP_TO_PRF_PROOF.statement },
              { label: 'PRP used as PRF output', value: bytesToHex(prfOut) },
            ],
          },
          {
            from: 'PRF', to: 'MAC',
            theorem: 'PRF-MAC: Mac_k(m) = F_k(m)',
            steps: [
              { label: 'Construction', value: 'Mac_k(m) = F_k(m)' },
              { label: 'Tag = PRP_k(m)', value: bytesToHex(macTag) },
            ],
          },
        ];
      }

      case 'CRHF→HMAC': {
        const { tag: hmacTag, steps: hmacSteps } = hmacConstruct(keyBytes.slice(0, 8), queryBytes, true);
        return [
          inputStage,
          {
            from: 'CRHF', to: 'HMAC',
            theorem: 'HMAC Security (Bellare, 2006)',
            steps: [
              { label: 'Construction', value: 'HMAC_k(m) = H((k ⊕ opad) ∥ H((k ⊕ ipad) ∥ m))' },
              ...hmacSteps,
            ],
          },
        ];
      }

      case 'HMAC→MAC': {
        const { tag: macTag } = hmacConstruct(keyBytes.slice(0, 8), queryBytes, true);
        return [
          inputStage,
          {
            from: 'HMAC', to: 'MAC',
            theorem: 'HMAC EUF-CMA Security (identity)',
            steps: [
              { label: 'Observation', value: 'HMAC is already a secure EUF-CMA MAC — direct identity' },
              { label: 'HMAC Tag (= MAC Tag)', value: bytesToHex(macTag) },
            ],
          },
        ];
      }

      case 'OWF→PRG': {
        const result = prgFromAES(keyBytes, 32);
        return [
          inputStage,
          {
            from: 'OWF', to: 'PRG',
            theorem: 'HILL hard-core-bit / AES CTR expansion',
            steps: result.steps,
          },
        ];
      }

      case 'PRF→PRG': {
        const result = prgFromPRF(keyBytes);
        return [
          inputStage,
          {
            from: 'PRF', to: 'PRG',
            theorem: 'G(s) = F_s(0) ∥ F_s(1)',
            steps: result.steps,
          },
        ];
      }

      default: {
        // Multi-hop: decompose into per-hop stages using chain.reductions
        if (chain.reductions && chain.reductions.length > 0) {
          const stages = [inputStage];
          for (const red of chain.reductions) {
            const redStatus = getPrimitiveStatus(red.to);
            stages.push({
              from: red.from,
              to: red.to,
              theorem: red.theorem || (red.chain ? red.chain.join(' → ') : 'Reduction'),
              steps: redStatus.implemented
                ? [{ label: `${red.from}→${red.to}`, value: red.chain ? red.chain.join(', ') : 'Direct reduction' }]
                : [{ label: 'Status', value: `Not implemented yet (due: ${redStatus.label})`, className: 'warning' }],
            });
          }
          return stages;
        }
        return [
          inputStage,
          {
            from: source, to: target,
            steps: [{ label: 'Reduction', value: `${source}→${target} — computing chain…` }],
          },
        ];
      }
    }
  } catch (e) {
    return [
      inputStage,
      { from: source, to: target, steps: [{ label: 'Error', value: e.message, className: 'error' }] },
    ];
  }
}
