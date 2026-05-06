import React, { useMemo } from 'react';
import ReductionStages from './ReductionStages.jsx';
import { getPrimitiveStatus } from '../crypto/routing.js';
import { hexToBytes, bytesToHex } from '../crypto/utils.js';
import { aesOWF, dlpOWF, DLP_PARAMS } from '../crypto/owf.js';
import { prgFromAES, prgFromDLP } from '../crypto/prg.js';
import { ggmPRF, prfEvaluate } from '../crypto/prf.js';
import { createPRP } from '../crypto/prp.js';
import { aesEncryptBlock } from '../crypto/aes.js';
import { prfMac, cbcMac } from '../crypto/mac.js';
import { dlpHash } from '../crypto/crhf.js';
import { hmacConstruct } from '../crypto/hmac.js';

const SOURCE_PRIMITIVES = ['OWF', 'OWP', 'PRG', 'PRF', 'PRP', 'MAC', 'CRHF', 'HMAC'];

export default function BuildPanel({ foundation, sourcePrimitive, onSourceChange, keyHex, onKeyChange }) {
  const stages = useMemo(() => {
    try {
      const keyBytes = hexToBytes(keyHex.slice(0, 32).padEnd(32, '0'));
      return computeBuildStages(foundation, sourcePrimitive, keyBytes);
    } catch (e) {
      return [{ from: 'Error', to: '?', steps: [{ label: 'Error', value: e.message, className: 'error' }] }];
    }
  }, [foundation, sourcePrimitive, keyHex]);

  const status = getPrimitiveStatus(sourcePrimitive);

  return (
    <div className="panel">
      <div className="panel__header">
        <div className="panel__title">
          <span className="panel__title-icon build" />
          Column 1 — Build from Foundation
        </div>
        <span className="panel__badge col1">Leg 1</span>
      </div>

      <div className="select-wrapper">
        <label className="select-label">Source Primitive A</label>
        <select
          id="source-primitive-select"
          className="select-input"
          value={sourcePrimitive}
          onChange={e => onSourceChange(e.target.value)}
        >
          {SOURCE_PRIMITIVES.map(p => {
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
        <label className="select-label">Key / Seed (hex)</label>
        <input
          id="build-key-input"
          className="hex-input"
          type="text"
          value={keyHex}
          onChange={e => onKeyChange(e.target.value.replace(/[^0-9a-fA-F]/g, ''))}
          placeholder="e.g. a3f2b1c9..."
          maxLength={64}
        />
      </div>

      <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginBottom: '8px' }}>
        {foundation.name} → {sourcePrimitive}
        {!status.implemented && (
          <span style={{ color: 'var(--accent-amber)', marginLeft: '8px' }}>
            ⚠ Not implemented yet (due: {status.label})
          </span>
        )}
      </div>

      <ReductionStages stages={stages} />
    </div>
  );
}

// ─── Stage builders ─────────────────────────────────────────────────────────

function computeBuildStages(foundation, primitive, keyBytes) {
  const isAES = foundation.type === 'aes';
  const foundName = foundation.name;

  // Stage 0 always: Foundation info
  const foundStage = {
    from: 'Input',
    to: foundName,
    title: 'Foundation',
    theorem: isAES ? 'AES-128 concrete PRP/PRF' : 'DLP: gˣ mod p (concrete OWF/OWP)',
    steps: [
      { label: 'Foundation', value: foundName },
      { label: 'Key / Seed (hex)', value: bytesToHex(keyBytes) },
    ],
  };

  switch (primitive) {
    case 'OWF': {
      if (isAES) {
        const result = aesOWF(keyBytes);
        return [
          foundStage,
          {
            from: foundName, to: 'OWF',
            theorem: 'Davies-Meyer: f(k) = AES_k(0¹²⁸)',
            steps: result.steps,
          },
        ];
      } else {
        let val = 0n;
        for (const b of keyBytes) val = (val << 8n) | BigInt(b);
        val = val % DLP_PARAMS.q;
        const result = dlpOWF(val);
        return [
          foundStage,
          {
            from: foundName, to: 'OWF',
            theorem: 'DLP: f(x) = gˣ mod p',
            steps: result.steps,
          },
        ];
      }
    }

    case 'OWP': {
      if (isAES) {
        const out = aesEncryptBlock(keyBytes, new Uint8Array(16));
        return [
          foundStage,
          {
            from: foundName, to: 'OWP',
            theorem: 'AES is a PRP ⇒ OWP by definition',
            steps: [
              { label: 'Observation', value: 'AES is a PRP — a keyed permutation on {0,1}¹²⁸' },
              { label: 'E_k(0¹²⁸)', value: bytesToHex(out) },
            ],
          },
        ];
      } else {
        let val = 0n;
        for (const b of keyBytes) val = (val << 8n) | BigInt(b);
        val = val % DLP_PARAMS.q;
        const result = dlpOWF(val);
        return [
          foundStage,
          {
            from: foundName, to: 'OWP',
            theorem: 'DLP is already a OWP (permutation on ℤ_q)',
            steps: [
              ...result.steps,
              { label: 'Note', value: 'DLP is a bijection on the subgroup — already a OWP' },
            ],
          },
        ];
      }
    }

    case 'PRG': {
      if (isAES) {
        const result = prgFromAES(keyBytes, 32);
        return [
          foundStage,
          {
            from: foundName, to: 'PRF',
            theorem: 'PRP/PRF Switching Lemma',
            steps: [
              { label: 'Route', value: 'AES (PRP) → PRF via switching lemma' },
              { label: 'Advantage bound', value: 'ε ≤ q²/2¹²⁸ (negligible)' },
            ],
          },
          {
            from: 'PRF', to: 'PRG',
            theorem: 'G(s) = F_s(0) ∥ F_s(1)',
            steps: result.steps,
          },
        ];
      } else {
        let val = 0n;
        for (const b of keyBytes) val = (val << 8n) | BigInt(b);
        val = val % DLP_PARAMS.q;
        const result = prgFromDLP(val, 64);
        return [
          foundStage,
          {
            from: foundName, to: 'OWF',
            theorem: 'DLP: f(x) = gˣ mod p',
            steps: [{ label: 'DLP seed', value: val.toString(16).slice(0, 16) + '...' }],
          },
          {
            from: 'OWF', to: 'PRG',
            theorem: 'HILL hard-core-bit construction',
            steps: result.steps,
          },
        ];
      }
    }

    case 'PRF': {
      if (isAES) {
        const input = new Uint8Array(16); input[15] = 42;
        const out = prfEvaluate(keyBytes, input);
        return [
          foundStage,
          {
            from: foundName, to: 'PRF',
            theorem: 'PRP/PRF Switching Lemma',
            steps: [
              { label: 'Route', value: 'AES (PRP) → PRF via switching lemma' },
              { label: 'Advantage bound', value: 'ε ≤ q²/2¹²⁸ (negligible)' },
              { label: 'F_k(0x2a...)', value: bytesToHex(out) },
            ],
          },
        ];
      } else {
        const input = new Uint8Array(16); input[15] = 42;
        const prgResult = (() => {
          let val = 0n;
          for (const b of keyBytes) val = (val << 8n) | BigInt(b);
          return { seed: val % DLP_PARAMS.q };
        })();
        const ggmResult = ggmPRF(keyBytes, input, 8);
        return [
          foundStage,
          {
            from: foundName, to: 'OWF',
            theorem: 'DLP: f(x) = gˣ mod p',
            steps: [{ label: 'DLP seed', value: prgResult.seed.toString(16).slice(0, 16) + '...' }],
          },
          {
            from: 'OWF', to: 'PRG',
            theorem: 'HILL hard-core-bit construction',
            steps: [{ label: 'Route', value: 'DLP seed feeds HILL PRG' }],
          },
          {
            from: 'PRG', to: 'PRF',
            theorem: 'GGM Tree Construction',
            steps: ggmResult.steps,
          },
        ];
      }
    }

    case 'PRP': {
      if (isAES) {
        const block = new Uint8Array(16); block[0] = 0xde; block[1] = 0xad;
        const enc = aesEncryptBlock(keyBytes, block);
        return [
          foundStage,
          {
            from: foundName, to: 'PRP',
            theorem: 'AES is directly a PRP',
            steps: [
              { label: 'Observation', value: 'AES-128 is already a PRP — no construction needed' },
              { label: 'E_k(dead...)', value: bytesToHex(enc) },
            ],
          },
        ];
      } else {
        const prp = createPRP(keyBytes);
        const block = new Uint8Array(16); block[0] = 0xde; block[1] = 0xad;
        const result = prp.encrypt(block);
        return [
          foundStage,
          {
            from: foundName, to: 'PRF',
            theorem: 'DLP → OWF → PRG →[GGM] PRF',
            steps: [{ label: 'Route', value: 'DLP feeds GGM PRG → PRF' }],
          },
          {
            from: 'PRF', to: 'PRP',
            theorem: 'Luby-Rackoff: 3-round Feistel',
            steps: result.steps,
          },
        ];
      }
    }

    case 'MAC': {
      const msg = keyBytes.slice(0, 16);
      if (isAES) {
        const tag = prfMac(keyBytes, msg);
        const cbcTag = cbcMac(keyBytes, msg);
        return [
          foundStage,
          {
            from: foundName, to: 'PRF',
            theorem: 'PRP/PRF Switching Lemma',
            steps: [
              { label: 'Route', value: 'AES (PRP) → PRF via switching lemma' },
              { label: 'Advantage bound', value: 'ε ≤ q²/2¹²⁸' },
            ],
          },
          {
            from: 'PRF', to: 'MAC',
            theorem: 'PRF-MAC: Mac_k(m) = F_k(m)',
            steps: [
              { label: 'Demo message (hex)', value: bytesToHex(msg) },
              { label: 'PRF-MAC tag = F_k(m)', value: bytesToHex(tag) },
              { label: 'CBC-MAC tag (multi-block)', value: bytesToHex(cbcTag) },
            ],
          },
        ];
      } else {
        const tag = prfMac(keyBytes, msg);
        return [
          foundStage,
          {
            from: foundName, to: 'PRF',
            theorem: 'DLP → OWF → PRG →[GGM] PRF',
            steps: [{ label: 'Route', value: 'DLP seed feeds GGM tree → PRF' }],
          },
          {
            from: 'PRF', to: 'MAC',
            theorem: 'PRF-MAC: Mac_k(m) = F_k(m)',
            steps: [
              { label: 'Demo message (hex)', value: bytesToHex(msg) },
              { label: 'PRF-MAC tag = F_k(m)', value: bytesToHex(tag) },
            ],
          },
        ];
      }
    }

    case 'CRHF': {
      const msg = keyBytes.slice(0, 8);
      const { digest, steps: hashSteps } = dlpHash(msg, { trace: true });
      if (isAES) {
        return [
          foundStage,
          {
            from: foundName, to: 'PRF',
            theorem: 'PRP/PRF Switching Lemma',
            steps: [{ label: 'Route', value: 'AES (PRP) → PRF via switching lemma' }],
          },
          {
            from: 'DLP', to: 'Compression fn',
            theorem: 'DLP: h(x,y) = gˣ · hʸ mod p',
            steps: hashSteps.slice(0, 4),
          },
          {
            from: 'Compression fn', to: 'CRHF',
            theorem: 'Merkle-Damgård Transform',
            steps: [
              ...hashSteps.slice(4),
              { label: 'CRHF digest H(m)', value: bytesToHex(digest) },
            ],
          },
        ];
      } else {
        return [
          foundStage,
          {
            from: foundName, to: 'Compression fn',
            theorem: 'DLP: h(x,y) = gˣ · hʸ mod p',
            steps: hashSteps.slice(0, 4),
          },
          {
            from: 'Compression fn', to: 'CRHF',
            theorem: 'Merkle-Damgård Transform',
            steps: [
              ...hashSteps.slice(4),
              { label: 'CRHF digest H(m)', value: bytesToHex(digest) },
            ],
          },
        ];
      }
    }

    case 'HMAC': {
      const msg = keyBytes.slice(0, 8);
      const { tag: hmacTag, steps: hmacSteps } = hmacConstruct(keyBytes.slice(0, 8), msg, true);
      const route = isAES
        ? 'AES (PRF) → CRHF (DLP-MD) → HMAC double-hash'
        : 'DLP → CRHF (DLP-MD) → HMAC double-hash';
      return [
        foundStage,
        {
          from: foundName, to: 'CRHF',
          theorem: 'DLP Merkle-Damgård CRHF',
          steps: [{ label: 'Route', value: route }],
        },
        {
          from: 'CRHF', to: 'HMAC',
          theorem: 'HMAC: H((k⊕opad)∥H((k⊕ipad)∥m))',
          steps: hmacSteps,
        },
      ];
    }

    default:
      return [
        foundStage,
        {
          from: foundName, to: primitive,
          steps: [{ label: 'Unknown', value: `Primitive ${primitive} not recognized`, className: 'error' }],
        },
      ];
  }
}
