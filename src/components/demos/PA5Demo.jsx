import React, { useMemo, useState } from 'react';
import StepDisplay from '../StepDisplay.jsx';
import { cbcMac, macVerify } from '../../crypto/mac.js';
import { merkleDamgard, merkleDamgardWithState, mdPad, toyCompression } from '../../crypto/merkle_damgard.js';
import { bytesToHex, hexToBytes, randomBytes, stringToBytes, concatBytes } from '../../crypto/utils.js';

const ORACLE_QUERIES = 50;
const MD_BLOCK_SIZE = 8;
const MD_IV = new Uint8Array(4);
const KEY_LEN = 8;

export default function PA5Demo() {
  const macKey = useMemo(() => randomBytes(16), []);
  const mdKey = useMemo(() => randomBytes(KEY_LEN), []);

  const [oracleMessages, setOracleMessages] = useState([]);
  const [forgeMsg, setForgeMsg] = useState('forgery');
  const [forgeTagHex, setForgeTagHex] = useState('');
  const [forgeResult, setForgeResult] = useState(null);
  const [forgeCount, setForgeCount] = useState({ attempts: 0, successes: 0 });

  const [leMsg, setLeMsg] = useState('message');
  const [leSuffix, setLeSuffix] = useState('suffix');
  const [leResult, setLeResult] = useState(null);

  const handleGenerateOracle = () => {
    const msgs = [];
    for (let i = 0; i < ORACLE_QUERIES; i++) {
      const msg = randomBytes(8 + (i % 8));
      const tag = cbcMac(macKey, msg);
      msgs.push({ msg, tag });
    }
    setOracleMessages(msgs);
  };

  const handleForge = () => {
    const msgBytes = stringToBytes(forgeMsg);
    const tagBytes = forgeTagHex ? hexToBytes(forgeTagHex) : new Uint8Array(0);
    const valid = macVerify(macKey, msgBytes, tagBytes, 'cbc');
    setForgeResult({ valid, msg: forgeMsg, tag: forgeTagHex });
    setForgeCount(prev => ({
      attempts: prev.attempts + 1,
      successes: prev.successes + (valid ? 1 : 0)
    }));
  };

  const handleLengthExtension = () => {
    const msgBytes = stringToBytes(leMsg);
    const suffixBytes = stringToBytes(leSuffix);

    const base = merkleDamgard(toyCompression, concatBytes(mdKey, msgBytes), {
      blockSize: MD_BLOCK_SIZE,
      iv: MD_IV,
      trace: true
    });

    const pad = mdPad(mdKey.length + msgBytes.length, MD_BLOCK_SIZE);
    const extended = concatBytes(msgBytes, pad, suffixBytes);

    const forged = merkleDamgardWithState(toyCompression, suffixBytes, {
      blockSize: MD_BLOCK_SIZE,
      iv: base.digest,
      trace: true,
      totalLengthBytes: mdKey.length + msgBytes.length + pad.length
    });

    const verify = merkleDamgard(toyCompression, concatBytes(mdKey, extended), {
      blockSize: MD_BLOCK_SIZE,
      iv: MD_IV,
      trace: true
    });

    const forgedSteps = forged.steps.map((step, idx) => {
      if (idx === 1 && step.label === 'IV') {
        return { ...step, label: 'IV (Intercepted Tag t)' };
      }
      return step;
    });

    setLeResult({
      originalTag: base.digest,
      forgedTag: forged.digest,
      verifiedTag: verify.digest,
      success: bytesToHex(forged.digest) === bytesToHex(verify.digest),
      pad,
      extended,
      baseSteps: base.steps,
      forgedSteps
    });
  };

  return (
    <div>
      <div className="demo-panel__title">PA#5: Message Authentication Codes</div>
      <div className="demo-panel__desc">
        PRF-MAC and CBC-MAC with EUF-CMA forgery attempts and a length-extension demo.
      </div>

      <div className="btn-group" style={{ marginBottom: '12px' }}>
        <button className="btn btn-primary" onClick={handleGenerateOracle}>
          Generate MAC Oracle Queries
        </button>
      </div>

      {oracleMessages.length > 0 && (
        <div style={{ marginBottom: '16px' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
            Oracle Messages (first 10 shown)
          </div>
          <div className="test-results">
            {oracleMessages.slice(0, 10).map((row, i) => (
              <div className="test-row" key={i}>
                <span className="test-name">m{i}</span>
                <span className="test-value">{bytesToHex(row.msg)}</span>
                <span className="test-value">tag={bytesToHex(row.tag)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="hex-input-wrapper">
        <label className="select-label">Forgery Message</label>
        <input
          className="hex-input"
          type="text"
          value={forgeMsg}
          onChange={e => setForgeMsg(e.target.value)}
        />
      </div>
      <div className="hex-input-wrapper">
        <label className="select-label">Forgery Tag (hex)</label>
        <input
          className="hex-input"
          type="text"
          value={forgeTagHex}
          onChange={e => setForgeTagHex(e.target.value.replace(/[^0-9a-fA-F]/g, ''))}
        />
      </div>
      <div className="btn-group" style={{ marginBottom: '12px' }}>
        <button className="btn" onClick={handleForge}>Submit Forgery</button>
      </div>

      {forgeResult && (
        <div className="game-panel">
          <div className="game-panel__label">Forgery Result</div>
          <div className={`counter ${forgeResult.valid ? 'bad' : 'good'}`}>
            {forgeResult.valid ? 'FORGERY ACCEPTED (unexpected)' : 'Forgery rejected'}
          </div>
          <div style={{ marginTop: '8px' }}>
            Attempts: {forgeCount.attempts}, Successes: {forgeCount.successes}
          </div>
        </div>
      )}

      <div style={{ marginTop: '20px' }}>
        <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
          Length-Extension Attack (naive MAC = H(k || m))
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
          <div className="hex-input-wrapper">
            <label className="select-label">Message</label>
            <input
              className="hex-input"
              type="text"
              value={leMsg}
              onChange={e => setLeMsg(e.target.value)}
            />
          </div>
          <div className="hex-input-wrapper">
            <label className="select-label">Suffix</label>
            <input
              className="hex-input"
              type="text"
              value={leSuffix}
              onChange={e => setLeSuffix(e.target.value)}
            />
          </div>
        </div>
        <div className="btn-group" style={{ marginTop: '8px' }}>
          <button className="btn btn-primary" onClick={handleLengthExtension}>
            Run Length-Extension Demo
          </button>
        </div>

        {leResult && (
          <div style={{ marginTop: '12px' }}>
            <StepDisplay steps={[
              { label: 'Key length', value: `${mdKey.length} bytes` },
              { label: 'Message', value: bytesToHex(stringToBytes(leMsg)) },
              { label: 'Padding', value: bytesToHex(leResult.pad) },
              { label: 'Suffix bytes (added)', value: bytesToHex(stringToBytes(leSuffix)), className: 'warning' },
              { label: 'Attacker sees tag', value: bytesToHex(leResult.originalTag) },
              { label: 'Extended message', value: bytesToHex(leResult.extended) },
              { label: 'Forged tag', value: bytesToHex(leResult.forgedTag) },
              { label: 'Verified tag', value: bytesToHex(leResult.verifiedTag) },
              { label: 'Result', value: leResult.success ? 'forgery succeeds' : 'forgery fails' }
            ]} />

            <div style={{ marginTop: '12px' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                Attacker Continuation (from known tag)
              </div>
              <StepDisplay steps={leResult.forgedSteps} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
