import React, { useMemo, useState } from 'react';
import StepDisplay from '../StepDisplay.jsx';
import { cpaEncrypt, cpaDecrypt } from '../../crypto/cpa_enc.js';
import { ccaEncrypt, ccaDecrypt } from '../../crypto/cca_enc.js';
import { bytesToHex, stringToBytes, randomBytes } from '../../crypto/utils.js';

export default function PA6Demo() {
  const kE = useMemo(() => randomBytes(16), []);
  const kM = useMemo(() => randomBytes(16), []);

  const [message, setMessage] = useState('Attack at dusk');
  const [cpaBitIndex, setCpaBitIndex] = useState(0);
  const [ccaBitIndex, setCcaBitIndex] = useState(0);
  const [cpaBase, setCpaBase] = useState(null);
  const [ccaBase, setCcaBase] = useState(null);
  const [cpaFlips, setCpaFlips] = useState(new Set());
  const [ccaFlips, setCcaFlips] = useState(new Set());

  const handleEncrypt = () => {
    const msg = stringToBytes(message);
    setCpaBase(cpaEncrypt(kE, msg));
    setCcaBase(ccaEncrypt(kE, kM, msg));
    setCpaFlips(new Set());
    setCcaFlips(new Set());
  };

  const toggleFlip = (setter, bitIndex) => {
    const key = Number(bitIndex);
    setter(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const applyFlips = (ct, flipSet) => {
    const out = new Uint8Array(ct);
    for (const entry of flipSet) {
      const bit = Number(entry);
      const b = Math.floor(bit / 8);
      const bitInByte = bit % 8;
      if (b >= 0 && b < out.length) {
        out[b] ^= (1 << (7 - bitInByte));
      }
    }
    return out;
  };

  const cpaView = useMemo(() => {
    if (!cpaBase) return null;
    const flipped = applyFlips(cpaBase.ciphertext, cpaFlips);
    const dec = cpaDecrypt(kE, cpaBase.nonce, flipped);
    return { flipped, dec };
  }, [cpaBase, cpaFlips]);

  const ccaView = useMemo(() => {
    if (!ccaBase) return null;
    const flipped = applyFlips(ccaBase.ciphertext, ccaFlips);
    const dec = ccaDecrypt(kE, kM, ccaBase.nonce, flipped, ccaBase.tag);
    return { flipped, dec };
  }, [ccaBase, ccaFlips]);

  const cpaFlippedList = Array.from(cpaFlips).sort((a, b) => a - b);
  const ccaFlippedList = Array.from(ccaFlips).sort((a, b) => a - b);

  const renderHexRow = (bytes, options = {}) => {
    const { highlightDiff = false, compareTo = null } = options;
    const cells = [];
    for (let i = 0; i < bytes.length; i++) {
      const diff = highlightDiff && compareTo && compareTo[i] !== bytes[i];
      const value = bytes[i].toString(16).padStart(2, '0');
      cells.push(
        <span
          key={i}
          style={{
            color: diff ? 'var(--accent-rose)' : 'var(--text-secondary)',
            marginRight: '6px',
            display: 'inline-block',
            minWidth: '20px'
          }}
        >
          {value}
        </span>
      );
    }
    return (
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
        {cells}
      </div>
    );
  };

  const renderHexDiff = (original, actual) => {
    const maxLen = Math.max(original.length, actual.length);
    const cells = [];
    for (let i = 0; i < maxLen; i++) {
      const o = original[i];
      const a = actual[i];
      const diff = o !== a;
      const value = (a ?? 0).toString(16).padStart(2, '0');
      cells.push(
        <span
          key={i}
          style={{
            color: diff ? 'var(--accent-rose)' : 'var(--text-secondary)',
            marginRight: '4px'
          }}
        >
          {value}
        </span>
      );
    }
    return (
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
        {cells}
      </div>
    );
  };

  const truncateHex = (hex, maxLen = 64) => {
    if (hex.length <= maxLen) return hex;
    return hex.slice(0, maxLen) + '...';
  };

  return (
    <div>
      <div className="demo-panel__title">PA#6: CCA-Secure Encryption</div>
      <div className="demo-panel__desc">
        Compare CPA-only malleability vs Encrypt-then-MAC rejection.
      </div>

      <div className="hex-input-wrapper">
        <label className="select-label">Plaintext</label>
        <input
          className="hex-input"
          type="text"
          value={message}
          onChange={e => setMessage(e.target.value)}
        />
      </div>

      <div className="btn-group" style={{ marginBottom: '12px' }}>
        <button className="btn btn-primary" onClick={handleEncrypt}>Encrypt</button>
      </div>

      {(cpaBase && ccaBase) && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
          <div className="panel">
            <div className="panel__title">CPA-only</div>
            <StepDisplay steps={[
              { label: 'Ciphertext', value: truncateHex(bytesToHex(cpaBase.ciphertext)) },
              { label: 'Flipped CT', value: truncateHex(bytesToHex(cpaView.flipped)) },
              { label: 'Decrypted', value: truncateHex(bytesToHex(cpaView.dec.plaintext)) }
            ]} />
            <div style={{ marginTop: '10px' }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px' }}>
                Original (hex)
              </div>
              {renderHexRow(stringToBytes(message))}
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '6px', marginBottom: '4px' }}>
                Decrypted (diff in red)
              </div>
              {renderHexRow(cpaView.dec.plaintext, { highlightDiff: true, compareTo: stringToBytes(message) })}
            </div>
            <div className="slider-wrapper" style={{ marginTop: '12px' }}>
              <label>Bit index: {cpaBitIndex}</label>
              <input
                type="range"
                min="0"
                max={(cpaBase.ciphertext.length * 8) - 1}
                value={cpaBitIndex}
                onChange={e => setCpaBitIndex(Number(e.target.value))}
              />
            </div>
            <div className="btn-group">
              <button className="btn" onClick={() => toggleFlip(setCpaFlips, cpaBitIndex)}>Toggle Bit</button>
            </div>
            <div style={{ marginTop: '8px', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Flipped bits: {cpaFlippedList.length ? cpaFlippedList.join(', ') : 'none'}
            </div>
          </div>

          <div className="panel">
            <div className="panel__title">Encrypt-then-MAC</div>
            <StepDisplay steps={[
              { label: 'Ciphertext', value: truncateHex(bytesToHex(ccaBase.ciphertext)) },
              { label: 'Tag', value: bytesToHex(ccaBase.tag) },
              { label: 'Flipped CT', value: truncateHex(bytesToHex(ccaView.flipped)) },
              { label: 'Decrypt', value: ccaView.dec.valid ? 'accepted' : 'rejected' }
            ]} />
            <div className="slider-wrapper" style={{ marginTop: '12px' }}>
              <label>Bit index: {ccaBitIndex}</label>
              <input
                type="range"
                min="0"
                max={(ccaBase.ciphertext.length * 8) - 1}
                value={ccaBitIndex}
                onChange={e => setCcaBitIndex(Number(e.target.value))}
              />
            </div>
            <div className="btn-group">
              <button className="btn" onClick={() => toggleFlip(setCcaFlips, ccaBitIndex)}>Toggle Bit</button>
            </div>
            <div style={{ marginTop: '8px', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Flipped bits: {ccaFlippedList.length ? ccaFlippedList.join(', ') : 'none'}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
