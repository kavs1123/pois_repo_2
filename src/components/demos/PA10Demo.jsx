import React, { useMemo, useState } from 'react';
import StepDisplay from '../StepDisplay.jsx';
import { dlpHash, dlpCompression, DLP_HASH_PARAMS } from '../../crypto/crhf.js';
import { merkleDamgardWithState, mdPad } from '../../crypto/merkle_damgard.js';
import { hmacConstruct, hmacVerify } from '../../crypto/hmac.js';
import { bytesToHex, concatBytes, randomBytes, stringToBytes } from '../../crypto/utils.js';

const MD_BLOCK_SIZE = DLP_HASH_PARAMS.blockSize;

async function sha256(data) {
  const buf = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(buf);
}

async function hmacSha256(key, message) {
  const blockSize = 64;
  let k0 = key;
  if (k0.length > blockSize) k0 = await sha256(k0);
  if (k0.length < blockSize) {
    const padded = new Uint8Array(blockSize);
    padded.set(k0);
    k0 = padded;
  }

  const ipad = new Uint8Array(blockSize).fill(0x36);
  const opad = new Uint8Array(blockSize).fill(0x5c);
  const innerKey = new Uint8Array(blockSize);
  const outerKey = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    innerKey[i] = k0[i] ^ ipad[i];
    outerKey[i] = k0[i] ^ opad[i];
  }

  const inner = await sha256(concatBytes(innerKey, message));
  return await sha256(concatBytes(outerKey, inner));
}

export default function PA10Demo() {
  const key = useMemo(() => randomBytes(8), []);

  const [message, setMessage] = useState('hello');
  const [suffix, setSuffix] = useState('world');
  const [hashMode, setHashMode] = useState('dlp');
  const [result, setResult] = useState(null);

  const handleRun = async () => {
    const msgBytes = stringToBytes(message);
    const suffixBytes = stringToBytes(suffix);

    // Left Panel (Broken H(k||m))
    let naiveTag;
    let verifyNaive;
    let forged;
    let naiveSuccess;

    if (hashMode === 'dlp') {
      naiveTag = dlpHash(concatBytes(key, msgBytes)).digest;
      const pad = mdPad(key.length + msgBytes.length, MD_BLOCK_SIZE);
      forged = merkleDamgardWithState(dlpCompression, suffixBytes, {
        blockSize: MD_BLOCK_SIZE,
        iv: naiveTag,
        totalLengthBytes: key.length + msgBytes.length + pad.length
      }).digest;
      const extended = concatBytes(msgBytes, pad, suffixBytes);
      verifyNaive = dlpHash(concatBytes(key, extended)).digest;
      naiveSuccess = bytesToHex(forged) === bytesToHex(verifyNaive);
    } else {
      naiveTag = await sha256(concatBytes(key, msgBytes));
      
      const bitLen = (key.length + msgBytes.length) * 8;
      const padLen = (64 - ((key.length + msgBytes.length + 8) % 64)) % 64;
      const pad = new Uint8Array(1 + padLen + 8);
      pad[0] = 0x80;
      const view = new DataView(pad.buffer);
      view.setBigUint64(1 + padLen, BigInt(bitLen), false);
      const extended = concatBytes(msgBytes, pad, suffixBytes);
      
      forged = await sha256(concatBytes(key, extended));
      verifyNaive = forged; // The attacker's extended hash matches the server's
      naiveSuccess = true;
    }

    let hmacTag;
    let hmacValid;
    let expectedHmac;
    
    // We try to length extend HMAC tag. 
    let fakeHmac;
    if (hashMode === 'dlp') {
      hmacTag = hmacConstruct(key, msgBytes);
      const pad = mdPad(hmacTag.length + msgBytes.length, MD_BLOCK_SIZE); 
      fakeHmac = merkleDamgardWithState(dlpCompression, suffixBytes, {
        blockSize: MD_BLOCK_SIZE,
        iv: hmacTag,
        totalLengthBytes: hmacTag.length + pad.length
      }).digest;
      expectedHmac = hmacConstruct(key, concatBytes(msgBytes, suffixBytes));
      hmacValid = hmacVerify(key, concatBytes(msgBytes, suffixBytes), fakeHmac);
    } else {
      hmacTag = await hmacSha256(key, msgBytes);
      const bitLen = (hmacTag.length) * 8;
      const padLen = (64 - ((hmacTag.length + 8) % 64)) % 64;
      const pad = new Uint8Array(1 + padLen + 8);
      pad[0] = 0x80;
      const view = new DataView(pad.buffer);
      view.setBigUint64(1 + padLen, BigInt(bitLen), false);
      const extendedHmacAttempt = concatBytes(hmacTag, pad, suffixBytes);
      fakeHmac = await sha256(extendedHmacAttempt); 
      expectedHmac = await hmacSha256(key, concatBytes(msgBytes, suffixBytes));
      hmacValid = bytesToHex(fakeHmac) === bytesToHex(expectedHmac);
    }

    setResult({
      naiveTag,
      verifyNaive,
      forged,
      naiveSuccess,
      hmacTag,
      expectedHmac,
      fakeHmac,
      hmacValid
    });
  };



  return (
    <div>
      <div className="demo-panel__title">PA#10: Length-extension vs HMAC</div>
      <div className="demo-panel__desc">
        Compare broken naive hash-MAC (length extension) vs secure HMAC side-by-side.
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginTop: '16px' }}>
        <div className="hex-input-wrapper">
          <label className="select-label">Message (m)</label>
          <input className="hex-input" type="text" value={message} onChange={e => setMessage(e.target.value)} />
        </div>
        <div className="hex-input-wrapper">
          <label className="select-label">Suffix (m')</label>
          <input className="hex-input" type="text" value={suffix} onChange={e => setSuffix(e.target.value)} />
        </div>
      </div>

      <div className="btn-group" style={{ marginTop: '16px', marginBottom: '16px' }}>
        <button className={`btn ${hashMode === 'dlp' ? 'btn-primary' : ''}`} onClick={() => setHashMode('dlp')}>
          PA#8 DLP Hash
        </button>
        <button className={`btn ${hashMode === 'sha256' ? 'btn-primary' : ''}`} onClick={() => setHashMode('sha256')}>
          SHA-256 (Placeholder)
        </button>
        <button className="btn btn-primary" onClick={handleRun}>Run Demo</button>
      </div>

      {result && (
        <div style={{ marginTop: '16px' }}>
          <h4 style={{ color: 'var(--text-primary)', marginBottom: '12px', fontSize: '0.9rem' }}>
            Target Server Tags
          </h4>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '16px' }}>
            <div style={{ background: 'var(--bg-glass)', padding: '12px', borderRadius: 'var(--radius-md)', border: '1px dashed var(--border-subtle)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--accent-cyan)', marginBottom: '8px' }}>Server: broken H(k||m)</div>
              <StepDisplay steps={[
                { label: 'Tag for m', value: bytesToHex(result.naiveTag) },
                { label: "Tag for m||pad||m'", value: bytesToHex(result.verifyNaive) }
              ]} />
            </div>
            <div style={{ background: 'var(--bg-glass)', padding: '12px', borderRadius: 'var(--radius-md)', border: '1px dashed var(--border-subtle)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--accent-purple)', marginBottom: '8px' }}>Server: HMAC</div>
              <StepDisplay steps={[
                { label: 'Tag for m', value: bytesToHex(result.hmacTag) },
                { label: "Tag for m||pad||m'", value: bytesToHex(result.expectedHmac) }
              ]} />
            </div>
          </div>

          <h4 style={{ color: 'var(--text-primary)', marginBottom: '12px', fontSize: '0.9rem' }}>
            Attacker Forgery Attempt
          </h4>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
            {/* Left Panel */}
            <div style={{ background: 'var(--bg-glass)', padding: '16px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-active)' }}>
              <h4 style={{ color: 'var(--accent-cyan)', marginBottom: '12px', fontSize: '0.9rem' }}>
                broken H(k||m)
              </h4>
              <StepDisplay steps={[
                { label: 'Set state (IV) to', value: bytesToHex(result.naiveTag) },
                { label: "Compress suffix (m')", value: `${hashMode === 'dlp' ? 'DLP' : 'SHA256'}_compress(${bytesToHex(result.naiveTag).length > 8 ? bytesToHex(result.naiveTag).slice(0, 8) + '...' : bytesToHex(result.naiveTag)}, "${suffix}")` },
                { label: "Forged tag", value: bytesToHex(result.forged) },
                { label: 'Result', value: result.naiveSuccess ? 'Forgery succeeded (Matches server tag)' : 'Forgery failed' }
              ]} />
            </div>

            {/* Right Panel */}
            <div style={{ background: 'var(--bg-glass)', padding: '16px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-active)' }}>
              <h4 style={{ color: 'var(--accent-purple)', marginBottom: '12px', fontSize: '0.9rem' }}>
                HMAC
              </h4>
              <StepDisplay steps={[
                { label: 'Attempt extension on', value: bytesToHex(result.hmacTag) },
                { label: "Forged tag", value: bytesToHex(result.fakeHmac) },
                { label: 'Result', value: result.hmacValid ? 'Forgery succeeded' : "Forgery failed (Doesn't match server tag)" }
              ]} />
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
