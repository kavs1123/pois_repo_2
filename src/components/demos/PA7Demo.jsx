import React, { useMemo, useState } from 'react';
import { merkleDamgard, mdPad, toyCompression } from '../../crypto/merkle_damgard.js';
import { bytesToHex, stringToBytes, concatBytes } from '../../crypto/utils.js';

const BLOCK_SIZE = 8;
const IV = new Uint8Array(4);

export default function PA7Demo() {
  const [message, setMessage] = useState('hello merkle');

  const { chain, blocks } = useMemo(() => {
    const msgBytes = stringToBytes(message);
    const pad = mdPad(msgBytes.length, BLOCK_SIZE);
    const padded = concatBytes(msgBytes, pad);
    const blockList = [];
    for (let i = 0; i < padded.length; i += BLOCK_SIZE) {
      blockList.push(padded.slice(i, i + BLOCK_SIZE));
    }
    
    let cv = new Uint8Array(IV);
    const cvList = [cv];
    for (const b of blockList) {
      cv = toyCompression(cv, b);
      cvList.push(cv);
    }
    return { chain: cvList, blocks: blockList };
  }, [message]);

  return (
    <div>
      <div className="demo-panel__title">PA#7: Merkle-Damgard Transform</div>
      <div className="demo-panel__desc">
        MD-strengthening padding and chaining over a toy compression function.
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

      <div style={{ marginTop: '16px', marginBottom: '8px', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
        Blocks (padded):
      </div>
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '24px' }}>
        {blocks.map((b, i) => (
          <div key={i} style={{ 
            border: '1px solid var(--border-subtle)', 
            padding: '6px 10px', 
            borderRadius: 'var(--radius-sm)', 
            background: 'var(--bg-glass)', 
            fontFamily: 'var(--font-mono)', 
            fontSize: '0.85rem' 
          }}>
            <strong style={{ color: 'var(--accent-cyan)' }}>M<sub>{i + 1}</sub></strong>: {bytesToHex(b)}
          </div>
        ))}
      </div>

      <div style={{ marginTop: '8px', marginBottom: '12px', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
        Animated Merkle-Damgård Chain:
      </div>
      <div key={message} style={{ 
        display: 'flex', 
        flexWrap: 'wrap', 
        alignItems: 'center', 
        gap: '8px', 
        fontFamily: 'var(--font-mono)' 
      }}>
        {chain.map((cv, i) => (
          <React.Fragment key={i}>
            <div
              style={{
                padding: '6px 10px',
                borderRadius: 'var(--radius-sm)',
                background: 'var(--accent-blue-dim)',
                border: '1px solid var(--accent-blue)',
                color: 'var(--accent-blue)',
                fontSize: '0.85rem',
                animation: `stepFadeIn 0.3s ease forwards`,
                animationDelay: `${i * 0.8}s`,
                opacity: 0,
                transform: 'translateX(-8px)'
              }}
            >
              z<sub>{i}</sub> = {bytesToHex(cv)}
            </div>
            {i < chain.length - 1 && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  fontSize: '0.85rem',
                  color: 'var(--text-muted)',
                  animation: `stepFadeIn 0.3s ease forwards`,
                  animationDelay: `${i * 0.8 + 0.4}s`,
                  opacity: 0,
                  transform: 'translateX(-8px)'
                }}
              >
                <span style={{ margin: '0 4px' }}>&rarr;</span>
                <span style={{ 
                  background: 'var(--bg-glass)', 
                  padding: '2px 6px', 
                  borderRadius: 'var(--radius-sm)', 
                  border: '1px solid var(--border-subtle)',
                  color: 'var(--text-secondary)'
                }}>
                  h(z<sub>{i}</sub>, M<sub>{i + 1}</sub>)
                </span>
                <span style={{ margin: '0 4px' }}>&rarr;</span>
              </div>
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}
