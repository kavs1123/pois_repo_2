import React from 'react';

export default function FoundationToggle({ value, onChange }) {
  return (
    <div className="foundation-toggle">
      <span className="foundation-toggle__label">Foundation</span>
      <div className="toggle-group">
        <button
          id="foundation-aes"
          className={`toggle-btn ${value === 'aes' ? 'active' : ''}`}
          onClick={() => onChange('aes')}
        >
          AES-128 (PRP)
        </button>
        <button
          id="foundation-dlp"
          className={`toggle-btn ${value === 'dlp' ? 'active' : ''}`}
          onClick={() => onChange('dlp')}
        >
          DLP (g<sup>x</sup> mod p)
        </button>
      </div>
    </div>
  );
}
