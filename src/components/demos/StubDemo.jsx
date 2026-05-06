import React from 'react';

export default function StubDemo({ pa, title, description }) {
  return (
    <div>
      <div className="demo-panel__title">{title}</div>
      <div className="demo-panel__desc">{description}</div>

      <div className="stub-placeholder">
        <div className="stub-placeholder__icon">🔒</div>
        <div className="stub-placeholder__text">
          Not implemented yet
        </div>
        <div className="stub-placeholder__pa">
          Due: PA#{pa}
        </div>
        <div style={{
          marginTop: '12px',
          fontSize: '0.7rem',
          color: 'var(--text-dim)',
          maxWidth: '400px'
        }}>
          This primitive will be implemented in a future assignment.
          The stub is in place so the app remains fully runnable.
        </div>
      </div>
    </div>
  );
}
