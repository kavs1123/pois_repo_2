import React, { useState } from 'react';

/**
 * A single collapsible stage card.
 * stage: { title, from, to, theorem?, steps: [{label, value, className?}] }
 */
function StageCard({ stage, index, defaultOpen }) {
  const [open, setOpen] = useState(defaultOpen);

  const isError = stage.steps?.some(s => s.className === 'error');
  const isWarn  = stage.steps?.some(s => s.className === 'warning');
  const accentColor = isError
    ? 'var(--accent-rose)'
    : isWarn
      ? 'var(--accent-amber)'
      : 'var(--accent-cyan)';

  return (
    <div
      style={{
        border: `1px solid ${open ? accentColor : 'var(--border-subtle)'}`,
        borderRadius: 'var(--radius-md)',
        marginBottom: '6px',
        overflow: 'hidden',
        transition: 'border-color 0.2s ease',
        background: open ? 'var(--bg-glass)' : 'transparent',
      }}
    >
      {/* Header row */}
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: '100%',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '8px 10px',
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          textAlign: 'left',
        }}
      >
        {/* Step index badge */}
        <span style={{
          flexShrink: 0,
          width: '18px',
          height: '18px',
          borderRadius: '50%',
          background: accentColor,
          color: 'var(--bg-primary)',
          fontSize: '0.65rem',
          fontWeight: 700,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}>
          {index + 1}
        </span>

        {/* From → To arrow pill */}
        <span style={{
          display: 'flex',
          alignItems: 'center',
          gap: '4px',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.78rem',
        }}>
          <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>{stage.from}</span>
          <span style={{ color: 'var(--text-dim)', fontSize: '0.7rem' }}>→</span>
          <span style={{ color: accentColor, fontWeight: 700 }}>{stage.to}</span>
        </span>

        {/* Title / theorem label */}
        <span style={{
          flex: 1,
          fontSize: '0.7rem',
          color: 'var(--text-dim)',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}>
          {stage.theorem || stage.title || ''}
        </span>

        {/* Chevron */}
        <span style={{
          flexShrink: 0,
          fontSize: '0.6rem',
          color: 'var(--text-dim)',
          transform: open ? 'rotate(180deg)' : 'rotate(0deg)',
          transition: 'transform 0.2s ease',
        }}>▼</span>
      </button>

      {/* Collapsible body */}
      {open && (
        <div style={{ padding: '0 10px 10px 10px' }}>
          {/* Thin accent separator */}
          <div style={{
            height: '1px',
            background: `linear-gradient(to right, ${accentColor}55, transparent)`,
            marginBottom: '8px',
          }} />

          {stage.steps && stage.steps.length > 0 ? (
            <div className="step-display" style={{ gap: '4px' }}>
              {stage.steps.map((step, i) => (
                <div
                  className="step-item"
                  key={i}
                  style={{ animationDelay: `${i * 0.04}s` }}
                >
                  <span className="step-label">{step.label}</span>
                  <span className={`step-value ${step.className || ''}`}
                    style={{ wordBreak: 'break-all', fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}
                  >
                    {step.value}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>No computation steps.</span>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * Renders an ordered list of collapsible reduction stage cards.
 * stages: Array of { from, to, title?, theorem?, steps[] }
 */
export default function ReductionStages({ stages }) {
  if (!stages || stages.length === 0) return null;

  return (
    <div style={{ marginTop: '4px' }}>
      {stages.map((stage, i) => (
        <StageCard
          key={`${stage.from}-${stage.to}-${i}`}
          stage={stage}
          index={i}
          defaultOpen={i === stages.length - 1} // Last (final) stage open by default
        />
      ))}
    </div>
  );
}
