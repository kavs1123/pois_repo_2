import React from 'react';

export default function StepDisplay({ steps }) {
  if (!steps || steps.length === 0) return null;

  return (
    <div className="step-display">
      {steps.map((step, i) => (
        <div className="step-item" key={i} style={{ animationDelay: `${i * 0.05}s` }}>
          <span className="step-label">{step.label}</span>
          <span className={`step-value ${step.className || ''}`}>{step.value}</span>
        </div>
      ))}
    </div>
  );
}
