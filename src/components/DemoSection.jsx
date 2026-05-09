import React, { useState } from 'react';
import PA1Demo from './demos/PA1Demo.jsx';
import PA2Demo from './demos/PA2Demo.jsx';
import PA3Demo from './demos/PA3Demo.jsx';
import PA4Demo from './demos/PA4Demo.jsx';
import PA5Demo from './demos/PA5Demo.jsx';
import PA6Demo from './demos/PA6Demo.jsx';
import PA7Demo from './demos/PA7Demo.jsx';
import PA8Demo from './demos/PA8Demo.jsx';
import PA9Demo from './demos/PA9Demo.jsx';
import PA10Demo from './demos/PA10Demo.jsx';
import PA15Demo from './demos/PA15Demo.jsx';
import PA16Demo from './demos/PA16Demo.jsx';
import PA17Demo from './demos/PA17Demo.jsx';
import PA18Demo from './demos/PA18Demo.jsx';
import PA19Demo from './demos/PA19Demo.jsx';
import PA20Demo from './demos/PA20Demo.jsx';
import StubDemo from './demos/StubDemo.jsx';
import { PA_DEMOS } from '../data/reductions.js';

const DEMO_TABS = [
  { id: 1, label: 'PA#1 OWF+PRG' },
  { id: 2, label: 'PA#2 PRF' },
  { id: 3, label: 'PA#3 CPA-Enc' },
  { id: 4, label: 'PA#4 Modes' },
  { id: 5, label: 'PA#5 MAC' },
  { id: 6, label: 'PA#6 CCA' },
  { id: 7, label: 'PA#7 M-D' },
  { id: 8, label: 'PA#8 CRHF' },
  { id: 9, label: 'PA#9 Birthday' },
  { id: 10, label: 'PA#10 HMAC' },
  { id: 15, label: 'PA#15 Signatures' },
  { id: 16, label: 'PA#16 ElGamal' },
  { id: 17, label: 'PA#17 CCA PKC' },
  { id: 18, label: 'PA#18 OT' },
  { id: 19, label: 'PA#19 Secure Gates' },
  { id: 20, label: 'PA#20 MPC' },
];

export default function DemoSection({ activeDemo, onDemoChange, foundation, keyHex }) {
  return (
    <div className="demo-section">
      <div className="demo-tabs">
        {DEMO_TABS.map(tab => (
          <button
            key={tab.id}
            id={`demo-tab-pa${tab.id}`}
            className={`demo-tab ${activeDemo === tab.id ? 'active' : ''}`}
            onClick={() => onDemoChange(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="demo-panel animate-slide-down" key={activeDemo}>
        {renderDemo(activeDemo, foundation, keyHex)}
      </div>
    </div>
  );
}

function renderDemo(id, foundation, keyHex) {
  const info = PA_DEMOS[id];

  switch (id) {
    case 1: return <PA1Demo foundation={foundation} keyHex={keyHex} />;
    case 2: return <PA2Demo keyHex={keyHex} />;
    case 3: return <PA3Demo keyHex={keyHex} />;
    case 4: return <PA4Demo keyHex={keyHex} />;
    case 5: return <PA5Demo />;
    case 6: return <PA6Demo />;
    case 7: return <PA7Demo />;
    case 8: return <PA8Demo />;
    case 9: return <PA9Demo />;
    case 10: return <PA10Demo />;
    case 15: return <PA15Demo />;
    case 16: return <PA16Demo />;
    case 17: return <PA17Demo />;
    case 18: return <PA18Demo />;
    case 19: return <PA19Demo />;
    case 20: return <PA20Demo />;
    default:
      return <StubDemo pa={id} title={info?.title || `PA#${id}`} description={info?.description || 'Not implemented yet.'} />;
  }
}
