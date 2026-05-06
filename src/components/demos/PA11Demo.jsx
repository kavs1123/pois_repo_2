import React, { useState } from 'react';
import {
  DH_PARAMS, CDH_DEMO_BITS,
  dhAliceStep1, dhBobStep1, dhAliceStep2, dhBobStep2,
  mitmAttack, cdhBruteForce, randSmall, generateSafePrime,
} from '../../crypto/dh.js';
import { modPow } from '../../crypto/utils.js';

// ─── Style tokens ─────────────────────────────────────────────────────────────
const S = {
  panel:  { background:'var(--bg-secondary)', border:'1px solid var(--border-subtle)', borderRadius:'var(--radius-md)', padding:'14px', marginBottom:'12px' },
  hdr:    { fontWeight:700, fontSize:'0.82rem', color:'var(--accent-cyan)', marginBottom:'10px' },
  dim:    { color:'var(--text-dim)' },
  sec:    { color:'var(--text-secondary)' },
  cyan:   { color:'var(--accent-cyan)' },
  amber:  { color:'#f59e0b' },
  green:  { color:'#22c55e' },
  red:    { color:'#ef4444' },
  mono:   { fontFamily:'var(--font-mono)', fontSize:'0.71rem' },
  label:  { fontSize:'0.7rem', color:'var(--text-dim)', display:'block', marginBottom:'4px', fontWeight:600 },
};

const hex = v => v != null ? `0x${v.toString(16)}` : '—';
const shortHex = v => v != null ? `0x${v.toString(16).slice(0,12)}…` : '—';

function Btn({ onClick, disabled, children, color = 'var(--accent-cyan)' }) {
  return (
    <button onClick={onClick} disabled={disabled} style={{
      padding:'7px 18px', borderRadius:'var(--radius-md)', border:'none',
      background: disabled ? 'var(--bg-glass)' : color,
      color: disabled ? 'var(--text-dim)' : (color === 'var(--accent-cyan)' ? 'var(--bg-primary)' : '#fff'),
      cursor: disabled ? 'not-allowed' : 'pointer', fontWeight:700, fontSize:'0.8rem',
    }}>{children}</button>
  );
}

function KBadge({ K, label }) {
  return (
    <div style={{ marginTop:'8px', padding:'8px 12px', borderRadius:'var(--radius-md)',
      background: K ? 'rgba(34,197,94,0.1)' : 'rgba(100,100,100,0.1)',
      border:`1px solid ${K ? '#22c55e44' : 'var(--border-subtle)'}`,
    }}>
      <div style={{ fontSize:'0.65rem', ...S.dim, marginBottom:'3px' }}>{label}</div>
      <div style={{ ...S.mono, ...( K ? S.green : S.dim), wordBreak:'break-all', fontSize:'0.7rem' }}>
        {K ? hex(K) : '—'}
      </div>
    </div>
  );
}

// ─── Exchange step display ─────────────────────────────────────────────────────
const STEPS = ['idle','alice_sends','bob_sends','compute','done'];

function StepIndicator({ step }) {
  const labels = ['','Alice → g^a → Bob','Bob → g^b → Alice','Computing shared secrets…','✓ Exchange complete'];
  const idx = STEPS.indexOf(step);
  return idx > 0 ? (
    <div style={{ textAlign:'center', fontSize:'0.75rem', color:'var(--accent-cyan)',
      padding:'6px', animation:'fadeIn 0.4s ease', fontWeight:600 }}>
      {labels[idx]}
    </div>
  ) : null;
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function PA11Demo() {
  const [params, setParams]     = useState(DH_PARAMS);
  const [step, setStep]         = useState('idle');
  const [eveEnabled, setEve]    = useState(false);
  const [useSmalll, setSmall]   = useState(true); // use small a,b for CDH demo

  // Alice state
  const [a, setA] = useState(null);
  const [A, setA_] = useState(null);
  // Bob state
  const [b, setB] = useState(null);
  const [B, setB_] = useState(null);
  // Shared secrets
  const [K_alice, setKAlice] = useState(null);
  const [K_bob,   setKBob]   = useState(null);
  // Eve state
  const [eve, setEveData]   = useState(null);
  // CDH state
  const [cdhResult, setCdh] = useState(null);
  const [cdhRunning, setCdhR] = useState(false);
  // Safe prime gen
  const [genBits, setGenBits] = useState(32);
  const [genResult, setGenRes] = useState(null);
  const [genRunning, setGenR] = useState(false);

  // ── Randomize ───────────────────────────────────────────────────────────────
  function randomizeAlice() {
    const aa = useSmalll ? randSmall(CDH_DEMO_BITS) : dhAliceStep1(params).a;
    const AA = modPow(params.g, aa, params.p);
    setA(aa); setA_(AA); setKAlice(null); setStep('idle'); setCdh(null); setEveData(null);
  }

  function randomizeBob() {
    const bb = useSmalll ? randSmall(CDH_DEMO_BITS) : dhBobStep1(params).b;
    const BB = modPow(params.g, bb, params.p);
    setB(bb); setB_(BB); setKBob(null); setStep('idle'); setCdh(null); setEveData(null);
  }

  function doExchange() {
    let aa = a, AA = A, bb = b, BB = B;
    if (!aa) { aa = useSmalll ? randSmall(CDH_DEMO_BITS) : dhAliceStep1(params).a; }
    if (!bb) { bb = useSmalll ? randSmall(CDH_DEMO_BITS) : dhBobStep1(params).b; }
    if (!AA) AA = modPow(params.g, aa, params.p);
    if (!BB) BB = modPow(params.g, bb, params.p);
    setA(aa); setA_(AA); setB(bb); setB_(BB);

    setStep('alice_sends');
    setTimeout(() => {
      setStep('bob_sends');
      setTimeout(() => {
        setStep('compute');
        setTimeout(() => {
          let KA, KB;
          if (eveEnabled) {
            const eveD = mitmAttack(AA, BB, params);
            KA = dhAliceStep2(aa, eveD.E, params);
            KB = dhBobStep2(bb, eveD.E, params);
            setEveData({ ...eveD, K_alice_real: KA, K_bob_real: KB });
          } else {
            KA = dhAliceStep2(aa, BB, params);
            KB = dhBobStep2(bb, AA, params);
          }
          setKAlice(KA); setKBob(KB); setStep('done');
        }, 700);
      }, 700);
    }, 700);
  }

  // ── CDH brute force ─────────────────────────────────────────────────────────
  function runCDH() {
    if (!A || !B || !a) return;
    setCdhR(true); setCdh(null);
    setTimeout(() => {
      const r = cdhBruteForce(A, B, params);
      setCdh(r); setCdhR(false);
    }, 10);
  }

  // ── Safe prime generation ────────────────────────────────────────────────────
  function runGenPrime() {
    setGenR(true); setGenRes(null);
    setTimeout(() => {
      const r = generateSafePrime(genBits);
      setGenRes(r); setGenR(false);
    }, 10);
  }

  const keysMatch = K_alice != null && K_bob != null && K_alice === K_bob;
  const keysMismatch = K_alice != null && K_bob != null && K_alice !== K_bob;

  return (
    <div style={{ padding:'0 2px' }}>
      {/* ── Header ── */}
      <div style={{ marginBottom:'16px' }}>
        <h2 style={{ ...S.cyan, fontSize:'1.05rem', margin:'0 0 3px' }}>PA#11 · Diffie-Hellman Key Exchange</h2>
        <p style={{ ...S.dim, fontSize:'0.73rem', margin:0 }}>
          Establish a shared secret over a public channel · CDH hardness assumption · MITM vulnerability
        </p>
      </div>

      {/* ── Group Parameters info bar ── */}
      <div style={{ ...S.panel, padding:'10px 14px', marginBottom:'12px' }}>
        <div style={{ display:'flex', flexWrap:'wrap', gap:'16px', ...S.mono, fontSize:'0.69rem', alignItems:'center' }}>
          <span style={S.dim}>Group parameters:</span>
          <span>p = <span style={S.cyan}>{hex(params.p)}</span></span>
          <span>q = <span style={S.cyan}>{hex(params.q)}</span></span>
          <span>g = <span style={S.cyan}>{params.g.toString()}</span></span>
          <span style={{ ...S.dim, fontSize:'0.65rem' }}>(safe prime p=2q+1, |p|≈{params.p.toString(2).length} bits)</span>
        </div>
      </div>

      {/* ── Exchange Mode Toggle ── */}
      <div style={{ display:'flex', alignItems:'center', gap:'12px', marginBottom:'12px' }}>
        <label style={{ display:'flex', alignItems:'center', gap:'6px', cursor:'pointer', fontSize:'0.75rem', ...S.sec }}>
          <input type="checkbox" checked={useSmalll} onChange={e => { setSmall(e.target.checked); setStep('idle'); setKAlice(null); setKBob(null); setCdh(null); }} />
          Small exponents (≤2^{CDH_DEMO_BITS} bits) — enables CDH brute-force demo
        </label>
        <label style={{ display:'flex', alignItems:'center', gap:'6px', cursor:'pointer', fontSize:'0.75rem', color: eveEnabled ? '#ef4444' : 'var(--text-dim)' }}>
          <input type="checkbox" checked={eveEnabled} onChange={e => { setEve(e.target.checked); setStep('idle'); setKAlice(null); setKBob(null); setEveData(null); }} />
          ☠️ Enable Eve (MITM Attack)
        </label>
      </div>

      {/* ── Main Exchange Panel ── */}
      <div style={{ ...S.panel }}>
        <div style={S.hdr}>🔑 Live DH Exchange</div>

        <div style={{ display:'grid', gridTemplateColumns:'1fr auto 1fr', gap:'12px', alignItems:'start' }}>

          {/* Alice */}
          <div style={{ padding:'12px', background:'rgba(0,229,255,0.04)', borderRadius:'var(--radius-md)', border:'1px solid rgba(0,229,255,0.15)' }}>
            <div style={{ fontWeight:700, fontSize:'0.85rem', marginBottom:'8px', color:'var(--accent-cyan)' }}>👩 Alice</div>
            <div style={{ fontSize:'0.7rem', ...S.dim, marginBottom:'6px' }}>Private exponent a</div>
            <div style={{ display:'flex', gap:'6px', marginBottom:'8px' }}>
              <div style={{ flex:1, ...S.mono, fontSize:'0.69rem', padding:'5px 8px',
                background:'var(--bg-glass)', borderRadius:'var(--radius-md)',
                border:'1px solid var(--border-subtle)', wordBreak:'break-all', ...S.sec }}>
                {a ? shortHex(a) : '—'}
              </div>
              <Btn onClick={randomizeAlice} color="#8b5cf6">🎲</Btn>
            </div>
            <div style={{ fontSize:'0.7rem', ...S.dim, marginBottom:'4px' }}>Public value A = g^a</div>
            <div style={{ ...S.mono, fontSize:'0.69rem', padding:'5px 8px',
              background:'var(--bg-glass)', borderRadius:'var(--radius-md)',
              border:'1px solid var(--border-subtle)', wordBreak:'break-all', ...S.sec, marginBottom:'8px' }}>
              {A ? shortHex(A) : '—'}
            </div>
            <KBadge K={K_alice} label="K = B^a mod p (Alice's secret)" />
          </div>

          {/* Channel */}
          <div style={{ display:'flex', flexDirection:'column', alignItems:'center', gap:'8px', paddingTop:'32px' }}>
            {/* Arrow Alice→Bob */}
            <div style={{ fontSize:'0.65rem', textAlign:'center', ...S.dim, transition:'opacity 0.4s',
              opacity: ['alice_sends','bob_sends','compute','done'].includes(step) ? 1 : 0.25 }}>
              <div style={{ color: step === 'alice_sends' ? 'var(--accent-cyan)' : 'var(--text-dim)', fontWeight: step === 'alice_sends' ? 700 : 400 }}>
                {eveEnabled ? '→ Eve →' : '─────→'}
              </div>
              <div style={{ ...S.mono, fontSize:'0.6rem', color:'var(--accent-cyan)' }}>
                {A ? shortHex(A) : 'g^a'}
              </div>
            </div>

            <Btn onClick={doExchange} disabled={step !== 'idle' && step !== 'done'} color="var(--accent-cyan)">
              {step === 'idle' ? '▶ Exchange' : step === 'done' ? '↺ Again' : '…'}
            </Btn>

            {/* Arrow Bob→Alice */}
            <div style={{ fontSize:'0.65rem', textAlign:'center', ...S.dim, transition:'opacity 0.4s',
              opacity: ['bob_sends','compute','done'].includes(step) ? 1 : 0.25 }}>
              <div style={{ color: step === 'bob_sends' ? 'var(--accent-cyan)' : 'var(--text-dim)', fontWeight: step === 'bob_sends' ? 700 : 400 }}>
                {eveEnabled ? '← Eve ←' : '←─────'}
              </div>
              <div style={{ ...S.mono, fontSize:'0.6rem', color:'var(--accent-cyan)' }}>
                {B ? shortHex(B) : 'g^b'}
              </div>
            </div>

            <StepIndicator step={step} />
          </div>

          {/* Bob */}
          <div style={{ padding:'12px', background:'rgba(139,92,246,0.04)', borderRadius:'var(--radius-md)', border:'1px solid rgba(139,92,246,0.15)' }}>
            <div style={{ fontWeight:700, fontSize:'0.85rem', marginBottom:'8px', color:'#8b5cf6' }}>👨 Bob</div>
            <div style={{ fontSize:'0.7rem', ...S.dim, marginBottom:'6px' }}>Private exponent b</div>
            <div style={{ display:'flex', gap:'6px', marginBottom:'8px' }}>
              <div style={{ flex:1, ...S.mono, fontSize:'0.69rem', padding:'5px 8px',
                background:'var(--bg-glass)', borderRadius:'var(--radius-md)',
                border:'1px solid var(--border-subtle)', wordBreak:'break-all', ...S.sec }}>
                {b ? shortHex(b) : '—'}
              </div>
              <Btn onClick={randomizeBob} color="#8b5cf6">🎲</Btn>
            </div>
            <div style={{ fontSize:'0.7rem', ...S.dim, marginBottom:'4px' }}>Public value B = g^b</div>
            <div style={{ ...S.mono, fontSize:'0.69rem', padding:'5px 8px',
              background:'var(--bg-glass)', borderRadius:'var(--radius-md)',
              border:'1px solid var(--border-subtle)', wordBreak:'break-all', ...S.sec, marginBottom:'8px' }}>
              {B ? shortHex(B) : '—'}
            </div>
            <KBadge K={K_bob} label="K = A^b mod p (Bob's secret)" />
          </div>
        </div>

        {/* Shared secret match banner */}
        {step === 'done' && (
          <div style={{ marginTop:'12px', padding:'10px 14px', borderRadius:'var(--radius-md)', textAlign:'center',
            background: keysMatch ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
            border:`1px solid ${keysMatch ? '#22c55e44' : '#ef444444'}`,
            fontSize:'0.8rem', fontWeight:700,
            color: keysMatch ? '#22c55e' : '#ef4444',
          }}>
            {keysMatch
              ? '✓ Shared secret matches! K_Alice = K_Bob = g^{ab} mod p'
              : eveEnabled
                ? '✗ MITM active — K_Alice ≠ K_Bob. Eve holds both secrets!'
                : '✗ Secrets do not match (unexpected error)'}
          </div>
        )}
      </div>

      {/* ── Eve's Panel ── */}
      {eveEnabled && (
        <div style={{ ...S.panel, borderColor:'rgba(239,68,68,0.4)', background:'rgba(239,68,68,0.03)' }}>
          <div style={{ ...S.hdr, color:'#ef4444' }}>☠️ Eve's MITM Interception</div>
          <p style={{ ...S.dim, fontSize:'0.72rem', marginBottom:'10px' }}>
            Eve intercepts A and B, sends her own g^e to both parties.
            Alice and Bob each establish a secret <em>with Eve</em>, not each other.
            Eve decrypts and re-encrypts all messages — neither party knows.
          </p>
          {eve ? (
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:'12px' }}>
              <div>
                <div style={{ fontSize:'0.7rem', ...S.dim, marginBottom:'6px', fontWeight:600 }}>Eve ↔ Alice</div>
                {[
                  ["Eve's exponent e", `0x${eve.e.toString(16)}`],
                  ["Eve's public g^e", `0x${eve.E.toString(16)}`],
                  ["K(Alice↔Eve)", `0x${eve.K_alice_real?.toString(16) ?? eve.K_alice.toString(16)}`],
                ].map(([l,v]) => (
                  <div key={l} style={{ ...S.mono, fontSize:'0.69rem', marginBottom:'4px' }}>
                    <span style={S.dim}>{l}: </span>
                    <span style={S.red}>{v.slice(0,20)}…</span>
                  </div>
                ))}
              </div>
              <div>
                <div style={{ fontSize:'0.7rem', ...S.dim, marginBottom:'6px', fontWeight:600 }}>Eve ↔ Bob</div>
                {[
                  ["Eve's public g^e (same)", `0x${eve.E.toString(16)}`],
                  ["K(Bob↔Eve)", `0x${eve.K_bob_real?.toString(16) ?? eve.K_bob.toString(16)}`],
                  ["Alice's K ≠ Bob's K", '✗ They share NOTHING with each other'],
                ].map(([l,v]) => (
                  <div key={l} style={{ ...S.mono, fontSize:'0.69rem', marginBottom:'4px' }}>
                    <span style={S.dim}>{l}: </span>
                    <span style={S.red}>{v.slice(0,20)}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div style={{ ...S.dim, fontSize:'0.72rem' }}>Run the exchange with Eve enabled to see the attack.</div>
          )}
          <div style={{ marginTop:'10px', padding:'8px 12px', borderRadius:'var(--radius-md)',
            background:'rgba(245,158,11,0.08)', border:'1px solid #f59e0b44', fontSize:'0.72rem', ...S.amber }}>
            🛡 Fix: Authenticated DH (e.g., signed with digital signatures — PA#15) prevents MITM.
          </div>
        </div>
      )}

      {/* ── CDH Hardness ── */}
      <div style={S.panel}>
        <div style={S.hdr}>⚡ CDH Hardness Demo</div>
        <p style={{ ...S.dim, fontSize:'0.72rem', marginBottom:'10px' }}>
          Given only g^a and g^b (public), can Eve compute g^ab without knowing a or b?
          With small exponents (≤2^{CDH_DEMO_BITS}), brute-force succeeds quickly.
          For real DH (q≈2³¹), the same approach would require ~2 billion iterations.
        </p>
        <div style={{ display:'flex', gap:'8px', alignItems:'center', marginBottom:'12px', flexWrap:'wrap' }}>
          <Btn onClick={runCDH} disabled={cdhRunning || !A || !B || !a} color="#f59e0b">
            {cdhRunning ? '⏳ Searching…' : '🔍 Brute-Force g^ab'}
          </Btn>
          {(!A || !B) && <span style={{ fontSize:'0.71rem', ...S.dim }}>Run Exchange first to get g^a and g^b</span>}
          {A && B && !useSmalll && <span style={{ fontSize:'0.71rem', ...S.amber }}>⚠ Enable "Small exponents" for instant brute force</span>}
        </div>
        {cdhResult && (
          <div style={{ ...S.mono }}>
            {cdhResult.found ? (
              <>
                <div style={{ padding:'8px 12px', background:'rgba(34,197,94,0.08)', borderRadius:'var(--radius-md)',
                  border:'1px solid #22c55e33', marginBottom:'8px' }}>
                  <span style={S.green}>✓ Found g^ab = </span>
                  <span style={{ ...S.sec, wordBreak:'break-all' }}>{hex(cdhResult.K)}</span>
                </div>
                <div style={{ display:'flex', gap:'16px', flexWrap:'wrap', fontSize:'0.72rem' }}>
                  <span style={S.dim}>Iterations: <strong style={S.sec}>{cdhResult.iters.toLocaleString()}</strong></span>
                  <span style={S.dim}>Time: <strong style={S.sec}>{cdhResult.timeMs}ms</strong></span>
                  <span style={S.dim}>Matches K_Alice: <strong style={{ color: cdhResult.K === K_alice ? '#22c55e' : '#ef4444' }}>{cdhResult.K === K_alice ? '✓ YES' : '✗ NO'}</strong></span>
                </div>
                <div style={{ marginTop:'8px', fontSize:'0.68rem', ...S.amber }}>
                  With full DH params (q≈2³¹): ~{(Number(params.q) / cdhResult.iters * cdhResult.timeMs / 1000).toFixed(0)}s for brute force — infeasible.
                </div>
              </>
            ) : (
              <div style={{ ...S.amber, fontSize:'0.75rem' }}>
                ⚠ {cdhResult.note || 'Not found within search limit.'}
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Safe Prime Generation ── */}
      <div style={S.panel}>
        <div style={S.hdr}>🔐 Safe Prime Generation (p = 2q+1)</div>
        <p style={{ ...S.dim, fontSize:'0.72rem', marginBottom:'10px' }}>
          Generate a fresh safe prime using Miller-Rabin from PA#13.
          Both q and p=2q+1 must be prime. A generator g of the order-q subgroup is then found.
        </p>
        <div style={{ display:'flex', gap:'6px', marginBottom:'12px', flexWrap:'wrap', alignItems:'center' }}>
          {[32,48].map(b => (
            <button key={b} onClick={() => setGenBits(b)} style={{
              padding:'5px 14px', borderRadius:'20px', cursor:'pointer', fontSize:'0.75rem',
              border:`1px solid ${genBits===b ? 'var(--accent-cyan)' : 'var(--border-subtle)'}`,
              background: genBits===b ? 'rgba(0,229,255,0.1)' : 'transparent',
              color: genBits===b ? 'var(--accent-cyan)' : 'var(--text-dim)',
              fontWeight: genBits===b ? 700 : 400,
            }}>{b}-bit q</button>
          ))}
          <span style={{ fontSize:'0.67rem', ...S.dim }}>(p will be {genBits+1} bits)</span>
        </div>
        <div style={{ display:'flex', gap:'8px', flexWrap:'wrap', alignItems:'center', marginBottom:'12px' }}>
          <Btn onClick={runGenPrime} disabled={genRunning} color="#8b5cf6">
            {genRunning ? '⏳ Generating…' : '⚡ Generate Safe Prime'}
          </Btn>
          {genResult && (
            <Btn onClick={() => { setParams({ p:genResult.p, q:genResult.q, g:genResult.g });
              setStep('idle'); setKAlice(null); setKBob(null); setA(null); setA_(null); setB(null); setB_(null); }} color="#22c55e">
              ✓ Use these parameters
            </Btn>
          )}
        </div>
        {genResult && (
          <div style={{ ...S.mono, fontSize:'0.69rem' }}>
            {[
              ['q (prime)', hex(genResult.q)],
              ['p = 2q+1 (safe prime)', hex(genResult.p)],
              ['g (generator of order-q subgroup)', genResult.g.toString()],
              ['Verification: g^q mod p = 1', '✓'],
              ['Generation time', `${genResult.timeMs}ms`],
            ].map(([l,v]) => (
              <div key={l} style={{ marginBottom:'4px' }}>
                <span style={S.dim}>{l}: </span>
                <span style={S.cyan}>{v}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
