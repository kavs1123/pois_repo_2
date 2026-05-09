import React, { useState, useCallback } from 'react';
import {
    crt, rsaDecCRT, integerRoot, rsaKeygenE, hastadAttack,
    hastadMaxBytes, BENCHMARK_DATA,
} from '../../crypto/crt.js';
import { rsaDec, rsaEnc, rsaKeygen, bytesToBigInt, bigIntToBytes, byteLength, pkcs15Enc } from '../../crypto/rsa.js';

const S = {
    panel: { background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', padding: '14px', marginBottom: '12px' },
    hdr: { fontWeight: 700, fontSize: '0.82rem', color: 'var(--accent-cyan)', marginBottom: '10px' },
    dim: { color: 'var(--text-dim)' },
    cyan: { color: 'var(--accent-cyan)' },
    amber: { color: '#f59e0b' },
    green: { color: '#22c55e' },
    red: { color: '#ef4444' },
    mono: { fontFamily: 'var(--font-mono)', fontSize: '0.71rem' },
};
function Btn({ onClick, disabled, children, color = 'var(--accent-cyan)' }) {
    return <button onClick={onClick} disabled={disabled} style={{ padding: '7px 18px', borderRadius: 'var(--radius-md)', border: 'none', background: disabled ? 'var(--bg-glass)' : color, color: disabled ? 'var(--text-dim)' : (color === 'var(--accent-cyan)' ? 'var(--bg-primary)' : '#fff'), cursor: disabled ? 'not-allowed' : 'pointer', fontWeight: 700, fontSize: '0.8rem' }}>{children}</button>;
}
const hexShort = (v, max = 20) => { const s = (typeof v === 'bigint' ? v : BigInt(v)).toString(16); return s.length > max ? `0x${s.slice(0, max)}…` : `0x${s}`; };

// ── Section 1: CRT Solver ─────────────────────────────────────────────────────
const PRESETS = [
    { label: 'x≡2(3),x≡3(5),x≡2(7)', pairs: [{ a: '2', n: '3' }, { a: '3', n: '5' }, { a: '2', n: '7' }] },
    { label: 'x≡1(2),x≡2(3),x≡3(5)', pairs: [{ a: '1', n: '2' }, { a: '2', n: '3' }, { a: '3', n: '5' }] },
    { label: 'x≡0(3),x≡1(4),x≡6(7)', pairs: [{ a: '0', n: '3' }, { a: '1', n: '4' }, { a: '6', n: '7' }] },
];

function CRTSection() {
    const [pairs, setPairs] = useState([{ a: '2', n: '3' }, { a: '3', n: '5' }, { a: '2', n: '7' }]);
    const [result, setResult] = useState(null);
    const [err, setErr] = useState('');

    function solve() {
        try {
            const residues = pairs.map(p => BigInt(p.a));
            const moduli = pairs.map(p => BigInt(p.n));
            for (let i = 0; i < moduli.length; i++)
                for (let j = i + 1; j < moduli.length; j++) {
                    let a = moduli[i], b = moduli[j]; while (b) { const t = b; b = a % b; a = t; }
                    if (a !== 1n) { setErr(`gcd(n${i + 1},n${j + 1})=${a}≠1 — moduli must be pairwise coprime`); return; }
                }
            const N = moduli.reduce((a, b) => a * b, 1n);
            const x = crt(residues, moduli);
            setResult({ x, N, steps: pairs.map((p, i) => ({ a: BigInt(p.a), n: BigInt(p.n), Mi: N / BigInt(p.n) })) });
            setErr('');
        } catch (e) { setErr(e.message); }
    }

    return (
        <div style={S.panel}>
            <div style={S.hdr}>⚙️ CRT Solver — x ≡ aᵢ (mod nᵢ)</div>
            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '10px' }}>
                {PRESETS.map(p => (
                    <button key={p.label} onClick={() => { setPairs(p.pairs); setResult(null); }} style={{ padding: '4px 10px', borderRadius: '12px', border: '1px solid var(--border-subtle)', background: 'transparent', color: 'var(--text-dim)', cursor: 'pointer', fontSize: '0.71rem' }}>{p.label}</button>
                ))}
            </div>
            {pairs.map((p, i) => (
                <div key={i} style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '6px' }}>
                    <span style={{ ...S.dim, fontSize: '0.75rem', width: '20px' }}>x ≡</span>
                    <input className="hex-input" value={p.a} onChange={e => { const np = [...pairs]; np[i] = { ...np[i], a: e.target.value }; setPairs(np); setResult(null); }} style={{ width: '70px' }} placeholder="aᵢ" />
                    <span style={{ ...S.dim, fontSize: '0.75rem' }}>(mod</span>
                    <input className="hex-input" value={p.n} onChange={e => { const np = [...pairs]; np[i] = { ...np[i], n: e.target.value }; setPairs(np); setResult(null); }} style={{ width: '70px' }} placeholder="nᵢ" />
                    <span style={{ ...S.dim, fontSize: '0.75rem' }}>)</span>
                    {pairs.length > 2 && <button onClick={() => { setPairs(pairs.filter((_, j) => j !== i)); setResult(null); }} style={{ background: 'transparent', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', fontSize: '0.9rem' }}>✕</button>}
                </div>
            ))}
            <div style={{ display: 'flex', gap: '8px', marginTop: '8px', flexWrap: 'wrap' }}>
                <Btn onClick={solve}>Solve</Btn>
                <button onClick={() => { setPairs([...pairs, { a: '0', n: '11' }]); setResult(null); }} style={{ padding: '6px 14px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', background: 'transparent', color: 'var(--text-dim)', cursor: 'pointer', fontSize: '0.78rem' }}>+ Add Row</button>
            </div>
            {err && <div style={{ marginTop: '8px', ...S.red, fontSize: '0.72rem' }}>✗ {err}</div>}
            {result && (
                <div style={{ marginTop: '12px', padding: '10px 12px', background: 'var(--bg-glass)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ ...S.mono, fontSize: '0.7rem' }}>
                        <div style={{ marginBottom: '4px' }}><span style={S.dim}>N = n₁·n₂·… = </span><span style={S.cyan}>{result.N.toString()}</span></div>
                        {result.steps.map((s, i) => (
                            <div key={i} style={{ marginBottom: '2px', ...S.dim }}>
                                M{i + 1} = N/n{i + 1} = <span style={S.cyan}>{s.Mi.toString()}</span>
                                {'  '}y{i + 1} = M{i + 1}⁻¹ mod n{i + 1} = <span style={S.cyan}>{(result.x > 0n ? crt([...Array(result.steps.length).fill(0n).map((_, j) => j === i ? 1n : 0n)], result.steps.map(s => s.n)) : 0n).toString()}</span>
                            </div>
                        ))}
                        <div style={{ marginTop: '8px', padding: '8px', background: 'rgba(34,197,94,0.08)', borderRadius: '6px', border: '1px solid #22c55e44' }}>
                            <span style={S.dim}>x = </span><strong style={S.green}>{result.x.toString()}</strong>
                            <span style={{ ...S.dim, marginLeft: '12px', fontSize: '0.68rem' }}>Verify: {result.steps.map((s, i) => `${result.x}≡${result.x % s.n}(mod ${s.n})`).join(', ')}</span>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

// ── Section 2: Garner's RSA Speedup ──────────────────────────────────────────
function GarnerSection() {
    const [liveResult, setLive] = useState(null);
    const [running, setRunning] = useState(false);

    function runLiveBench() {
        setRunning(true); setLive(null);
        setTimeout(() => {
            try {
                const kp = rsaKeygen(512);
                const msgs = Array.from({ length: 20 }, () => { const b = new Uint8Array(4); crypto.getRandomValues(b); return bytesToBigInt(b) % (kp.pk.N - 2n) + 1n; });
                const t1 = performance.now();
                for (const m of msgs) rsaDec(kp.sk, rsaEnc(kp.pk, m));
                const stdMs = (performance.now() - t1) / msgs.length;
                const t2 = performance.now();
                for (const m of msgs) rsaDecCRT(kp.sk, rsaEnc(kp.pk, m));
                const crtMs = (performance.now() - t2) / msgs.length;
                setLive({ stdMs: stdMs.toFixed(3), crtMs: crtMs.toFixed(3), speedup: (stdMs / crtMs).toFixed(2) });
            } catch (e) { console.error(e); }
            setRunning(false);
        }, 10);
    }

    return (
        <div style={S.panel}>
            <div style={S.hdr}>⚡ Garner's Algorithm — CRT-Based RSA Decryption</div>
            <p style={{ ...S.dim, fontSize: '0.72rem', marginBottom: '10px' }}>
                Standard RSA: computes C^d mod N (d ≈ 2048 bits, N ≈ 2048 bits).
                CRT RSA: computes C^dp mod p and C^dq mod q independently, then recombines.
                Since dp, dq ≈ 1024 bits and p, q ≈ 1024 bits, each exponentiation is ~4× cheaper.
            </p>
            <div style={{ ...S.mono, fontSize: '0.69rem', marginBottom: '10px', padding: '8px 10px', background: 'var(--bg-glass)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                <div style={S.dim}>m_p = C^dp mod p &nbsp; m_q = C^dq mod q</div>
                <div style={S.dim}>h = q_inv · (m_p − m_q) mod p</div>
                <div style={{ ...S.cyan, marginTop: '4px' }}>m = m_q + h·q &nbsp; (Garner's recombination)</div>
            </div>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.72rem', marginBottom: '10px' }}>
                <thead>
                    <tr>{['Key Size', 'Standard (ms/op)', 'CRT (ms/op)', 'Speedup'].map(h => <th key={h} style={{ padding: '6px 8px', textAlign: 'left', borderBottom: '1px solid var(--border-subtle)', ...S.dim, fontWeight: 600 }}>{h}</th>)}</tr>
                </thead>
                <tbody>
                    {BENCHMARK_DATA.map(r => (
                        <tr key={r.bits}>
                            <td style={{ padding: '5px 8px', ...S.cyan }}>{r.bits}-bit</td>
                            <td style={{ padding: '5px 8px', ...S.dim }}>{r.standard_ms}</td>
                            <td style={{ padding: '5px 8px', ...S.green }}>{r.crt_ms}</td>
                            <td style={{ padding: '5px 8px' }}><span style={{ color: '#f59e0b', fontWeight: 700 }}>{r.speedup}×</span></td>
                        </tr>
                    ))}
                </tbody>
            </table>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                <Btn onClick={runLiveBench} disabled={running} color="#8b5cf6">{running ? '⏳ Benchmarking…' : '▶ Run Live 512-bit Bench (20 ops)'}</Btn>
                {liveResult && (
                    <span style={{ ...S.mono, fontSize: '0.7rem', ...S.dim }}>
                        std={liveResult.stdMs}ms/op &nbsp; crt={liveResult.crtMs}ms/op &nbsp;
                        <strong style={S.amber}>speedup: {liveResult.speedup}×</strong>
                    </span>
                )}
            </div>
        </div>
    );
}

// ── Section 3: Håstad's Broadcast Attack ─────────────────────────────────────
const MSG_PRESETS = ['Hi', 'OK', 'No', 'Go', 'AB'];

function HastadSection() {
    const [msg, setMsg] = useState('Hi');
    const [usePad, setUsePad] = useState(false);
    const [setup, setSetup] = useState(null);
    const [step, setStep] = useState(0); // 0=idle,1=setup,2=crt,3=root
    const [running, setRunning] = useState(false);

    function runSetup() {
        setRunning(true); setSetup(null); setStep(0);
        setTimeout(() => {
            try {
                const mBytes = new TextEncoder().encode(msg);
                const mInt = bytesToBigInt(mBytes);
                // Generate 3 independent 64-bit RSA key pairs with e=3
                const pairs = [rsaKeygenE(64, 3), rsaKeygenE(64, 3), rsaKeygenE(64, 3)];
                const e = 3n;
                let ciphertexts, ems;
                if (!usePad) {
                    // Textbook: c_i = m^3 mod N_i
                    ciphertexts = pairs.map(kp => mInt ** e % kp.pk.N);
                    ems = null;
                } else {
                    // Padded: each recipient gets different random PS → different EM_i
                    ems = pairs.map(kp => {
                        const k = byteLength(kp.pk.N);
                        const em = new Uint8Array(k);
                        em[0] = 0x00; em[1] = 0x02;
                        const ps = new Uint8Array(k - mBytes.length - 3);
                        let i2 = 0; while (i2 < ps.length) { const b = new Uint8Array(16); crypto.getRandomValues(b); for (const x of b) { if (x && i2 < ps.length) ps[i2++] = x; } }
                        em.set(ps, 2); em[2 + ps.length] = 0x00; em.set(mBytes, 3 + ps.length);
                        return em;
                    });
                    ciphertexts = pairs.map((kp, i) => bytesToBigInt(ems[i]) ** e % kp.pk.N);
                }
                const Ns = pairs.map(kp => kp.pk.N);
                // Run attack
                const { m: recovered, me, success } = hastadAttack(ciphertexts, Ns, 3);
                // Verify
                let recoveredText = '(garbage)';
                if (success) {
                    try { recoveredText = new TextDecoder().decode(bigIntToBytes(recovered, Math.ceil(recovered.toString(2).length / 8))); } catch { }
                } else {
                    recoveredText = `floor(x^⅓) = ${recovered.toString(16).slice(0, 16)}… (not a perfect cube)`;
                }
                setSetup({ pairs, Ns, ciphertexts, me, mInt, e, success, recovered, recoveredText, usePad, ems });
                setStep(1);
            } catch (err) { console.error(err); }
            setRunning(false);
        }, 10);
    }

    const s = setup;
    return (
        <div style={S.panel}>
            <div style={S.hdr}>📡 Håstad's Broadcast Attack (e=3)</div>
            <p style={{ ...S.dim, fontSize: '0.72rem', marginBottom: '10px' }}>
                Sender broadcasts the same message to 3 recipients, each using their own 64-bit N but same exponent e=3.
                The adversary collects c₁,c₂,c₃ and applies CRT to recover m³ exactly, then takes the cube root.
            </p>

            {/* Controls */}
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap', marginBottom: '12px' }}>
                <span style={{ fontSize: '0.72rem', ...S.dim }}>Message:</span>
                {MSG_PRESETS.map(p => (
                    <button key={p} onClick={() => { setMsg(p); setSetup(null); setStep(0); }} style={{ padding: '4px 10px', borderRadius: '12px', fontSize: '0.72rem', cursor: 'pointer', border: `1px solid ${msg === p ? 'var(--accent-cyan)' : 'var(--border-subtle)'}`, background: msg === p ? 'rgba(0,229,255,0.1)' : 'transparent', color: msg === p ? 'var(--accent-cyan)' : 'var(--text-dim)' }}>{p}</button>
                ))}
                <input className="hex-input" value={msg} onChange={e => { setMsg(e.target.value); setSetup(null); setStep(0); }} style={{ width: '80px' }} maxLength={8} />
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginLeft: '8px' }}>
                    <div onClick={() => { setUsePad(p => !p); setSetup(null); setStep(0); }} style={{ width: '36px', height: '20px', borderRadius: '10px', background: usePad ? '#22c55e' : 'var(--bg-glass)', border: `1px solid ${usePad ? '#22c55e' : 'var(--border-subtle)'}`, cursor: 'pointer', position: 'relative', transition: 'all 0.2s' }}>
                        <div style={{ width: '14px', height: '14px', borderRadius: '50%', background: '#fff', position: 'absolute', top: '2px', left: usePad ? '19px' : '2px', transition: 'left 0.2s' }} />
                    </div>
                    <span style={{ fontSize: '0.72rem', color: usePad ? '#22c55e' : 'var(--text-dim)' }}>PKCS padding {usePad ? 'ON (attack fails)' : 'OFF (attack succeeds)'}</span>
                </div>
            </div>

            <Btn onClick={runSetup} disabled={running || !msg}>{running ? '⏳ Running…' : '▶ Run Broadcast Attack'}</Btn>

            {/* Results */}
            {s && step >= 1 && (
                <div style={{ marginTop: '14px' }}>
                    {/* 3 recipient panels */}
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '8px', marginBottom: '12px' }}>
                        {s.pairs.map((kp, i) => (
                            <div key={i} style={{ padding: '8px 10px', background: 'var(--bg-glass)', borderRadius: 'var(--radius-md)', border: `1px solid ${['#00e5ff44', '#f59e0b44', '#8b5cf644'][i]}` }}>
                                <div style={{ fontSize: '0.68rem', fontWeight: 700, marginBottom: '4px', color: ['var(--accent-cyan)', '#f59e0b', '#8b5cf6'][i] }}>Recipient {i + 1}</div>
                                <div style={{ ...S.mono, fontSize: '0.62rem' }}>
                                    <div style={S.dim}>N{i + 1} = <span style={S.cyan}>{hexShort(kp.pk.N, 10)}</span></div>
                                    <div style={S.dim}>e = <span style={S.cyan}>3</span></div>
                                    <div style={S.dim}>c{i + 1} = <span style={{ color: ['var(--accent-cyan)', '#f59e0b', '#8b5cf6'][i] }}>{hexShort(s.ciphertexts[i], 10)}</span></div>
                                    {s.usePad && s.ems && <div style={{ ...S.dim, fontSize: '0.6rem', marginTop: '2px' }}>EM{i + 1}≠EM{(i + 1) % 3 + 1} (random PS!)</div>}
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Attacker panel */}
                    <div style={{ padding: '10px 12px', background: s.success ? 'rgba(239,68,68,0.06)' : 'rgba(34,197,94,0.06)', borderRadius: 'var(--radius-md)', border: `1px solid ${s.success ? '#ef444444' : '#22c55e44'}`, marginBottom: '10px' }}>
                        <div style={{ fontSize: '0.72rem', fontWeight: 700, marginBottom: '8px', color: s.success ? '#ef4444' : '#22c55e' }}>
                            👁 Attacker
                        </div>
                        <div style={{ ...S.mono, fontSize: '0.69rem' }}>
                            <div style={{ marginBottom: '4px' }}>
                                <span style={S.dim}>Step 1 — CRT({`c₁,c₂,c₃`}, {`N₁,N₂,N₃`}) = m³ mod N₁N₂N₃:</span>
                            </div>
                            <div style={{ marginBottom: '8px', wordBreak: 'break-all', padding: '4px 6px', background: 'var(--bg-glass)', borderRadius: '4px', ...S.cyan }}>
                                {s.me.toString(16).slice(0, 48)}{s.me.toString(16).length > 48 ? '…' : ''}
                            </div>
                            <div style={{ marginBottom: '4px' }}>
                                <span style={S.dim}>Step 2 — Integer cube root (Newton's method):</span>
                            </div>
                            <div style={{ marginBottom: '6px', padding: '4px 6px', background: 'var(--bg-glass)', borderRadius: '4px' }}>
                                <span style={S.dim}>floor(x^⅓) = </span>
                                <span style={s.success ? S.red : S.green}>{s.recovered.toString(16).slice(0, 40)}</span>
                            </div>
                            <div style={{ marginBottom: '4px' }}>
                                <span style={S.dim}>Step 3 — Is floor(x^⅓)³ = x exactly? </span>
                                <strong style={s.success ? S.red : S.green}>{s.success ? 'Yes → perfect cube root!' : 'No → not a perfect cube (padding randomized EM)'}</strong>
                            </div>
                        </div>
                    </div>

                    {/* Result banner */}
                    <div style={{ padding: '12px 14px', textAlign: 'center', fontWeight: 800, fontSize: '0.9rem', borderRadius: 'var(--radius-md)', border: `1px solid ${s.success ? '#ef444466' : '#22c55e66'}`, background: s.success ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.1)', color: s.success ? '#ef4444' : '#22c55e' }}>
                        {s.success
                            ? `✗ Plaintext recovered: "${s.recoveredText}" — textbook RSA broken by broadcast attack!`
                            : `✓ Attack failed — PKCS padding randomizes EM, cube root is not exact, plaintext protected.`}
                    </div>
                </div>
            )}

            {/* Theory */}
            <div style={{ marginTop: '12px', padding: '8px 12px', borderRadius: 'var(--radius-md)', background: 'rgba(245,158,11,0.06)', border: '1px solid #f59e0b33', fontSize: '0.71rem', ...S.amber }}>
                <strong>Why it works:</strong> Since m {'<'} min(N_i), we have m³ {'<'} N₁·N₂·N₃ exactly.
                CRT reconstructs m³ <em>as an integer</em>, not just mod something. Integer cube root then gives m directly.
                <strong> Max safe message:</strong> m {'<'} 2^(keyBits/3) — for 64-bit N, any message under 22 bytes works.
                <br /><br />
                <strong>With padding:</strong> Each EM_i is different (random PS bytes), so CRT solves a system with 3 different values — the result is not a perfect cube, and the attack fails.
            </div>
        </div>
    );
}

// ── Main Export ───────────────────────────────────────────────────────────────
export default function PA14Demo() {
    return (
        <div style={{ padding: '0 2px' }}>
            <div style={{ marginBottom: '16px' }}>
                <h2 style={{ ...S.cyan, fontSize: '1.05rem', margin: '0 0 3px' }}>PA#14 · CRT & Håstad's Broadcast Attack</h2>
                <p style={{ ...S.dim, fontSize: '0.73rem', margin: 0 }}>
                    CRT solver · Garner's 4× RSA speedup · Håstad broadcast attack · padding defeats CRT
                </p>
            </div>
            <CRTSection />
            <GarnerSection />
            <HastadSection />
        </div>
    );
}