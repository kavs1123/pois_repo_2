import React, { useState, useEffect, useRef } from 'react';
import {
    millerRabin, carmichaelDemo,
    BENCHMARK_DATA, KNOWN_512_BIT_PRIME,
} from '../../crypto/miller_rabin.js';

const EXAMPLES = [
    { label: '561 — Carmichael number (composite)', value: '561' },
    { label: '2147483647 — 2³¹−1 (Mersenne prime)', value: '2147483647' },
    { label: '4294967291 — known prime (2³²−5)', value: '4294967291' },
    { label: '561001 — composite (= 3×11×17×1001)', value: '561001' },
    { label: '512-bit prime (pre-verified, 40 rounds)', value: KNOWN_512_BIT_PRIME },
];



const Badge = ({ ok }) => (
    <span style={{
        padding: '5px 18px', borderRadius: '20px', fontWeight: 800,
        fontSize: '0.95rem', letterSpacing: '0.04em',
        background: ok ? 'rgba(34,197,94,0.15)' : 'rgba(239,68,68,0.15)',
        color: ok ? '#22c55e' : '#ef4444',
        border: `1px solid ${ok ? '#22c55e55' : '#ef444455'}`,
    }}>
        {ok ? '✓ PROBABLY PRIME' : '✗ COMPOSITE'}
    </span>
);

export default function PA13Demo() {
    const [input, setInput] = useState('561');
    const [rounds, setRounds] = useState(10);
    const [result, setResult] = useState(null);
    const [running, setRunning] = useState(false);
    const [showDrop, setShowDrop] = useState(false);

    const [carmichael] = useState(() => carmichaelDemo());
    const dropRef = useRef(null);

    useEffect(() => {
        const fn = e => { if (dropRef.current && !dropRef.current.contains(e.target)) setShowDrop(false); };
        document.addEventListener('mousedown', fn);
        return () => document.removeEventListener('mousedown', fn);
    }, []);

    function runTest() {
        setRunning(true); setResult(null);
        setTimeout(() => {
            try {
                const n = BigInt(input.trim());
                setResult({ ...millerRabin(n, rounds), n });
            } catch (e) { setResult({ error: e.message }); }
            setRunning(false);
        }, 10);
    }



    const errLabel = `≤ 4⁻${rounds} ≈ 10⁻${Math.round(rounds * Math.log10(4))}`;

    const S = { // shared inline style helpers
        panel: { background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', padding: '14px', marginBottom: '12px' },
        label: { fontSize: '0.7rem', color: 'var(--text-dim)', marginBottom: '4px', display: 'block', fontWeight: 600 },
        mono: { fontFamily: 'var(--font-mono)', fontSize: '0.71rem' },
        dim: { color: 'var(--text-dim)' },
        cyan: { color: 'var(--accent-cyan)' },
        sec: { color: 'var(--text-secondary)' },
        amber: { color: '#f59e0b' },
        green: { color: '#22c55e' },
        red: { color: '#ef4444' },
        hdr: { fontWeight: 700, fontSize: '0.82rem', color: 'var(--accent-cyan)', marginBottom: '10px' },
    };

    return (
        <div style={{ padding: '0 2px' }}>
            {/* ── Header ── */}
            <div style={{ marginBottom: '16px' }}>
                <h2 style={{ ...S.cyan, fontSize: '1.05rem', margin: '0 0 3px' }}>PA#13 · Miller-Rabin Primality Testing</h2>
                <p style={{ ...S.dim, fontSize: '0.73rem', margin: 0 }}>
                    Probabilistic primality test · error probability ≤ 4⁻ᵏ · Carmichael numbers correctly identified
                </p>
            </div>

            {/* ── Tester ── */}
            <div style={S.panel}>
                <div style={S.hdr}>🔬 Primality Tester</div>

                {/* Input with dropdown */}
                <div style={{ position: 'relative', marginBottom: '12px' }} ref={dropRef}>
                    <label style={S.label}>Integer to test (click for examples)</label>
                    <div style={{ position: 'relative' }}>
                        <input
                            className="hex-input"
                            type="text"
                            value={input}
                            onChange={e => setInput(e.target.value.replace(/[^0-9]/g, ''))}
                            onFocus={() => setShowDrop(true)}
                            placeholder="Enter any positive integer…"
                            style={{ paddingRight: '36px', width: '100%', boxSizing: 'border-box' }}
                        />
                        <button onClick={() => setShowDrop(v => !v)} style={{
                            position: 'absolute', right: '8px', top: '50%', transform: 'translateY(-50%)',
                            background: 'none', border: 'none', cursor: 'pointer', ...S.dim, fontSize: '0.7rem',
                        }}>▼</button>
                    </div>

                    {showDrop && (
                        <div style={{
                            position: 'absolute', top: '100%', left: 0, right: 0, zIndex: 200,
                            background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)',
                            borderRadius: 'var(--radius-md)', overflow: 'hidden', boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
                        }}>
                            <div style={{ padding: '6px 10px', fontSize: '0.64rem', ...S.dim, borderBottom: '1px solid var(--border-subtle)' }}>
                                Pre-loaded examples
                            </div>
                            {EXAMPLES.map(ex => (
                                <button key={ex.label} onClick={() => { setInput(ex.value); setShowDrop(false); setResult(null); }}
                                    style={{
                                        display: 'block', width: '100%', textAlign: 'left', padding: '8px 12px',
                                        background: 'none', border: 'none', borderBottom: '1px solid var(--border-subtle)',
                                        cursor: 'pointer', ...S.sec, fontSize: '0.74rem', transition: 'background 0.15s',
                                    }}
                                    onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-glass)'}
                                    onMouseLeave={e => e.currentTarget.style.background = 'none'}
                                >
                                    {ex.label}
                                </button>
                            ))}
                            <button onClick={() => { setInput(''); setShowDrop(false); }}
                                style={{
                                    display: 'block', width: '100%', textAlign: 'left', padding: '8px 12px',
                                    background: 'none', border: 'none', cursor: 'pointer', ...S.cyan, fontSize: '0.74rem',
                                }}>
                                ✏️ Enter your own number
                            </button>
                        </div>
                    )}
                </div>

                {/* Rounds slider */}
                <div style={{ marginBottom: '14px' }}>
                    <label style={S.label}>
                        Rounds k = <strong style={S.cyan}>{rounds}</strong>
                        <span style={{ ...S.dim, fontWeight: 400, marginLeft: '8px' }}>
                            (error probability {errLabel})
                        </span>
                    </label>
                    <input type="range" min={1} max={40} value={rounds}
                        onChange={e => setRounds(Number(e.target.value))}
                        style={{ width: '100%', accentColor: 'var(--accent-cyan)' }} />
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.62rem', ...S.dim }}>
                        <span>k=1 (25% error)</span><span>k=40 (10⁻²⁴ error)</span>
                    </div>
                </div>

                <button onClick={runTest} disabled={running || !input} style={{
                    padding: '8px 22px', borderRadius: 'var(--radius-md)',
                    background: running ? 'var(--bg-glass)' : 'var(--accent-cyan)',
                    color: running ? 'var(--text-dim)' : 'var(--bg-primary)',
                    border: 'none', cursor: running ? 'wait' : 'pointer',
                    fontWeight: 700, fontSize: '0.85rem',
                }}>
                    {running ? '⏳ Testing…' : '▶ Test Primality'}
                </button>

                {/* Results */}
                {result && !result.error && (
                    <div style={{ marginTop: '16px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '10px', flexWrap: 'wrap' }}>
                            <Badge ok={result.result === 'PROBABLY_PRIME'} />
                            <span style={{ ...S.dim, fontSize: '0.71rem' }}>
                                {result.timeMs}ms &nbsp;|&nbsp; n−1 = 2<sup>{result.s?.toString()}</sup> × d
                                &nbsp;|&nbsp; {result.witnesses.length} round(s) run
                            </span>
                        </div>
                        {result.witnesses.length > 0 && (
                            <div style={{ overflowX: 'auto' }}>
                                <table style={{ width: '100%', borderCollapse: 'collapse', ...S.mono }}>
                                    <thead>
                                        <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                                            {['Round', 'Witness a', 'aᵈ mod n', 'Squarings', 'Verdict'].map(h => (
                                                <th key={h} style={{ padding: '4px 8px', textAlign: 'left', ...S.dim, fontWeight: 600 }}>{h}</th>
                                            ))}
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {result.witnesses.map((w, i) => {
                                            const isC = w.verdict === 'COMPOSITE_WITNESS';
                                            const initX = w.steps[0]?.x;
                                            const sq = w.steps.filter(s => s.r > 0).length;
                                            const fmt = v => { const s = v.toString(); return s.length > 16 ? s.slice(0, 16) + '…' : s; };
                                            return (
                                                <tr key={i} style={{ borderBottom: '1px solid var(--border-subtle)', background: isC ? 'rgba(239,68,68,0.06)' : 'transparent' }}>
                                                    <td style={{ padding: '4px 8px', ...S.dim }}>{i + 1}</td>
                                                    <td style={{ padding: '4px 8px', ...S.cyan }}>{fmt(w.a)}</td>
                                                    <td style={{ padding: '4px 8px', ...S.sec }}>{initX != null ? fmt(initX) : '—'}</td>
                                                    <td style={{ padding: '4px 8px', ...S.dim }}>{sq}</td>
                                                    <td style={{ padding: '4px 8px', fontWeight: 700, color: isC ? '#ef4444' : '#22c55e' }}>
                                                        {isC ? '✗ COMPOSITE' : '✓ pass'}
                                                    </td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                )}
                {result?.error && <div style={{ marginTop: '10px', ...S.red, fontSize: '0.75rem' }}>⚠ {result.error}</div>}
            </div>

            {/* ── Carmichael Demo ── */}
            <div style={S.panel}>
                <div style={S.hdr}>⚠️ Carmichael Number Demo — n = 561 = 3 × 11 × 17</div>
                <p style={{ ...S.dim, fontSize: '0.73rem', marginBottom: '10px' }}>
                    561 is composite, but <strong>passes Fermat's test</strong> for every base coprime to it.
                    Miller-Rabin correctly identifies it as COMPOSITE.
                </p>
                <div style={{ fontSize: '0.69rem', ...S.sec, marginBottom: '6px', fontWeight: 600 }}>Fermat test: a^(560) mod 561</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '10px' }}>
                    {carmichael.fermatResults.map(({ a, value, passes }) => (
                        <div key={a.toString()} style={{
                            padding: '4px 10px', borderRadius: '12px', ...S.mono, fontSize: '0.69rem',
                            background: passes ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
                            border: `1px solid ${passes ? '#22c55e33' : '#ef444433'}`,
                            color: passes ? '#22c55e' : '#ef4444',
                        }}>
                            a={a.toString()}: {value.toString()} {passes ? '≡ 1 ✓' : '≢ 1 ✗'}
                        </div>
                    ))}
                </div>
                <div style={{ ...S.amber, fontSize: '0.7rem', marginBottom: '8px' }}>
                    ⚠ All tested bases pass Fermat → naïvely looks prime!
                </div>
                <div style={{
                    padding: '8px 12px', borderRadius: 'var(--radius-md)',
                    background: 'rgba(34,197,94,0.07)', border: '1px solid #22c55e33', fontSize: '0.74rem',
                }}>
                    <span style={{ ...S.green, fontWeight: 700 }}>
                        Miller-Rabin: {carmichael.millerRabinResult.result}
                    </span>
                    <span style={{ ...S.dim, marginLeft: '8px' }}>
                        — correctly identified as COMPOSITE in {carmichael.millerRabinResult.witnesses.length} round(s)
                    </span>
                </div>
            </div>



            {/* ── Benchmark Table ── */}
            <div style={S.panel}>
                <div style={S.hdr}>📊 Benchmark — Candidates Before Finding a Prime</div>
                <p style={{ ...S.dim, fontSize: '0.72rem', marginBottom: '10px' }}>
                    PNT predicts ≈ ln(2ᵇ)/2 = 0.347b candidates. Trial division pre-filtering
                    reduces actual count. Data measured offline (k=40 rounds).
                </p>
                <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', ...S.mono, fontSize: '0.71rem' }}>
                        <thead>
                            <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                                {['Bits', 'Avg Candidates', 'PNT Prediction', 'Ratio', 'Avg Time', 'Notes'].map(h => (
                                    <th key={h} style={{ padding: '5px 8px', textAlign: 'left', ...S.dim, fontWeight: 600 }}>{h}</th>
                                ))}
                            </tr>
                        </thead>
                        <tbody>
                            {BENCHMARK_DATA.map(row => (
                                <tr key={row.bits} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                                    <td style={{ padding: '5px 8px', ...S.cyan, fontWeight: 700 }}>{row.bits}</td>
                                    <td style={{ padding: '5px 8px', ...S.sec }}>{row.avgCandidates ?? '—'}</td>
                                    <td style={{ padding: '5px 8px', ...S.amber }}>{row.pntPrediction}</td>
                                    <td style={{ padding: '5px 8px', ...S.dim }}>{row.ratio != null ? `${row.ratio}×` : '—'}</td>
                                    <td style={{ padding: '5px 8px', ...S.sec }}>{row.avgTimeMs}ms</td>
                                    <td style={{ padding: '5px 8px', ...S.dim, fontSize: '0.64rem' }}>{row.note}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* ── Error Probability Table ── */}
            <div style={S.panel}>
                <div style={S.hdr}>📐 Error Probability Reference</div>
                <table style={{ width: '100%', borderCollapse: 'collapse', ...S.mono, fontSize: '0.71rem' }}>
                    <thead>
                        <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                            {['Rounds k', 'Max Error Probability', 'Suitable for'].map(h => (
                                <th key={h} style={{ padding: '4px 8px', textAlign: 'left', ...S.dim, fontWeight: 600 }}>{h}</th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {[
                            [1, '25%', 'Quick sanity check only'],
                            [5, '~0.098%', 'Low-security applications'],
                            [10, '≈ 10⁻⁶', 'General-purpose testing'],
                            [20, '≈ 10⁻¹²', 'Cryptographic (most libs)'],
                            [40, '≈ 10⁻²⁴', 'High-assurance cryptography'],
                        ].map(([k, err, use]) => (
                            <tr key={k} style={{ borderBottom: '1px solid var(--border-subtle)', background: rounds === k ? 'rgba(0,229,255,0.05)' : 'transparent' }}>
                                <td style={{ padding: '4px 8px', ...S.cyan, fontWeight: rounds === k ? 700 : 400 }}>{k}</td>
                                <td style={{ padding: '4px 8px', ...S.amber }}>{err}</td>
                                <td style={{ padding: '4px 8px', ...S.dim }}>{use}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}