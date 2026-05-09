import React, { useState, useRef, useCallback, useEffect } from 'react';
import { pkcs15Enc, bytesToBigInt, bigIntToBytes, byteLength, rsaEnc, rsaDec } from '../../crypto/rsa.js';

// ── Styles ────────────────────────────────────────────────────────────────────
const S = {
    panel: { background: 'var(--bg-secondary)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', padding: '14px', marginBottom: '12px' },
    hdr: { fontWeight: 700, fontSize: '0.82rem', color: 'var(--accent-cyan)', marginBottom: '10px' },
    dim: { color: 'var(--text-dim)' },
    sec: { color: 'var(--text-secondary)' },
    cyan: { color: 'var(--accent-cyan)' },
    amber: { color: '#f59e0b' },
    green: { color: '#22c55e' },
    red: { color: '#ef4444' },
    mono: { fontFamily: 'var(--font-mono)', fontSize: '0.71rem' },
    label: { fontSize: '0.7rem', color: 'var(--text-dim)', display: 'block', marginBottom: '4px', fontWeight: 600 },
};

function Btn({ onClick, disabled, children, color = 'var(--accent-cyan)' }) {
    return (
        <button onClick={onClick} disabled={disabled} style={{
            padding: '7px 18px', borderRadius: 'var(--radius-md)', border: 'none',
            background: disabled ? 'var(--bg-glass)' : color,
            color: disabled ? 'var(--text-dim)' : (color === 'var(--accent-cyan)' ? 'var(--bg-primary)' : '#fff'),
            cursor: disabled ? 'not-allowed' : 'pointer', fontWeight: 700, fontSize: '0.8rem',
        }}>{children}</button>
    );
}

const hex = (v, max = 32) => { const s = typeof v === 'bigint' ? v.toString(16) : v; return s.length > max ? `0x${s.slice(0, max)}…` : `0x${s}`; };
const fromHex = s => BigInt('0x' + s);

// ── Worker helper ─────────────────────────────────────────────────────────────
function makeWorker() {
    return new Worker(new URL('../../crypto/rsaWorker.js', import.meta.url), { type: 'module' });
}

function workerCall(worker, msg) {
    return new Promise((resolve, reject) => {
        const id = Math.random().toString(36).slice(2);
        const handler = (e) => {
            if (e.data.id !== id) return;
            if (e.data.action === 'error') { worker.removeEventListener('message', handler); reject(new Error(e.data.message)); return; }
            if (['keygen_done', 'keygen_encrypt_done'].includes(e.data.action)) {
                worker.removeEventListener('message', handler); resolve(e.data);
            }
        };
        worker.addEventListener('message', handler);
        worker.postMessage({ ...msg, id });
    });
}

// ── Padding Inspector ─────────────────────────────────────────────────────────
function PaddingVisual({ em, label }) {
    if (!em) return null;
    const bytes = Array.from(em);
    let sepIdx = -1;
    for (let i = 2; i < bytes.length; i++) { if (bytes[i] === 0) { sepIdx = i; break; } }
    const getColor = i => i <= 1 ? '#00e5ff' : (i < sepIdx ? '#f59e0b' : (i === sepIdx ? 'var(--text-dim)' : '#22c55e'));
    return (
        <div style={{ marginBottom: '10px' }}>
            <div style={{ fontSize: '0.68rem', ...S.dim, marginBottom: '4px', fontWeight: 600 }}>{label}</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '2px' }}>
                {bytes.map((b, i) => (
                    <div key={i} style={{
                        padding: '2px 4px', borderRadius: '3px', ...S.mono, fontSize: '0.61rem',
                        background: `${getColor(i)}22`, color: getColor(i), border: `1px solid ${getColor(i)}44`
                    }}>
                        {b.toString(16).padStart(2, '0')}
                    </div>
                ))}
            </div>
            <div style={{ display: 'flex', gap: '10px', marginTop: '4px', fontSize: '0.61rem' }}>
                {[['00 02', 'Header', '#00e5ff'], ['PS', 'Random nonzero', '#f59e0b'], ['00', 'Separator', 'var(--text-dim)'], ['m', 'Message', '#22c55e']].map(([k, l, c]) => (
                    <span key={k}><span style={{ color: c, fontFamily: 'monospace' }}>{k}</span> <span style={S.dim}>{l}</span></span>
                ))}
            </div>
        </div>
    );
}

// ── Main Component ────────────────────────────────────────────────────────────
export default function PA12Demo() {
    // Keys section
    const [keyBits, setKeyBits] = useState(512);
    const [keys, setKeys] = useState(null);   // { pk, sk, timeMs } — BigInt values
    const [keyGen, setKeyGen] = useState(false);
    // Determinism section
    const [mode, setMode] = useState('textbook');
    const [msg, setMsg] = useState('Yes');
    const [enc1, setEnc1] = useState(null);
    const [enc2, setEnc2] = useState(null);
    const [encrypting, setEncrypting] = useState(false);
    // Bleichenbacher section
    const [bNbits, setBNbits] = useState(64);
    const [bSetup, setBSetup] = useState(null);   // { pk, sk, c, em, timeMs }
    const [bSetupRunning, setBSetupR] = useState(false);
    const [bRunning, setBRunning] = useState(false);
    const [bLog, setBLog] = useState([]);
    const [bResult, setBResult] = useState(null);

    const workerRef = useRef(null);
    const bWorkerRef = useRef(null);

    useEffect(() => {
        const w1 = makeWorker();
        const w2 = makeWorker();
        w1.onerror = (e) => console.error('[RSA Worker 1]', e.message);
        w2.onerror = (e) => {
            console.error('[RSA Worker 2]', e.message);
            setBLog(prev => [...prev, `[Worker Error] ${e.message}`]);
            setBSetupR(false); setBRunning(false);
        };
        workerRef.current = w1;
        bWorkerRef.current = w2;
        return () => { w1.terminate(); w2.terminate(); };
    }, []);

    // Deserialize pk/sk from worker (hex strings → BigInt)
    function desPk(pk) { return { N: fromHex(pk.N), e: fromHex(pk.e) }; }
    function desSk(sk) { return { N: fromHex(sk.N), d: fromHex(sk.d), p: fromHex(sk.p), q: fromHex(sk.q), dp: fromHex(sk.dp), dq: fromHex(sk.dq), q_inv: fromHex(sk.q_inv) }; }

    // ── Key generation ──────────────────────────────────────────────────────────
    async function genKeys() {
        setKeyGen(true); setKeys(null); setEnc1(null); setEnc2(null);
        try {
            const r = await workerCall(workerRef.current, { action: 'keygen', bits: keyBits });
            setKeys({ pk: desPk(r.pk), sk: desSk(r.sk), timeMs: r.timeMs, pkRaw: r.pk, skRaw: r.sk });
        } catch (e) { console.error(e); }
        setKeyGen(false);
    }

    // ── Determinism demo ────────────────────────────────────────────────────────
    function encryptTwice() {
        if (!keys) return;
        setEncrypting(true); setEnc1(null); setEnc2(null);
        setTimeout(() => {
            try {
                const mBytes = new TextEncoder().encode(msg);
                let r1, r2;
                if (mode === 'textbook') {
                    const m = bytesToBigInt(mBytes);
                    r1 = { c: rsaEnc(keys.pk, m), em: null };
                    r2 = { c: rsaEnc(keys.pk, m), em: null };
                } else {
                    r1 = pkcs15Enc(keys.pk, mBytes);
                    r2 = pkcs15Enc(keys.pk, mBytes);
                }
                setEnc1(r1); setEnc2(r2);
            } catch (e) { console.error(e); }
            setEncrypting(false);
        }, 10);
    }

    // ── Bleichenbacher: setup (toy keygen in worker) ─────────────────────────────
    async function setupBleichenbacher() {
        setBSetupR(true); setBSetup(null); setBLog([]); setBResult(null);
        try {
            const r = await workerCall(bWorkerRef.current, { action: 'keygen_encrypt_toy', message: 'Y' });
            setBSetup({
                pk: desPk(r.pk), sk: desSk(r.sk),
                pkRaw: r.pk, skRaw: r.sk,
                c: r.c, em: r.em, timeMs: r.timeMs,
            });
        } catch (e) {
            console.error(e);
            setBLog([`[Setup Error] ${e.message}`]);
        }
        setBSetupR(false);
    }

    // ── Bleichenbacher: run attack ──────────────────────────────────────────────
    function runAttack() {
        if (!bSetup) return;
        setBRunning(true); setBLog([]); setBResult(null);

        // Terminate previous worker and create fresh one
        bWorkerRef.current?.terminate();
        bWorkerRef.current = makeWorker();
        const w = bWorkerRef.current;

        const id = 'attack-' + Date.now();
        w.addEventListener('message', (e) => {
            if (e.data.id !== id) return;
            const { type } = e.data;
            if (type === 'start') {
                setBLog([`[init] k=${e.data.k} bytes, B=2^${(e.data.k - 2) * 8}, starting search…`]);
            } else if (type === 'progress') {
                setBLog(prev => [...prev.slice(-40), `[step ${e.data.step}] queries=${e.data.totalQueries.toLocaleString()}, intervals=${e.data.intervals}`]);
            } else if (type === 'found_s') {
                setBLog(prev => [...prev.slice(-40), `[step ${e.data.step}] ✓ s found in ${e.data.localQueries} tries — total oracle queries: ${e.data.totalQueries}, intervals: ${e.data.intervals}`]);
            } else if (type === 'intervals') {
                setBLog(prev => [...prev.slice(-40), `[step ${e.data.step}] intervals → ${e.data.intervals}`]);
            } else if (type === 'done') {
                setBLog(prev => [...prev, `[✓ DONE] recovered in ${e.data.totalQueries.toLocaleString()} oracle queries, ${e.data.step} steps`]);
                setBResult(e.data);
                setBRunning(false);
            } else if (e.data.action === 'error') {
                setBLog(prev => [...prev, `[ERROR] ${e.data.message}`]);
                setBRunning(false);
            }
        });

        w.postMessage({ id, action: 'bleichenbacher_toy', pk: bSetup.pkRaw, sk: bSetup.skRaw, c: bSetup.c });
    }

    function stopAttack() {
        bWorkerRef.current?.terminate();
        bWorkerRef.current = makeWorker();
        setBRunning(false);
        setBLog(prev => [...prev, '[stopped by user]']);
    }

    const identical = enc1 && enc2 && enc1.c === enc2.c;

    return (
        <div style={{ padding: '0 2px' }}>
            {/* Header */}
            <div style={{ marginBottom: '16px' }}>
                <h2 style={{ ...S.cyan, fontSize: '1.05rem', margin: '0 0 3px' }}>PA#12 · Textbook RSA + PKCS#1 v1.5</h2>
                <p style={{ ...S.dim, fontSize: '0.73rem', margin: 0 }}>
                    RSA key generation · determinism attack · PKCS#1 v1.5 padding visualizer · Bleichenbacher CCA2 attack
                </p>
            </div>

            {/* ── Key Generation ── */}
            <div style={S.panel}>
                <div style={S.hdr}>🔑 RSA Key Generation</div>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap', marginBottom: '12px' }}>
                    {[256, 512].map(b => (
                        <button key={b} onClick={() => setKeyBits(b)} style={{
                            padding: '5px 14px', borderRadius: '20px', cursor: 'pointer', fontSize: '0.75rem',
                            border: `1px solid ${keyBits === b ? 'var(--accent-cyan)' : 'var(--border-subtle)'}`,
                            background: keyBits === b ? 'rgba(0,229,255,0.1)' : 'transparent',
                            color: keyBits === b ? 'var(--accent-cyan)' : 'var(--text-dim)', fontWeight: keyBits === b ? 700 : 400,
                        }}>{b}-bit N</button>
                    ))}
                    <Btn onClick={genKeys} disabled={keyGen}>{keyGen ? '⏳ Generating…' : '⚡ Generate Keys'}</Btn>
                    {keyGen && <span style={{ fontSize: '0.71rem', ...S.amber }}>Running in background (non-blocking)…</span>}
                    {keys && <span style={{ fontSize: '0.71rem', ...S.dim }}>Generated in {keys.timeMs}ms</span>}
                </div>
                {keys && (
                    <div style={{ ...S.mono, fontSize: '0.69rem' }}>
                        {[
                            ['N (modulus)', hex(keys.pk.N)],
                            ['e (public exp)', keys.pk.e.toString()],
                            ['d (private exp)', hex(keys.sk.d)],
                            ['p', hex(keys.sk.p, 24)],
                            ['q', hex(keys.sk.q, 24)],
                            ['dp = d mod (p-1)', hex(keys.sk.dp, 24)],
                            ['dq = d mod (q-1)', hex(keys.sk.dq, 24)],
                            ['q_inv = q⁻¹ mod p', hex(keys.sk.q_inv, 24)],
                        ].map(([l, v]) => (
                            <div key={l} style={{ marginBottom: '3px' }}>
                                <span style={S.dim}>{l}: </span><span style={S.cyan}>{v}</span>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* ── Determinism Attack ── */}
            <div style={S.panel}>
                <div style={S.hdr}>🎯 Determinism Attack Demo</div>

                {/* Mode toggle */}
                <div style={{ display: 'flex', gap: '0', marginBottom: '12px', borderRadius: 'var(--radius-md)', overflow: 'hidden', border: '1px solid var(--border-subtle)', width: 'fit-content' }}>
                    {['textbook', 'pkcs15'].map(m => (
                        <button key={m} onClick={() => { setMode(m); setEnc1(null); setEnc2(null); }} style={{
                            padding: '6px 16px', border: 'none', cursor: 'pointer', fontSize: '0.75rem', fontWeight: 700,
                            background: mode === m ? 'var(--accent-cyan)' : 'transparent',
                            color: mode === m ? 'var(--bg-primary)' : 'var(--text-dim)',
                        }}>{m === 'textbook' ? 'Textbook RSA' : 'PKCS#1 v1.5'}</button>
                    ))}
                </div>

                <div style={{ marginBottom: '12px' }}>
                    <label style={S.label}>Short message (simulates a vote)</label>
                    <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
                        <input className="hex-input" value={msg}
                            onChange={e => { setMsg(e.target.value); setEnc1(null); setEnc2(null); }}
                            style={{ width: '140px' }} placeholder="Yes / No / vote:1" />
                        {['Yes', 'No', 'vote:1', 'vote:2'].map(s => (
                            <button key={s} onClick={() => { setMsg(s); setEnc1(null); setEnc2(null); }} style={{
                                padding: '4px 10px', borderRadius: '12px', border: '1px solid var(--border-subtle)',
                                background: 'transparent', color: 'var(--text-dim)', cursor: 'pointer', fontSize: '0.72rem',
                            }}>{s}</button>
                        ))}
                    </div>
                </div>

                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <Btn onClick={encryptTwice} disabled={!keys || encrypting || !msg}>
                        {encrypting ? '⏳…' : '▶ Encrypt Twice'}
                    </Btn>
                    {!keys && <span style={{ fontSize: '0.71rem', ...S.amber }}>Generate keys first ↑</span>}
                </div>

                {enc1 && enc2 && (
                    <div style={{ marginTop: '14px' }}>
                        <div style={{
                            padding: '10px 14px', borderRadius: 'var(--radius-md)', marginBottom: '12px',
                            textAlign: 'center', fontWeight: 800, fontSize: '0.85rem',
                            background: identical ? 'rgba(239,68,68,0.12)' : 'rgba(34,197,94,0.12)',
                            color: identical ? '#ef4444' : '#22c55e',
                            border: `1px solid ${identical ? '#ef444444' : '#22c55e44'}`,
                        }}>
                            {identical
                                ? '✗ IDENTICAL CIPHERTEXTS — plaintext is leaked! (CPA insecure)'
                                : '✓ Different ciphertexts — random PS ensures CPA security'}
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '12px' }}>
                            {[enc1, enc2].map((enc, i) => (
                                <div key={i} style={{
                                    padding: '8px 10px', background: 'var(--bg-glass)',
                                    borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)'
                                }}>
                                    <div style={{ fontSize: '0.68rem', ...S.dim, marginBottom: '4px', fontWeight: 600 }}>Ciphertext #{i + 1}</div>
                                    <div style={{
                                        ...S.mono, fontSize: '0.67rem', wordBreak: 'break-all',
                                        color: identical ? '#ef4444' : '#22c55e'
                                    }}>
                                        {hex(enc.c, 40)}
                                    </div>
                                </div>
                            ))}
                        </div>

                        {mode === 'pkcs15' && enc1.em && (
                            <div style={{
                                padding: '10px 12px', background: 'var(--bg-glass)',
                                borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)'
                            }}>
                                <div style={{ fontSize: '0.7rem', fontWeight: 700, ...S.sec, marginBottom: '8px' }}>
                                    📦 PKCS#1 v1.5 Padding Inspector — PS bytes differ each encryption
                                </div>
                                <PaddingVisual em={enc1.em} label="Encryption #1" />
                                <PaddingVisual em={enc2.em} label="Encryption #2" />
                            </div>
                        )}
                    </div>
                )}
            </div>

            {/* ── Bleichenbacher Attack ── */}
            <div style={S.panel}>
                <div style={S.hdr}>☠️ Bleichenbacher CCA2 Attack (Padding Oracle)</div>
                <p style={{ ...S.dim, fontSize: '0.72rem', marginBottom: '10px' }}>
                    A <strong style={S.cyan}>padding oracle</strong> reveals only whether a ciphertext decrypts to a
                    valid padded message — 1 bit of information per query. Bleichenbacher (1998) showed this is enough
                    to recover the full plaintext using a binary search over the plaintext space.
                </p>
                <div style={{
                    padding: '8px 12px', marginBottom: '12px', borderRadius: 'var(--radius-md)',
                    background: 'rgba(0,229,255,0.05)', border: '1px solid rgba(0,229,255,0.2)', fontSize: '0.71rem', ...S.sec
                }}>
                    <strong style={S.cyan}>Toy scheme (64-bit N):</strong> EM = [<span style={S.cyan}>0x02</span> | random | message].
                    Oracle checks <code>EM[0] === 0x02</code>. This gives B = 2^56, N/B = 2^8 = <strong>256 candidates/step</strong> (vs. 65,536 for standard PKCS#1).
                    The Bleichenbacher algorithm is identical — simplified parameters make it feasible in the browser.
                </div>

                {/* Step 1: Setup */}
                <div style={{ marginBottom: '10px' }}>
                    <div style={{ fontSize: '0.72rem', ...S.dim, marginBottom: '6px', fontWeight: 600 }}>
                        Step 1 — Generate 64-bit keys + encrypt "Y" (runs in background, ~instant)
                    </div>
                    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
                        <Btn onClick={setupBleichenbacher} disabled={bSetupRunning} color="#8b5cf6">
                            {bSetupRunning ? '⏳ Generating…' : '⚡ Setup Attack'}
                        </Btn>
                        {bSetup && (
                            <span style={{ fontSize: '0.71rem', ...S.dim }}>
                                N=<span style={S.cyan}>{hex(bSetup.pk.N, 12)}</span> &nbsp;
                                c=<span style={S.cyan}>{hex(fromHex(bSetup.c), 12)}</span> &nbsp;
                                ({bSetup.timeMs}ms)
                            </span>
                        )}
                    </div>
                </div>

                {/* PKCS#1 padding of the target */}
                {bSetup?.em && (
                    <div style={{
                        padding: '8px 10px', background: 'var(--bg-glass)', borderRadius: 'var(--radius-md)',
                        border: '1px solid var(--border-subtle)', marginBottom: '10px'
                    }}>
                        <div style={{ fontSize: '0.68rem', ...S.dim, marginBottom: '4px', fontWeight: 600 }}>
                            Target ciphertext decrypts to this EM (attacker does NOT know this — only oracle does):
                        </div>
                        <PaddingVisual em={bSetup.em} label={`EM (${bSetup.em.length} bytes)`} />
                    </div>
                )}

                {/* Step 2: Run attack */}
                <div style={{ marginBottom: '10px' }}>
                    <div style={{ fontSize: '0.72rem', ...S.dim, marginBottom: '6px', fontWeight: 600 }}>
                        Step 2 — Run Bleichenbacher adaptive CCA2 attack (~256 oracle queries/step, completes in seconds)
                    </div>
                    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                        <Btn onClick={runAttack} disabled={!bSetup || bRunning} color="#ef4444">
                            {bRunning ? '⏳ Attacking…' : '🔓 Run Attack'}
                        </Btn>
                        {bRunning && <Btn onClick={stopAttack} color="#f59e0b">■ Stop</Btn>}
                        {!bSetup && <span style={{ fontSize: '0.71rem', ...S.amber }}>Complete Step 1 first</span>}
                    </div>
                </div>

                {/* Progress log */}
                {bLog.length > 0 && (
                    <div style={{
                        padding: '8px 10px', background: 'var(--bg-glass)',
                        borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)',
                        marginBottom: '10px', maxHeight: '180px', overflowY: 'auto',
                        ...S.mono, fontSize: '0.67rem'
                    }}>
                        {bLog.map((line, i) => (
                            <div key={i} style={{
                                marginBottom: '2px',
                                color: line.startsWith('[✓') ? '#22c55e' : line.startsWith('[step') && line.includes('✓') ? 'var(--accent-cyan)' : 'var(--text-dim)'
                            }}>
                                {line}
                            </div>
                        ))}
                    </div>
                )}

                {/* Result */}
                {bResult && (
                    <div style={{
                        padding: '12px 14px', background: 'rgba(34,197,94,0.08)',
                        borderRadius: 'var(--radius-md)', border: '1px solid #22c55e44', marginBottom: '10px'
                    }}>
                        <div style={{ fontWeight: 700, ...S.green, marginBottom: '8px', fontSize: '0.9rem' }}>
                            ✓ Plaintext Recovered!
                        </div>
                        <div style={{ ...S.mono, fontSize: '0.71rem' }}>
                            <div style={{ marginBottom: '5px' }}>
                                <span style={S.dim}>Recovered: </span>
                                <span style={{ ...S.green, fontWeight: 800, fontSize: '1rem' }}>"{bResult.plaintext}"</span>
                            </div>
                            <div style={{ display: 'flex', gap: '20px', flexWrap: 'wrap' }}>
                                <span style={S.dim}>Oracle queries: <strong style={S.cyan}>{bResult.totalQueries.toLocaleString()}</strong></span>
                                <span style={S.dim}>Bleichenbacher steps: <strong style={S.cyan}>{bResult.step}</strong></span>
                            </div>
                        </div>
                    </div>
                )}

                {/* Theory box */}
                <div style={{
                    padding: '8px 12px', borderRadius: 'var(--radius-md)',
                    background: 'rgba(245,158,11,0.06)', border: '1px solid #f59e0b33', fontSize: '0.71rem', ...S.amber
                }}>
                    <strong>Why this works:</strong> The oracle only reveals 1 bit per query (valid/invalid padding).
                    Bleichenbacher's binary search exploits this to narrow the plaintext range iteratively.
                    Each valid response constrains m to a smaller interval [a, b] within [2B, 3B−1].
                    When a=b, the plaintext is recovered — using only the public key and oracle responses.
                    <br /><br />
                    <strong>Fix:</strong> OAEP (RFC 3447) uses a hash-based mask that makes the oracle useless — it is CCA2-secure in the random oracle model. Never use raw PKCS#1 v1.5 for new systems.
                </div>
            </div>
        </div>
    );
}