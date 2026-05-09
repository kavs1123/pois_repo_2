/**
 * RSA Web Worker — SELF-CONTAINED (no imports).
 * All crypto functions are inlined to avoid module chain issues in Vite dev mode.
 */

// ── Square-and-multiply ───────────────────────────────────────────────────────
function modPow(base, exp, mod) {
    if (mod === 1n) return 0n;
    base = ((base % mod) + mod) % mod;
    let result = 1n;
    while (exp > 0n) {
        if (exp & 1n) result = result * base % mod;
        exp >>= 1n;
        base = base * base % mod;
    }
    return result;
}

// ── Extended GCD / Modular Inverse ───────────────────────────────────────────
function extGcd(a, b) {
    if (b === 0n) return { g: a, x: 1n, y: 0n };
    const { g, x, y } = extGcd(b, a % b);
    return { g, x: y, y: x - (a / b) * y };
}
function modInverse(a, m) {
    const am = ((a % m) + m) % m;
    const { g, x } = extGcd(am, m);
    if (g !== 1n) throw new Error('No modular inverse');
    return ((x % m) + m) % m;
}
function gcd(a, b) { return b === 0n ? a : gcd(b, a % b); }

// ── Byte helpers ──────────────────────────────────────────────────────────────
function byteLength(n) { return Math.ceil(n.toString(16).length / 2); }
function bytesToBigInt(bytes) {
    let v = 0n;
    for (const b of bytes) v = (v << 8n) | BigInt(b);
    return v;
}
function bigIntToBytes(n, len) {
    const out = new Uint8Array(len);
    let v = n;
    for (let i = len - 1; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
    return out;
}

// ── Miller-Rabin ──────────────────────────────────────────────────────────────
function factorTwos(n) {
    let s = 0n, d = n - 1n;
    while (d % 2n === 0n) { d /= 2n; s += 1n; }
    return { s, d };
}
function randBigInt(n) {
    const bits = n.toString(2).length;
    const bytes = Math.ceil(bits / 8);
    while (true) {
        const buf = new Uint8Array(bytes);
        crypto.getRandomValues(buf);
        if (bits % 8 !== 0) buf[0] &= (1 << (bits % 8)) - 1;
        let v = 0n;
        for (const b of buf) v = (v << 8n) | BigInt(b);
        if (v >= 2n && v <= n - 2n) return v;
    }
}
function millerRabin(n, k = 40) {
    if (n < 2n || n % 2n === 0n) return false;
    if (n === 2n || n === 3n) return true;
    const { s, d } = factorTwos(n);
    for (let i = 0; i < k; i++) {
        const a = randBigInt(n);
        let x = modPow(a, d, n);
        if (x === 1n || x === n - 1n) continue;
        let pass = false;
        for (let r = 1n; r < s; r++) {
            x = modPow(x, 2n, n);
            if (x === n - 1n) { pass = true; break; }
        }
        if (!pass) return false;
    }
    return true;
}
function genPrime(bits, k = 40) {
    const SMALL = [3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n];
    const byteLen = Math.ceil(bits / 8);
    while (true) {
        const buf = new Uint8Array(byteLen);
        crypto.getRandomValues(buf);
        buf[0] |= 0x80; buf[byteLen - 1] |= 1;
        let n = 0n;
        for (const b of buf) n = (n << 8n) | BigInt(b);
        let skip = false;
        for (const p of SMALL) { if (n === p) break; if (n % p === 0n) { skip = true; break; } }
        if (skip) continue;
        if (millerRabin(n, k)) return n;
    }
}

// ── RSA keygen ────────────────────────────────────────────────────────────────
function rsaKeygen(bits) {
    const half = Math.floor(bits / 2);
    const e = 65537n;
    let p, q, N, phi, d;
    while (true) {
        p = genPrime(half, 40);
        q = genPrime(half, 40);
        if (p === q) continue;
        N = p * q;
        phi = (p - 1n) * (q - 1n);
        if (gcd(e, phi) !== 1n) continue;
        d = modInverse(e, phi);
        break;
    }
    return {
        pk: { N, e },
        sk: { N, d, p, q, dp: d % (p - 1n), dq: d % (q - 1n), q_inv: modInverse(q, p) },
    };
}

// ── PKCS#1 v1.5 ───────────────────────────────────────────────────────────────
function pkcs15Enc(pk, mBytes) {
    const k = byteLength(pk.N);
    const psLen = k - mBytes.length - 3;
    const ps = new Uint8Array(psLen);
    let i = 0;
    while (i < psLen) {
        const b = new Uint8Array(64); crypto.getRandomValues(b);
        for (const byte of b) { if (byte !== 0 && i < psLen) ps[i++] = byte; }
    }
    const em = new Uint8Array(k);
    em[0] = 0x00; em[1] = 0x02;
    em.set(ps, 2); em[2 + psLen] = 0x00;
    em.set(mBytes, 3 + psLen);
    return { c: modPow(bytesToBigInt(em), pk.e, pk.N), em };
}
function pkcs15Dec(sk, c) {
    const k = byteLength(sk.N);
    const em = bigIntToBytes(modPow(c, sk.d, sk.N), k);
    if (em[0] !== 0x00 || em[1] !== 0x02) return false;
    let i = 2;
    while (i < em.length && em[i] !== 0x00) i++;
    if (i - 2 < 8 || i >= em.length) return false;
    return { em, m: em.slice(i + 1) };
}
function paddingOracle(sk, c) { return pkcs15Dec(sk, c) !== false; }

// ── Toy oracle (simplified for fast demo) ────────────────────────────────────
// Scheme: EM = [0x02, ...random..., message_byte]
// Oracle: checks EM[0] === 0x02 only.
// This gives B = 2^(8*(k-1)), so N/B = 2^(64-56) = 2^8 = 256 for 64-bit N.
// The Bleichenbacher algorithm runs identically — just with different B.
function pkcs15EncToy(pk, mByte) {
    const k = byteLength(pk.N);
    const em = new Uint8Array(k);
    em[0] = 0x02;
    crypto.getRandomValues(em.subarray(1, k - 1));
    em[k - 1] = mByte;
    return { c: modPow(bytesToBigInt(em), pk.e, pk.N), em };
}
function paddingOracleToy(sk, c) {
    const k = byteLength(sk.N);
    const em = bigIntToBytes(modPow(c, sk.d, sk.N), k);
    return em[0] === 0x02;
}

// ── Bleichenbacher helpers ────────────────────────────────────────────────────
const ceilDiv = (a, b) => (a + b - 1n) / b;
const floorDiv = (a, b) => a / b;
const bigMax = (a, b) => a > b ? a : b;
const bigMin = (a, b) => a < b ? a : b;

// ── BigInt serialization ──────────────────────────────────────────────────────
const toHex = n => n.toString(16);
const fromHex = s => BigInt('0x' + s);
const serPk = pk => ({ N: toHex(pk.N), e: toHex(pk.e) });
const desPk = pk => ({ N: fromHex(pk.N), e: fromHex(pk.e) });
const serSk = sk => ({ N: toHex(sk.N), d: toHex(sk.d), p: toHex(sk.p), q: toHex(sk.q), dp: toHex(sk.dp), dq: toHex(sk.dq), q_inv: toHex(sk.q_inv) });
const desSk = sk => ({ N: fromHex(sk.N), d: fromHex(sk.d), p: fromHex(sk.p), q: fromHex(sk.q), dp: fromHex(sk.dp), dq: fromHex(sk.dq), q_inv: fromHex(sk.q_inv) });

// ── Message handler ───────────────────────────────────────────────────────────
self.onmessage = (e) => {
    const { action, id } = e.data;
    try {
        // ── keygen ──────────────────────────────────────────────────────────────
        if (action === 'keygen') {
            const t0 = Date.now();
            const r = rsaKeygen(e.data.bits);
            self.postMessage({ id, action: 'keygen_done', pk: serPk(r.pk), sk: serSk(r.sk), timeMs: Date.now() - t0 });
        }

        // ── keygen + encrypt ─────────────────────────────────────────────────────
        else if (action === 'keygen_encrypt') {
            const t0 = Date.now();
            const r = rsaKeygen(e.data.bits);
            const mBytes = new TextEncoder().encode(e.data.message || 'Yes');
            const { c, em } = pkcs15Enc(r.pk, mBytes);
            self.postMessage({ id, action: 'keygen_encrypt_done', pk: serPk(r.pk), sk: serSk(r.sk), c: toHex(c), em: Array.from(em), timeMs: Date.now() - t0 });
        }

        // ── keygen + encrypt (toy, 64-bit N, single message byte) ───────────────
        else if (action === 'keygen_encrypt_toy') {
            const t0 = Date.now();
            const r = rsaKeygen(64);
            const mByte = (e.data.message || 'Y').charCodeAt(0);
            const { c, em } = pkcs15EncToy(r.pk, mByte);
            self.postMessage({ id, action: 'keygen_encrypt_done', pk: serPk(r.pk), sk: serSk(r.sk), c: toHex(c), em: Array.from(em), timeMs: Date.now() - t0 });
        }

        // ── Bleichenbacher toy attack ─────────────────────────────────────────────
        // Uses simplified oracle (EM[0]===0x02), B = 2^(8*(k-1)), N/B ≈ 256.
        else if (action === 'bleichenbacher_toy') {
            const pk = desPk(e.data.pk);
            const sk = desSk(e.data.sk);
            const c = fromHex(e.data.c);
            const oracle = ci => paddingOracleToy(sk, ci);

            const k = byteLength(pk.N);
            const B = 2n ** BigInt(8 * (k - 1));  // key difference: k-1 not k-2
            const twoB = 2n * B;
            const threeB = 3n * B;
            let M = [[twoB, threeB - 1n]];
            let s = ceilDiv(pk.N, threeB);
            let totalQueries = 0;
            let step = 0;

            self.postMessage({ id, type: 'start', k, B_bits: (k - 1) * 8, expected_per_step: 256, totalQueries: 0 });

            while (true) {
                step++;
                let localQ = 0;
                while (true) {
                    totalQueries++; localQ++;
                    if (oracle(c * modPow(s, pk.e, pk.N) % pk.N)) break;
                    s++;
                    if (localQ % 50 === 0) self.postMessage({ id, type: 'progress', step, totalQueries, intervals: M.length });
                }
                self.postMessage({ id, type: 'found_s', step, localQueries: localQ, totalQueries, intervals: M.length });

                const newM = [];
                for (const [a, b] of M) {
                    const rMin = ceilDiv(a * s - threeB + 1n, pk.N);
                    const rMax = floorDiv(b * s - twoB, pk.N);
                    for (let r = rMin; r <= rMax; r++) {
                        const lo = bigMax(a, ceilDiv(twoB + r * pk.N, s));
                        const hi = bigMin(b, floorDiv(threeB - 1n + r * pk.N, s));
                        if (lo <= hi) newM.push([lo, hi]);
                    }
                }
                M = newM;
                self.postMessage({ id, type: 'intervals', step, intervals: M.length });

                if (M.length === 1 && M[0][0] === M[0][1]) {
                    const mBytes = bigIntToBytes(M[0][0], k);
                    const plaintext = String.fromCharCode(mBytes[k - 1]);
                    self.postMessage({ id, type: 'done', m: toHex(M[0][0]), totalQueries, step, plaintext });
                    return;
                }

                if (M.length === 1) {
                    const [a, b] = M[0];
                    const r = ceilDiv(2n * (b * s - twoB), pk.N);
                    s = ceilDiv(twoB + r * pk.N, b);
                } else {
                    s = s + 1n;
                }
            }
        }
    } catch (err) {
        self.postMessage({ id, action: 'error', message: err.message + '\n' + err.stack });
    }
};