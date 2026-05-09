/**
 * PA#12: Textbook RSA + PKCS#1 v1.5 + Bleichenbacher Attack.
 * All BigInt arithmetic. Square-and-multiply implemented directly (no library pow).
 */

import { genPrime } from './miller_rabin.js';

// ─── Square-and-multiply (self-implemented, no library) ──────────────────────
export function modPow(base, exp, mod) {
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

// ─── Extended Euclidean Algorithm ────────────────────────────────────────────
export function extGcd(a, b) {
    if (b === 0n) return { g: a, x: 1n, y: 0n };
    const { g, x, y } = extGcd(b, a % b);
    return { g, x: y, y: x - (a / b) * y };
}

export function modInverse(a, m) {
    const am = ((a % m) + m) % m;
    const { g, x } = extGcd(am, m);
    if (g !== 1n) throw new Error(`No inverse: gcd(${a}, ${m}) = ${g}`);
    return ((x % m) + m) % m;
}

function gcd(a, b) { return b === 0n ? a : gcd(b, a % b); }

// ─── Byte helpers ─────────────────────────────────────────────────────────────
export function byteLength(n) { return Math.ceil(n.toString(16).length / 2); }

export function bytesToBigInt(bytes) {
    let v = 0n;
    for (const b of bytes) v = (v << 8n) | BigInt(b);
    return v;
}

export function bigIntToBytes(n, len) {
    const out = new Uint8Array(len);
    let v = n;
    for (let i = len - 1; i >= 0; i--) {
        out[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    return out;
}

// ─── RSA Key Generation ───────────────────────────────────────────────────────
export function rsaKeygen(bits = 512) {
    const start = performance.now();
    const half = Math.floor(bits / 2);
    const e = 65537n;

    let p, q, N, phi, d;
    while (true) {
        p = genPrime(half, 40).prime;
        q = genPrime(half, 40).prime;
        if (p === q) continue;
        N = p * q;
        phi = (p - 1n) * (q - 1n);
        if (gcd(e, phi) !== 1n) continue;
        d = modInverse(e, phi);
        break;
    }

    return {
        pk: { N, e },
        sk: {
            N, d, p, q,
            dp: d % (p - 1n),
            dq: d % (q - 1n),
            q_inv: modInverse(q, p),
        },
        timeMs: Math.round(performance.now() - start),
    };
}

// ─── Textbook RSA ─────────────────────────────────────────────────────────────
export const rsaEnc = (pk, m) => modPow(m, pk.e, pk.N);
export const rsaDec = (sk, c) => modPow(c, sk.d, sk.N);

// ─── PKCS#1 v1.5 ─────────────────────────────────────────────────────────────
export class PaddingError extends Error { constructor() { super('Invalid PKCS#1 v1.5 padding'); } }

export function pkcs15Enc(pk, mBytes) {
    const k = byteLength(pk.N);
    if (mBytes.length > k - 11) throw new Error('Message too long for key size');
    const psLen = k - mBytes.length - 3;
    // Build random nonzero PS
    const ps = new Uint8Array(psLen);
    let i = 0;
    while (i < psLen) {
        const b = new Uint8Array(64);
        crypto.getRandomValues(b);
        for (const byte of b) { if (byte !== 0 && i < psLen) ps[i++] = byte; }
    }
    const em = new Uint8Array(k);
    em[0] = 0x00; em[1] = 0x02;
    em.set(ps, 2);
    em[2 + psLen] = 0x00;
    em.set(mBytes, 3 + psLen);
    return { c: modPow(bytesToBigInt(em), pk.e, pk.N), em };
}

export function pkcs15Dec(sk, c) {
    const k = byteLength(sk.N);
    const em = bigIntToBytes(modPow(c, sk.d, sk.N), k);
    if (em[0] !== 0x00 || em[1] !== 0x02) throw new PaddingError();
    let i = 2;
    while (i < em.length && em[i] !== 0x00) i++;
    if (i - 2 < 8 || i >= em.length) throw new PaddingError();
    return { m: em.slice(i + 1), em };
}

// ─── Padding Oracle ──────────────────────────────────────────────────────────
export function paddingOracle(sk, c) {
    try { pkcs15Dec(sk, c); return true; }
    catch { return false; }
}

// ─── BigInt math helpers for Bleichenbacher ───────────────────────────────────
function ceilDiv(a, b) { return (a + b - 1n) / b; }
function floorDiv(a, b) { return a / b; }
const bigMax = (a, b) => a > b ? a : b;
const bigMin = (a, b) => a < b ? a : b;

// ─── Bleichenbacher Attack (async generator) ──────────────────────────────────
/**
 * Full Bleichenbacher 1998 CCA2 attack on PKCS#1 v1.5.
 *
 * Yields progress events and finally a 'done' event with recovered m.
 * Caller iterates with: for await (const event of bleichenbacher(...)) { ... }
 *
 * @param {{ N: BigInt, e: BigInt }} pk
 * @param {BigInt} c - target ciphertext
 * @param {Function} oracle - oracle(c) => bool
 */
export async function* bleichenbacher(pk, c, oracle) {
    const k = byteLength(pk.N);
    const B = 2n ** BigInt(8 * (k - 2));
    const twoB = 2n * B;
    const threeB = 3n * B;

    let M = [[twoB, threeB - 1n]];
    let s = ceilDiv(pk.N, threeB); // Step 2a: start from ceil(n/3B)
    let totalQueries = 0;
    let step = 0;
    const CHUNK = 200; // yield every CHUNK queries to keep UI live

    yield { type: 'start', k, B, twoB, threeB };

    while (true) {
        step++;

        // ── Find s_i ──────────────────────────────────────────────────────────────
        let localQ = 0;
        while (true) {
            totalQueries++; localQ++;
            const ci = c * modPow(s, pk.e, pk.N) % pk.N;
            if (oracle(ci)) break;
            s++;
            if (localQ % CHUNK === 0) {
                yield { type: 'progress', step, totalQueries, intervals: M.length, s };
                await new Promise(r => setTimeout(r, 0));
            }
        }

        yield { type: 'found_s', step, s, totalQueries, intervals: M.length };

        // ── Step 3: Narrow intervals ────────────────────────────────────────────
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

        yield { type: 'intervals', step, intervals: M.length };

        // ── Step 4: Check termination ───────────────────────────────────────────
        if (M.length === 1 && M[0][0] === M[0][1]) {
            yield { type: 'done', m: M[0][0], totalQueries, step };
            return;
        }

        // ── Compute next s lower bound ──────────────────────────────────────────
        if (M.length === 1) {
            // Step 2b: single interval — use r-based narrowing for efficiency
            const [a, b] = M[0];
            const r = ceilDiv(2n * (b * s - twoB), pk.N);
            s = ceilDiv(twoB + r * pk.N, b);
        } else {
            // Step 2c: multiple intervals — increment from previous s
            s = s + 1n;
        }
    }
}

export const PA_NUMBER = 12;
export const STUB = false;