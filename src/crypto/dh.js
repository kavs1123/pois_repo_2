/**
 * PA#11: Diffie-Hellman Key Exchange.
 *
 * Reuses DLP_PARAMS from ./owf.js (p≈2³¹ safe prime, q=(p-1)/2, g=2).
 * Uses modPow from ./utils.js and millerRabin/genPrime from ./miller_rabin.js.
 *
 * Exports:
 *   DH_PARAMS                  - Default group parameters
 *   CDH_DEMO_BITS              - Bit limit for brute-force demo (16)
 *   dhAliceStep1(params)       - {a, A} sample private exp, compute g^a
 *   dhBobStep1(params)         - {b, B} sample private exp, compute g^b
 *   dhAliceStep2(a, B, params) - K = B^a mod p
 *   dhBobStep2(b, A, params)   - K = A^b mod p
 *   mitmAttack(A, B, params)   - Eve's interception, returns {e,E,K_alice,K_bob,steps}
 *   cdhBruteForce(gA,gB,a,p)  - Brute-force discrete log up to 2^CDH_DEMO_BITS
 *   generateSafePrime(bits)    - Safe prime p=2q+1 via Miller-Rabin
 */

import { modPow } from './utils.js';
import { DLP_PARAMS } from './owf.js';
import { millerRabin, genPrime } from './miller_rabin.js';

// ─── Default group (existing ~31-bit safe prime) ──────────────────────────────
export const DH_PARAMS = {
    p: DLP_PARAMS.p,  // 2147483659n
    q: DLP_PARAMS.q,  // 1073741829n  = (p-1)/2
    g: DLP_PARAMS.g,  // 2n
};

// ─── CDH demo: brute force searches up to 2^16 iterations ────────────────────
export const CDH_DEMO_BITS = 16;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Uniform random BigInt in [1, n-1]. */
function randInRange(n) {
    const bits = n.toString(2).length;
    const bytes = Math.ceil(bits / 8);
    while (true) {
        const buf = new Uint8Array(bytes);
        crypto.getRandomValues(buf);
        if (bits % 8 !== 0) buf[0] &= (1 << (bits % 8)) - 1;
        let v = 0n;
        for (const b of buf) v = (v << 8n) | BigInt(b);
        if (v >= 1n && v <= n - 1n) return v;
    }
}

/** Random BigInt with at most `bits` bits (for small CDH demo exponents). */
export function randSmall(bits = CDH_DEMO_BITS) {
    const bytes = Math.ceil(bits / 8);
    const buf = new Uint8Array(bytes);
    crypto.getRandomValues(buf);
    buf[0] &= (1 << (bits % 8 || 8)) - 1;
    let v = 0n;
    for (const b of buf) v = (v << 8n) | BigInt(b);
    return v < 2n ? 2n : v;
}

// ─── DH Protocol ─────────────────────────────────────────────────────────────

/**
 * Alice Step 1: sample a ∈ [1, q-1], return A = g^a mod p.
 */
export function dhAliceStep1(params = DH_PARAMS) {
    const a = randInRange(params.q);
    const A = modPow(params.g, a, params.p);
    return { a, A };
}

/**
 * Bob Step 1: sample b ∈ [1, q-1], return B = g^b mod p.
 */
export function dhBobStep1(params = DH_PARAMS) {
    const b = randInRange(params.q);
    const B = modPow(params.g, b, params.p);
    return { b, B };
}

/** Alice Step 2: K = B^a mod p */
export function dhAliceStep2(a, B, params = DH_PARAMS) {
    return modPow(B, a, params.p);
}

/** Bob Step 2: K = A^b mod p */
export function dhBobStep2(b, A, params = DH_PARAMS) {
    return modPow(A, b, params.p);
}

// ─── MITM Attack (Eve) ────────────────────────────────────────────────────────

/**
 * Eve intercepts A=g^a and B=g^b, substitutes g^e for both.
 * Alice ends up with K_AE = A^e = g^{ae}.
 * Bob ends up with K_BE = B^e = g^{be}.
 * Eve computes both, reads all traffic.
 */
export function mitmAttack(A, B, params = DH_PARAMS) {
    const e = randInRange(params.q);
    const E = modPow(params.g, e, params.p); // Eve's public value
    const K_alice = modPow(A, e, params.p);         // K shared with Alice
    const K_bob = modPow(B, e, params.p);         // K shared with Bob

    return {
        e, E, K_alice, K_bob,
        steps: [
            { label: 'Eve intercepts g^a', value: `0x${A.toString(16)}` },
            { label: 'Eve intercepts g^b', value: `0x${B.toString(16)}` },
            { label: "Eve's private exponent e", value: `0x${e.toString(16)}` },
            { label: 'Eve sends g^e to Alice & Bob', value: `0x${E.toString(16)}` },
            { label: 'K(Alice ↔ Eve) = g^{ae}', value: `0x${K_alice.toString(16)}` },
            { label: 'K(Bob ↔ Eve) = g^{be}', value: `0x${K_bob.toString(16)}` },
        ],
    };
}

// ─── CDH Hardness Demo ────────────────────────────────────────────────────────

/**
 * Brute-force CDH: given g^a and g^b, recover g^{ab} by iterating x until g^x = g^a.
 * For the demo, a must be at most CDH_DEMO_BITS bits (enforced by randSmall).
 *
 * @param {BigInt} gA  - g^a mod p (Alice's public value)
 * @param {BigInt} gB  - g^b mod p (Bob's public value)
 * @param {{ p, g }}   params
 */
export function cdhBruteForce(gA, gB, params = DH_PARAMS) {
    const start = performance.now();
    const limit = 1n << BigInt(CDH_DEMO_BITS);
    let gx = params.g; // g^1

    for (let x = 1n; x <= limit; x++) {
        if (gx === gA) {
            const K = modPow(gB, x, params.p);
            return {
                K, found: true, iters: Number(x),
                timeMs: Math.round(performance.now() - start),
            };
        }
        gx = (gx * params.g) % params.p;
    }

    return {
        K: null, found: false, iters: Number(limit),
        timeMs: Math.round(performance.now() - start),
        note: `Private exponent exceeds 2^${CDH_DEMO_BITS} — use "Small a" mode.`,
    };
}

// ─── Safe Prime Generation ────────────────────────────────────────────────────

/**
 * Generate a safe prime p = 2q+1 (both prime) using Miller-Rabin from PA#13.
 * Finds a generator g of the subgroup of order q:
 *   For safe prime p=2q+1, g = h² mod p for any h where h² ≢ 1 (mod p).
 *
 * @param {number} bits  - Bit length of q (p will be bits+1 bits). Max 48 for browser.
 */
export function generateSafePrime(bits = 32) {
    const start = performance.now();
    const b = Math.min(bits, 48);

    while (true) {
        const { prime: q } = genPrime(b, 20);
        const p = 2n * q + 1n;
        if (millerRabin(p, 20).result !== 'PROBABLY_PRIME') continue;

        // Find generator of order-q subgroup: try h=2,3,... and use g = h² mod p
        for (let h = 2n; h < 100n; h++) {
            const g = modPow(h, 2n, p);
            if (g !== 1n && modPow(g, q, p) === 1n) {
                const timeMs = Math.round(performance.now() - start);
                return { p, q, g, timeMs };
            }
        }
        // Retry if no generator found (very rare)
    }
}

export const PA_NUMBER = 11;
export const STUB = false;