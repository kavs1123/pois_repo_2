# Minicrypt Clique Explorer
**CS8.401 · Principles of Information Security**

An interactive web application for exploring cryptographic primitives and their reductions in the Minicrypt world — extended through public-key cryptography and multi-party computation. Built with **React + Vite**, it lets you pick any two cryptographic primitives, trace the shortest reduction chain between them, and interactively run the underlying implementations.

---

## Table of Contents
1. [Project Overview](#project-overview)
2. [Directory Structure](#directory-structure)
3. [Setup & Running](#setup--running)
4. [PA Implementation Status](#pa-implementation-status)
5. [Crypto Module Reference](#crypto-module-reference)
6. [Component Reference](#component-reference)
7. [Testing Guide](#testing-guide)

---

## Project Overview

The explorer is structured around two ideas:

| Concept | Description |
|---|---|
| **Foundation** | The concrete hardness assumption underlying everything — either **AES-128** (PRP/PRF) or **DLP** (Discrete Log). Switchable from the top bar. |
| **Reduction** | A directed graph of cryptographic reductions (OWF → PRG → PRF → PRP → …). The app finds the shortest path between any two primitives via BFS and chains the constructions. |

The app has four main panels:
- **Build Panel** — instantiate a source primitive with a live key and evaluate it.
- **Reduce Panel** — pick a target, see the reduction chain, and evaluate the chain end-to-end.
- **Proof Panel** — see the theorem statements and security bounds for each reduction step.
- **Demo Section** — run interactive demos for each programming assignment (PA#1–PA#20, all implemented).

---

## Directory Structure

```
pois_repo_2/
├── index.html                  # Vite entry point (mounts #root)
├── vite.config.js              # Vite config (React plugin)
├── package.json                # Dependencies & npm scripts
├── package-lock.json
├── pois_project_doc.pdf        # Course assignment specification
├── precompute_bleich.mjs       # Offline script: precompute Bleichenbacher benchmarks
├── conformance-tests.md        # Informal conformance notes
├── problems.md                 # Problem-set scratchpad
├── project.md                  # Extended project notes
│
└── src/
    ├── main.jsx                # React root (renders <App />)
    ├── App.jsx                 # Top-level app: layout, global state, routing
    ├── index.css               # Global design system (CSS variables, dark theme, all component styles)
    │
    ├── components/             # React UI components
    │   ├── FoundationToggle.jsx    # AES / DLP switcher (top bar)
    │   ├── BuildPanel.jsx          # Left panel: pick source primitive, live evaluation
    │   ├── ReducePanel.jsx         # Right panel: pick target, chain execution & output
    │   ├── ProofPanel.jsx          # Bottom: theorem statements for each reduction hop
    │   ├── DemoSection.jsx         # Tab bar + router for PA demo components (PA#1–PA#20)
    │   ├── ReductionStages.jsx     # Collapsible stage cards for multi-hop reduction display
    │   ├── StepDisplay.jsx         # Renders a single evaluation step (label + value)
    │   │
    │   └── demos/                  # One component per programming assignment
    │       ├── PA1Demo.jsx         # OWF + PRG demo (HILL construction, NIST-style tests)
    │       ├── PA2Demo.jsx         # PRF demo (GGM tree construction + distinguishing game)
    │       ├── PA3Demo.jsx         # CPA-secure encryption demo (IND-CPA game, nonce-reuse)
    │       ├── PA4Demo.jsx         # Modes of operation (CBC / OFB / CTR + bit-flip / IV-reuse)
    │       ├── PA5Demo.jsx         # MACs: PRF-MAC + EUF-CMA game
    │       ├── PA6Demo.jsx         # CCA-secure encryption: Encrypt-then-MAC
    │       ├── PA7Demo.jsx         # Merkle-Damgård hash + collision propagation demo
    │       ├── PA8Demo.jsx         # DLP-based CRHF
    │       ├── PA9Demo.jsx         # Birthday attack visualisation
    │       ├── PA10Demo.jsx        # HMAC + timing side-channel demo
    │       ├── PA11Demo.jsx        # Diffie-Hellman key exchange + CDH hardness + MITM
    │       ├── PA12Demo.jsx        # Textbook RSA + PKCS#1 v1.5 + Bleichenbacher CCA2 attack
    │       ├── PA13Demo.jsx        # Miller-Rabin primality testing + Carmichael numbers
    │       ├── PA14Demo.jsx        # CRT solver + Garner's RSA speedup + Håstad broadcast attack
    │       ├── PA15Demo.jsx        # Digital signatures (RSA hash-then-sign) + EUF-CMA game
    │       ├── PA16Demo.jsx        # ElGamal encryption + malleability + IND-CPA simulation
    │       ├── PA17Demo.jsx        # CCA-safe signcryption (Encrypt-then-Sign, ElGamal + RSA)
    │       ├── PA18Demo.jsx        # Bellare-Micali 1-out-of-2 Oblivious Transfer
    │       ├── PA19Demo.jsx        # Secure boolean gates (AND via OT, XOR free, NOT local)
    │       ├── PA20Demo.jsx        # All 2-party MPC via GMW (Millionaire's, Equality, Adder circuits)
    │       └── StubDemo.jsx        # Fallback placeholder for any unregistered PA
    │
    ├── crypto/                 # Pure-JS cryptographic primitives (no external crypto libs)
    │   ├── aes.js              # Full AES-128: KeyExpansion, SubBytes, ShiftRows, MixColumns, encrypt/decrypt
    │   ├── owf.js              # One-Way Functions: AES-OWF (f(k)=AES_k(0^128)), DLP-OWF (f(x)=g^x mod p)
    │   ├── prg.js              # PRGs: HILL hard-core-bit PRG, AES counter-mode PRG, DLP-based PRG
    │   ├── prf.js              # PRFs: GGM tree PRF (PRG → PRF), direct AES-PRF
    │   ├── prp.js              # PRP: 3-round Luby-Rackoff Feistel (PRF → PRP)
    │   ├── cpa_enc.js          # CPA-secure encryption: nonce-based CTR mode, IND-CPA game simulation
    │   ├── modes.js            # Modes of operation: CBC, OFB, CTR (encrypt + decrypt + step traces)
    │   ├── mac.js              # PRF-MAC (Mac_k(m)=F_k(m)) + CBC-MAC + EUF-CMA game
    │   ├── cca_enc.js          # CCA-secure encryption: Encrypt-then-MAC (CTR + CBC-MAC)
    │   ├── merkle_damgard.js   # Merkle-Damgård construction + toy compression + length-extension demo
    │   ├── crhf.js             # DLP-based CRHF (g^x · h^y mod p)
    │   ├── birthday.js         # Birthday attack simulation (collision probability & demo)
    │   ├── hmac.js             # HMAC construction + Encrypt-then-HMAC
    │   ├── miller_rabin.js     # Miller-Rabin primality test + Carmichael demo + benchmark data
    │   ├── prime.js            # Trial-division prime sieve helper
    │   ├── rsa.js              # RSA key generation, encrypt/decrypt, PKCS#1 v1.5 padding, CRT decryption
    │   ├── rsaWorker.js        # Web Worker: background RSA keygen + Bleichenbacher attack runner
    │   ├── rsa_sig.js          # RSA digital signatures (hash-then-sign) + EUF-CMA challenger
    │   ├── crt.js              # CRT solver, Garner's RSA speedup, Håstad broadcast attack
    │   ├── dh.js               # Diffie-Hellman key exchange, MITM, CDH brute-force, safe prime generation
    │   ├── elgamal.js          # ElGamal PKE: keygen, Enc, Dec, malleability, IND-CPA simulation
    │   ├── signcrypt.js        # CCA2-safe signcryption: Encrypt-then-Sign (ElGamal + RSA signatures)
    │   ├── ot.js               # Bellare-Micali 1-of-2 Oblivious Transfer over the DLP subgroup
    │   ├── secure_gates.js     # Secure AND (via OT), XOR (additive masking), NOT (local flip), GMW shares
    │   ├── mpc.js              # GMW-style 2-party MPC: circuit builder + secure evaluation engine
    │   ├── foundation.js       # Foundation layer: AESFoundation & DLPFoundation (asOWF/asPRF/asPRP/asPRG)
    │   ├── routing.js          # Reduction graph: BFS shortest path, PRIMITIVES list, getPrimitiveStatus()
    │   ├── pa_tests.js         # Console-runnable demos for PA#5–PA#10 (MAC/CCA/MD/HMAC/timing)
    │   └── utils.js            # Shared helpers: randomBytes, bytesToHex, hexToBytes, xorBytes, modPow,
    │                           #   bigIntToBytes, bytesToBigInt, constantTimeEqual, pkcs7Pad, …
    │
    └── data/
        └── reductions.js       # REDUCTION_PROOFS map + PA_DEMOS metadata (theorem text, constructions per edge)
```

---

## Setup & Running

### Prerequisites
- **Node.js** ≥ 20
- **npm** ≥ 9

```bash
# Check versions
node -v
npm -v
```

> **Note:** Node.js 20 is required for the Web Crypto API (`crypto.getRandomValues`) to work correctly in the Vite dev environment. Using an earlier version will cause runtime errors.

### Install Dependencies

```bash
cd "pois_repo_2"
npm install
```

### Run Dev Server

Use the full one-liner (recommended — ensures Node 20 is active, installs dependencies, and starts the server in one shot):

```bash
export NVM_DIR="$HOME/.nvm" && . "$NVM_DIR/nvm.sh" && nvm use 20 && npm install && npm run dev
```

Or, if you already have Node 20 active and dependencies installed:

```bash
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser. The app hot-reloads on every file save.

### Build for Production

```bash
npm run build
# Output is in dist/
```

### Preview Production Build

```bash
npm run preview
# Serves the dist/ folder at http://localhost:4173
```

---

## PA Implementation Status

All 20 programming assignments are fully implemented.

| PA | Title | Primitives / Topic | Demo Component |
|---|---|---|---|
| PA#0 | Scaffold | App shell, routing | `App.jsx` |
| PA#1 | OWF + PRG | `OWF`, `OWP`, `PRG` | `PA1Demo.jsx` |
| PA#2 | PRF (GGM Tree) | `PRF`, `PRP` | `PA2Demo.jsx` |
| PA#3 | CPA-Secure Encryption | `CPA-ENC` | `PA3Demo.jsx` |
| PA#4 | Modes of Operation | CBC, OFB, CTR | `PA4Demo.jsx` |
| PA#5 | MACs | `MAC`, EUF-CMA | `PA5Demo.jsx` |
| PA#6 | CCA-Secure Encryption | `CCA-ENC`, Encrypt-then-MAC | `PA6Demo.jsx` |
| PA#7 | Merkle-Damgård | MD construction, collision propagation | `PA7Demo.jsx` |
| PA#8 | DLP CRHF | `CRHF` | `PA8Demo.jsx` |
| PA#9 | Birthday Attack | Collision probability | `PA9Demo.jsx` |
| PA#10 | HMAC | `HMAC`, timing side-channel | `PA10Demo.jsx` |
| PA#11 | Diffie-Hellman | DH key exchange, CDH, MITM, safe primes | `PA11Demo.jsx` |
| PA#12 | RSA | Textbook RSA, PKCS#1 v1.5, Bleichenbacher CCA2 | `PA12Demo.jsx` |
| PA#13 | Miller-Rabin | Probabilistic primality, Carmichael numbers | `PA13Demo.jsx` |
| PA#14 | CRT | CRT solver, Garner's RSA speedup, Håstad broadcast | `PA14Demo.jsx` |
| PA#15 | Digital Signatures | RSA hash-then-sign, EUF-CMA, multiplicative forgery | `PA15Demo.jsx` |
| PA#16 | ElGamal | CPA-secure PKE, malleability, IND-CPA simulation | `PA16Demo.jsx` |
| PA#17 | CCA-Safe PKC | Encrypt-then-Sign signcryption (ElGamal + RSA) | `PA17Demo.jsx` |
| PA#18 | Oblivious Transfer | Bellare-Micali 1-of-2 OT over DLP subgroup | `PA18Demo.jsx` |
| PA#19 | Secure Boolean Gates | AND via OT, XOR via masking, NOT local, {AND,XOR,NOT} complete | `PA19Demo.jsx` |
| PA#20 | 2-Party MPC | GMW protocol, Millionaire's / Equality / Adder circuits | `PA20Demo.jsx` |

Implemented reduction edges in the clique graph:

```
OWF  → PRG  (HILL hard-core-bit construction)
OWF  → OWP  (DLP is a permutation)
OWP  → PRG  (hard-core predicate extraction)
PRG  → PRF  (GGM tree)
PRG  → OWF  (PRG implies OWF)
PRF  → PRP  (Luby-Rackoff 3-round Feistel)
PRF  → MAC  (Mac_k(m) = F_k(m))
PRF  → PRG  (G(s) = F_s(0) ∥ F_s(1))
PRP  → PRF  (PRP/PRF switching lemma)
PRP  → MAC  (switching lemma + PRF-MAC)
PRP  → OWF  (f(k) = PRP_k(0^n))
MAC  → PRF  (EUF-CMA → PRF on uniform inputs)
CRHF → HMAC (HMAC construction)
HMAC → MAC  (HMAC EUF-CMA security)
```

---

## Crypto Module Reference

### Symmetric / Hash primitives (PA#1–PA#10)

| File | Key Exports | Notes |
|---|---|---|
| `aes.js` | `aesEncryptBlock`, `aesDecryptBlock` | Pure-JS AES-128, no WebCrypto dependency |
| `owf.js` | `aesOWF`, `dlpOWF`, `DLP_PARAMS` | DLP uses a 128-bit safe-prime group |
| `prg.js` | `prgFromAES`, `prgFromDLP`, `createPRG` | AES counter-mode PRG; DLP uses hard-core bits |
| `prf.js` | `prfEvaluate`, `ggmPRF` | GGM tree keyed off AES PRG |
| `prp.js` | `createPRP` | 3-round Feistel using `prfEvaluate` as round function |
| `cpa_enc.js` | `cpaNonceEnc`, `indCPAGame` | Nonce-based CTR, IND-CPA simulation |
| `modes.js` | `cbcEncrypt`, `cbcDecrypt`, `ofbEncrypt`, `ctrEncrypt` | All return step traces for animation |
| `mac.js` | `prfMac`, `cbcMac`, `eufCmaGame` | PRF-MAC and CBC-MAC with EUF-CMA challenger |
| `cca_enc.js` | `ccaEncrypt`, `ccaDecrypt` | CTR + CBC-MAC Encrypt-then-MAC |
| `merkle_damgard.js` | `merkleDamgard`, `toyCompression` | MD construction + length-extension demo |
| `crhf.js` | `dlpHash` | DLP-based CRHF: g^x·h^y mod p |
| `birthday.js` | `birthdayCollision`, `collisionProbability` | Birthday attack simulation |
| `hmac.js` | `hmacConstruct`, `encryptThenHMAC` | HMAC over `dlpHash`; also drives PA#15 hash-then-sign |
| `pa_tests.js` | (console demos) | Run with `node pa_tests.js` to verify PA#5–PA#10 |

### Public-key / Number-theory (PA#11–PA#17)

| File | Key Exports | Notes |
|---|---|---|
| `miller_rabin.js` | `millerRabin`, `carmichaelDemo`, `BENCHMARK_DATA` | Probabilistic primality; correctly rejects Carmichael numbers |
| `prime.js` | `trialDivisionSieve` | Fast small-prime pre-filter used by `miller_rabin.js` |
| `rsa.js` | `rsaKeygen`, `rsaEnc`, `rsaDec`, `rsaDecCRT`, `pkcs15Enc`, `bytesToBigInt`, `bigIntToBytes` | Full RSA including Garner's CRT speedup and PKCS#1 v1.5 |
| `rsaWorker.js` | (Web Worker) | Background RSA keygen + Bleichenbacher adaptive CCA2 attack |
| `rsa_sig.js` | `rsaKeyGen`, `Sign`, `verifyWithTrace`, `createEufCmaChallenger`, `rawRsaMultiplicativeForge` | Hash-then-sign with `dlpHash`; EUF-CMA game; multiplicative forgery demo |
| `crt.js` | `crt`, `rsaDecCRT`, `hastadAttack`, `BENCHMARK_DATA` | CRT solver, Garner's algorithm, Håstad broadcast attack |
| `dh.js` | `DH_PARAMS`, `dhAliceStep1`, `dhBobStep1`, `dhAliceStep2`, `dhBobStep2`, `mitmAttack`, `cdhBruteForce`, `generateSafePrime` | Full DH exchange with MITM and CDH hardness demo |
| `elgamal.js` | `elgamalKeygen`, `Enc`, `Dec`, `malleateMultiplyC2`, `indCpaChallenge` | ElGamal over DLP subgroup; malleability & CPA simulation |
| `signcrypt.js` | `ccaPkcEnc`, `ccaPkcDec`, `createCca2Oracle`, `tamperCeEncoding` | Encrypt-then-Sign over ElGamal + RSA; IND-CCA2 oracle |

### Multi-party computation (PA#18–PA#20)

| File | Key Exports | Notes |
|---|---|---|
| `ot.js` | `otReceiverStep1`, `otSenderStep`, `otReceiverStep2`, `otReceiverCheatAttempt`, `selfTestOtBits` | Bellare-Micali 1-of-2 OT; cheat attempt shows sender privacy |
| `secure_gates.js` | `secureAnd`, `secureXor`, `secureNot`, `truthTableAnd`, `truthTableXor` | AND uses one OT call; XOR/NOT are free (additive shares) |
| `mpc.js` | `buildMillionaireCircuit`, `buildEqualityCircuit`, `buildAdderCircuit`, `secureEval`, `lineageTrace`, `runEndToEndSelfTest` | GMW 2-party circuit evaluation; gate-by-gate transcript |

### Shared infrastructure

| File | Key Exports | Notes |
|---|---|---|
| `foundation.js` | `createAESFoundation`, `createDLPFoundation`, `getFoundation` | Foundation-agnostic interface (`asOWF/asPRF/asPRP/asPRG`) |
| `routing.js` | `getReductionChain`, `PRIMITIVES`, `getPrimitiveStatus` | BFS over the reduction directed graph |
| `utils.js` | `randomBytes`, `bytesToHex`, `hexToBytes`, `xorBytes`, `modPow`, `modInverse`, `extGcd`, `gcd`, `bigIntToBytes`, `bytesToBigInt`, `constantTimeEqual`, `pkcs7Pad`, `splitBlocks`, `concatBytes`, `stringToBytes`, `bytesToString` | Pure-JS; no Node built-ins needed in browser |

---

## Component Reference

| Component | Description |
|---|---|
| `FoundationToggle.jsx` | Switches the global hardness assumption (AES ↔ DLP) |
| `BuildPanel.jsx` | Left panel: pick a source primitive, input key + query, evaluate live |
| `ReducePanel.jsx` | Right panel: pick a target, run BFS, evaluate the full reduction chain |
| `ProofPanel.jsx` | Bottom: theorem name, construction, and security bound per hop |
| `ReductionStages.jsx` | Collapsible cards showing per-hop computation steps |
| `DemoSection.jsx` | Tab bar routing to PA#1–PA#20 demo components |
| `StepDisplay.jsx` | Renders a list of `{label, value, className}` evaluation steps |

---

## Testing Guide

### 1. In-Browser Interactive Testing

Start the dev server (`npm run dev`) and use the **Demo Section** tabs:

| PA | What to test |
|---|---|
| **PA#1** | Click **Run NIST Frequency Test** and **Run Monobit Test** — both should pass for AES-PRG output. |
| **PA#2** | Run the **Distinguishing Game** — the GGM PRF should be indistinguishable from a random function. |
| **PA#3** | Run the **IND-CPA Game** and **Nonce-Reuse Attack** to observe ciphertext indistinguishability breaking. |
| **PA#4** | Encrypt/decrypt in CBC/OFB/CTR — plaintext must match. Use **Bit-Flip** and **IV-Reuse** demos for mode vulnerabilities. |
| **PA#5** | Run the EUF-CMA game; PRF-MAC should pass the distinguishing test. |
| **PA#6** | Encrypt-then-MAC round-trip; tamper with the ciphertext to observe decryption rejection. |
| **PA#7** | Observe MD hash collision propagation from the toy compression function. |
| **PA#8** | Compute DLP-CRHF on two distinct inputs; verify second-preimage resistance. |
| **PA#9** | Vary group size to observe the birthday bound empirically. |
| **PA#10** | Run HMAC round-trip; observe the **timing side-channel** demo for naive vs. constant-time comparison. |
| **PA#11** | Click **▶ Exchange** — shared secrets should match. Enable **Eve (MITM)** to see secrets diverge. Run **Brute-Force g^ab** with small exponents. |
| **PA#12** | Generate keys, **Encrypt Twice** in textbook mode (identical ciphertexts) vs PKCS#1 v1.5 (different). Run the **Bleichenbacher CCA2** attack — plaintext is recovered in seconds. |
| **PA#13** | Test 561 (Carmichael) — Miller-Rabin correctly returns COMPOSITE. Test a 512-bit prime with k=40 rounds. |
| **PA#14** | Use the CRT solver, run the **Garner live benchmark** (≈4× speedup), and run **Håstad's broadcast attack** — toggle padding on/off to see the attack succeed or fail. |
| **PA#15** | Sign a message, verify, then tamper (flip 1 bit) — verification fails. Run the **multiplicative forgery** on raw RSA. Submit random (m*, σ*) guesses in the EUF-CMA game. |
| **PA#16** | Encrypt m, then **Multiply c₂ by 2**, decrypt — oracle returns 2·m, demonstrating malleability. Run IND-CPA rounds for large vs tiny q. |
| **PA#17** | Encrypt-then-Sign a message, tamper the CE, submit to the decryption oracle — it returns ⊥ (signature invalid). Compare with plain ElGamal that leaks 2·m. |
| **PA#18** | Run OT with choice b=0 and b=1; verify Bob recovers m_b. Try the **cheat attempt** — decrypting the other ciphertext gives garbage. |
| **PA#19** | Compute secure AND (uses one OT call), XOR (free), NOT (local). Run all 4 (a,b) combinations to verify truth tables. |
| **PA#20** | Slide Alice/Bob wealth inputs and evaluate **Millionaire's**, **Equality**, and **Adder** circuits securely. Run the end-to-end self-test. |

### 2. Reduction Chain Smoke Test

In the app's **Reduce Panel**:
1. Set Source = `OWF`, Target = `PRP`.
2. The chain `OWF → PRG → PRF → PRP` should appear.
3. Enter any 32-hex-char key and 32-hex-char query, then click **Evaluate Chain**.
4. Each hop should produce a non-empty hex output.

### 3. Console Unit Checks

Open DevTools → Console while the app is running and paste snippets:

```js
// Test AES round-trip
import { aesEncryptBlock, aesDecryptBlock } from '/src/crypto/aes.js';
const key = new Uint8Array(16).fill(0x2b);
const pt  = new Uint8Array(16).fill(0x32);
const ct  = aesEncryptBlock(key, pt);
const dec = aesDecryptBlock(key, ct);
console.assert(dec.every((b, i) => b === pt[i]), 'AES round-trip failed');

// Test PRG output length
import { prgFromAES } from '/src/crypto/prg.js';
const seed = new Uint8Array(16).fill(0xaa);
const out = prgFromAES(seed, 64);
console.assert(out.output.length === 64, 'PRG length mismatch');

// Test DH shared secret agreement
import { DH_PARAMS, dhAliceStep1, dhBobStep1, dhAliceStep2, dhBobStep2 } from '/src/crypto/dh.js';
const { a, A } = dhAliceStep1(DH_PARAMS);
const { b, B } = dhBobStep1(DH_PARAMS);
const KA = dhAliceStep2(a, B, DH_PARAMS);
const KB = dhBobStep2(b, A, DH_PARAMS);
console.assert(KA === KB, 'DH key mismatch');

// Test OT correctness (choice = 1, learns m1)
import { defaultOtParams, otReceiverStep1, otSenderStep, otReceiverStep2, encodeBit, decodeBit } from '/src/crypto/ot.js';
const params = defaultOtParams();
const r1 = otReceiverStep1(1, params);
const r2 = otSenderStep(r1.pk0, r1.pk1, encodeBit(0), encodeBit(1), params);
const recovered = otReceiverStep2(r1.state, r2.c0, r2.c1);
console.assert(decodeBit(recovered) === 1, 'OT: should recover m1');
```

### 4. PA#5–PA#10 Console Demos

Run the standalone demo script directly (outside the browser, in Node.js):

```bash
node src/crypto/pa_tests.js
```

This runs six console-level demos covering:
- PRF-MAC → PRF distinguishing test (PA#5)
- Key-separation flaw when kE = kM (PA#6)
- Merkle-Damgård collision propagation (PA#7)
- MAC → CRHF backward direction (PA#10)
- Naive vs constant-time MAC comparison timing (PA#10)
- CCA2 performance: Encrypt-then-CBC-MAC vs Encrypt-then-HMAC (PA#10)

---

*Last updated: May 2026 · CS8.401 PoIS Project*
