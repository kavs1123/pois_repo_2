# Minicrypt Clique Explorer
**CS8.401 · Principles of Information Security**

An interactive web application for exploring cryptographic primitives and their reductions in the Minicrypt world. Built with **React + Vite**, it lets you pick any two cryptographic primitives, trace the shortest reduction chain between them, and interactively run the underlying implementations.

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
- **Demo Section** — run interactive demos for each programming assignment (PA#1–PA#4 implemented).

---

## Directory Structure

```
pois_project/
├── index.html                  # Vite entry point (mounts #root)
├── vite.config.js              # Vite config (React plugin)
├── package.json                # Dependencies & npm scripts
├── package-lock.json
├── pois_project_doc.pdf        # Course assignment specification
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
    │   ├── DemoSection.jsx         # Tab bar + router for PA demo components
    │   ├── StepDisplay.jsx         # Renders a single evaluation step (label + value)
    │   │
    │   └── demos/                  # One component per programming assignment
    │       ├── PA1Demo.jsx         # OWF + PRG demo (HILL construction, NIST-style tests)
    │       ├── PA2Demo.jsx         # PRF demo (GGM tree construction + distinguishing game)
    │       ├── PA3Demo.jsx         # CPA-secure encryption demo (IND-CPA game, nonce-reuse)
    │       ├── PA4Demo.jsx         # Modes of operation (CBC / OFB / CTR + bit-flip / IV-reuse)
    │       └── StubDemo.jsx        # Placeholder for unimplemented PAs (PA#5–PA#10)
    │
    ├── crypto/                 # Pure-JS cryptographic primitives (no external crypto libs)
    │   ├── aes.js              # Full AES-128: KeyExpansion, SubBytes, ShiftRows, MixColumns, encrypt/decrypt
    │   ├── owf.js              # One-Way Functions: AES-OWF (f(k) = AES_k(0^128)), DLP-OWF (f(x) = g^x mod p)
    │   ├── prg.js              # PRGs: HILL hard-core-bit PRG, AES counter-mode PRG, DLP-based PRG
    │   ├── prf.js              # PRFs: GGM tree PRF (PRG → PRF), direct AES-PRF
    │   ├── prp.js              # PRP: 3-round Luby-Rackoff Feistel (PRF → PRP)
    │   ├── cpa_enc.js          # CPA-secure encryption: nonce-based CTR mode, IND-CPA game simulation
    │   ├── modes.js            # Modes of operation: CBC, OFB, CTR (encrypt + decrypt + step traces)
    │   ├── mac.js              # MAC stub (PRF-MAC, EUF-CMA — PA#5, not yet fully wired)
    │   ├── cca_enc.js          # CCA-secure encryption stub (PA#6)
    │   ├── crhf.js             # CRHF stub (DLP-based, PA#8)
    │   ├── hmac.js             # HMAC stub (PA#10)
    │   ├── merkle_damgard.js   # Merkle-Damgård stub (PA#7)
    │   ├── birthday.js         # Birthday attack stub (PA#9)
    │   ├── foundation.js       # Foundation layer: AESFoundation & DLPFoundation (asOWF/asPRF/asPRP/asPRG)
    │   ├── routing.js          # Reduction graph: BFS shortest path, PRIMITIVES list, getPrimitiveStatus()
    │   └── utils.js            # Shared helpers: randomBytes, bytesToHex, hexToBytes, xorBytes, modPow
    │
    └── data/
        └── reductions.js       # REDUCTION_PROOFS map (theorem text, security bounds, constructions per edge)
```

---

## Setup & Running

### Prerequisites
- **Node.js** ≥ 18  
- **npm** ≥ 9

```bash
# Check versions
node -v
npm -v
```

### Install Dependencies

```bash
cd "pois_project"
npm install
```

### Run Dev Server

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

| PA | Title | Primitives | Status | Demo Component |
|---|---|---|---|---|
| PA#0 | Scaffold | — | ✅ Done | `App.jsx` |
| PA#1 | OWF + PRG | `OWF`, `OWP`, `PRG` | ✅ Done | `PA1Demo.jsx` |
| PA#2 | PRF (GGM Tree) | `PRF`, `PRP` | ✅ Done | `PA2Demo.jsx` |
| PA#3 | CPA-Secure Encryption | `CPA-ENC` | ✅ Done | `PA3Demo.jsx` |
| PA#4 | Modes of Operation | CBC, OFB, CTR | ✅ Done | `PA4Demo.jsx` |
| PA#5 | MACs | `MAC` | 🔲 Stub | `StubDemo.jsx` |
| PA#6 | CCA-Secure Encryption | `CCA-ENC` | 🔲 Stub | `StubDemo.jsx` |
| PA#7 | Merkle-Damgård | — | 🔲 Stub | `StubDemo.jsx` |
| PA#8 | DLP CRHF | `CRHF` | 🔲 Stub | `StubDemo.jsx` |
| PA#9 | Birthday Attack | — | 🔲 Stub | `StubDemo.jsx` |
| PA#10 | HMAC | `HMAC` | 🔲 Stub | `StubDemo.jsx` |

Implemented reduction edges in the clique graph:

```
OWF  → PRG  (HILL hard-core-bit construction)
OWF  → OWP  (DLP is a permutation)
OWP  → PRG  (Goldreich-Levin + OWP→PRG)
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

| File | Key Exports | Notes |
|---|---|---|
| `aes.js` | `aesEncryptBlock`, `aesDecryptBlock` | Pure-JS AES-128, no WebCrypto dependency |
| `owf.js` | `aesOWF`, `dlpOWF`, `DLP_PARAMS` | DLP uses a 128-bit safe-prime group |
| `prg.js` | `prgFromAES`, `prgFromDLP`, `createPRG` | AES counter-mode PRG; DLP uses hard-core bits |
| `prf.js` | `prfEvaluate`, `ggmPRF` | GGM tree keyed off AES PRG |
| `prp.js` | `createPRP` | 3-round Feistel using `prfEvaluate` as round function |
| `cpa_enc.js` | `cpaNonceEnc`, `indCPAGame` | Nonce-based CTR, IND-CPA simulation |
| `modes.js` | `cbcEncrypt`, `cbcDecrypt`, `ofbEncrypt`, `ctrEncrypt` | All return step traces for animation |
| `foundation.js` | `createAESFoundation`, `createDLPFoundation`, `getFoundation` | Foundation-agnostic interface (`asOWF/asPRF/asPRP/asPRG`) |
| `routing.js` | `getReductionChain`, `PRIMITIVES`, `getPrimitiveStatus` | BFS over the reduction directed graph |
| `utils.js` | `randomBytes`, `bytesToHex`, `hexToBytes`, `xorBytes`, `modPow` | Pure-JS; no Node built-ins needed in browser |

---

## Testing Guide

There is no dedicated test runner configured yet. Use the following approaches to verify correctness:

### 1. In-Browser Interactive Testing

Start the dev server (`npm run dev`) and:

- **PA#1 OWF/PRG**: Open the *PA#1* tab in the Demo Section. Click **Run NIST Frequency Test** and **Run Monobit Test** — both should pass for AES-PRG output.
- **PA#2 PRF/GGM**: Open the *PA#2* tab. Run the **Distinguishing Game** — a random function and the GGM PRF are compared; the PRF should be indistinguishable.
- **PA#3 CPA**: Open the *PA#3* tab. Run the **IND-CPA Game** and observe ciphertext indistinguishability. Use the **Nonce-Reuse Attack** button to see how deterministic encryption breaks IND-CPA.
- **PA#4 Modes**: Open the *PA#4* tab. Encrypt a message in CBC/OFB/CTR and decrypt it back — plaintext should match. Use **Bit-Flip Demo** and **IV-Reuse Demo** to see mode vulnerabilities.

### 2. Reduction Chain Smoke Test

In the app's **Reduce Panel**:
1. Set Source = `OWF`, Target = `PRP`.
2. The chain `OWF → PRG → PRF → PRP` should appear.
3. Enter any 32-hex-char key and 32-hex-char query, then click **Evaluate Chain**.
4. Each hop should produce a non-empty hex output.

### 3. Console Unit Checks

Open DevTools → Console and paste snippets to test modules directly:

```js
// Import via Vite HMR (works in app context)
// Or open the browser console while the app is running

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
```

### 4. Adding a New PA Demo

1. Create `src/components/demos/PA5Demo.jsx`.
2. Implement the crypto logic in `src/crypto/mac.js` (already stubbed).
3. Register the component in `src/components/DemoSection.jsx` under tab index `5`.
4. Update `getPrimitiveStatus('MAC')` in `routing.js` to `implemented: true`.

---

*Last updated: April 2026 · CS8.401 PoIS Project*
