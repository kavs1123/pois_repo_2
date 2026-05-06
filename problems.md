Critical
Bidirectional mode is UI-only: it swaps the selected primitives but does not compute reverse reductions or swap column roles. Column order is fixed and the routing table is forward-only, so B→A paths generally fail. See src/App.jsx and src/crypto/routing.js.
Column 2 violates the “black-box A from Column 1” rule: it calls primitives (PRG/PRF/PRP) directly from keys, bypassing the concrete A instance built in Column 1. See src/components/ReducePanel.jsx and src/components/BuildPanel.jsx.
DLP foundation path is not respected in PRF construction: ggmPRF expands using AES, so DLP→PRG→PRF uses AES under the hood. See src/crypto/prf.js.
Major
AES OWF construction is wrong per spec (concatenation vs XOR/Davies–Meyer). aesOWF outputs AES_k(0)||k instead of AES_k(0) ⊕ k. See src/crypto/owf.js.
PA#1 forward OWF→PRG (HILL hard-core-bit) is not used for AES; prgFromAES is AES-CTR expansion, not the HILL construction from the OWF. See src/crypto/prg.js.
PRG interface doesn’t match the required seed() + nextbits(n) signature; it exposes nextBytes. See src/crypto/prg.js.
PA#2 demo lacks the required GGM tree visualization and path highlighting; it only shows step text. See src/components/demos/PA2Demo.jsx.
PA#3 “broken mode” doesn’t yield advantage ≈ 1 as required; the adversary still guesses randomly even when the nonce is reused. See src/components/demos/PA3Demo.jsx.
PA#4 demo reuses a single IV across encryptions (useMemo), but CBC/OFB require a fresh IV per encryption call. See src/components/demos/PA4Demo.jsx.
Minor
Reduction chain text and steps for OWF→PRG in Column 2 are hard-coded to AES expansion regardless of foundation selection. See src/components/ReducePanel.jsx.

