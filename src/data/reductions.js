/**
 * Reduction chain metadata and proof text.
 * Used by the ProofPanel component.
 */

export const REDUCTION_PROOFS = {
  'OWF→PRG': {
    theorem: 'HILL Theorem (Håstad-Impagliazzo-Levin-Luby)',
    statement: 'Any OWF with a hard-core predicate yields a PRG.',
    security: 'If adversary breaks PRG with advantage ε, it inverts the OWF with advantage ε\' ≥ ε/poly(n).',
    construction: 'G(x₀) = b(x₀) ∥ b(x₁) ∥ ... ∥ b(xℓ) where xᵢ₊₁ = f(xᵢ)',
    pa: 1,
  },
  'OWF→OWP': {
    theorem: 'DLP as OWP',
    statement: 'The DLP function f(x) = gˣ mod p is a permutation on the subgroup of order q.',
    security: 'Inverting the OWP is as hard as solving the discrete logarithm problem.',
    construction: 'f(x) = gˣ mod p (bijection on ℤ_q)',
    pa: 1,
  },
  'PRG→PRF': {
    theorem: 'GGM Theorem (Goldreich-Goldwasser-Micali)',
    statement: 'Any PRG that doubles its input yields a PRF via the GGM tree construction.',
    security: 'If adversary breaks PRF with advantage ε making q queries, it breaks PRG with advantage ε\' ≥ ε/n (tree depth n).',
    construction: 'F_k(x) = G_{xₙ}(...G_{x₁}(k)) where G₀/G₁ are halves of PRG output',
    pa: 2,
  },
  'PRF→PRP': {
    theorem: 'Luby-Rackoff Theorem',
    statement: 'A 3-round Feistel network using a PRF yields a secure PRP.',
    security: 'If adversary breaks PRP with advantage ε making q queries, it breaks PRF with advantage ε\' ≥ ε - q²/2ⁿ.',
    construction: '3 rounds of Feistel: Lᵢ₊₁ = Rᵢ, Rᵢ₊₁ = Lᵢ ⊕ F_{kᵢ}(Rᵢ)',
    pa: 2,
  },
  'PRF→MAC': {
    theorem: 'PRF-MAC Security',
    statement: 'A PRF directly yields a secure fixed-length MAC.',
    security: 'If adversary forges MAC with probability ε, it distinguishes PRF from random with advantage ε.',
    construction: 'Mac_k(m) = F_k(m)',
    pa: 5,
  },
  'PRP→MAC': {
    theorem: 'Switching Lemma + PRF-MAC',
    statement: 'A PRP is used as a PRF (switching lemma), then as a MAC.',
    security: 'Advantage ≤ q²/2ⁿ + ε_{PRF-MAC}',
    construction: 'PRP →^{switch} PRF →^{direct} MAC',
    pa: [2, 5],
  },
  'PRP→PRF': {
    theorem: 'PRP/PRF Switching Lemma',
    statement: 'A PRP over {0,1}ⁿ is indistinguishable from a PRF for polynomial queries.',
    security: '|Pr[D^PRP=1] - Pr[D^PRF=1]| ≤ q²/2ⁿ',
    construction: 'Use PRP directly as PRF (identity)',
    pa: 2,
  },
  'CRHF→HMAC': {
    theorem: 'HMAC Security (Bellare, 2006)',
    statement: 'HMAC built from a CRHF is a secure MAC.',
    security: 'Security reduces to PRF-security of the compression function.',
    construction: 'HMAC_k(m) = H((k ⊕ opad) ∥ H((k ⊕ ipad) ∥ m))',
    pa: 10,
  },
  'HMAC→MAC': {
    theorem: 'HMAC EUF-CMA Security',
    statement: 'HMAC is a secure EUF-CMA MAC.',
    security: 'Any forgery on HMAC breaks the underlying PRF (compression function).',
    construction: 'HMAC is directly a MAC (identity)',
    pa: 10,
  },
  'PRG→OWF': {
    theorem: 'PRG implies OWF',
    statement: 'f(s) = G(s) is a OWF if G is a secure PRG.',
    security: 'If f is invertible, the inverter distinguishes PRG output from random.',
    construction: 'f(s) = G(s)',
    pa: 1,
  },
  'PRF→PRG': {
    theorem: 'PRF→PRG Construction',
    statement: 'A PRF yields a PRG: G(s) = F_s(0) ∥ F_s(1).',
    security: 'If G is distinguishable, the distinguisher breaks the PRF.',
    construction: 'G(s) = F_s(0) ∥ F_s(1)',
    pa: 2,
  },
  'MAC→PRF': {
    theorem: 'MAC→PRF (Uniform Inputs)',
    statement: 'A secure MAC queried on uniform random inputs is a PRF.',
    security: 'EUF-CMA security implies pseudorandomness on random inputs.',
    construction: 'Use MAC oracle as PRF oracle',
    pa: 5,
  },
  'OWP→PRG': {
    theorem: 'Goldreich-Levin + OWP→PRG',
    statement: 'Any OWP with a hard-core predicate yields a PRG.',
    security: 'Same as HILL, but simpler because f is a permutation.',
    construction: 'G(x) = (f(x), b(x))',
    pa: 1,
  },
};

/**
 * Get proof text for a reduction chain.
 */
export function getProofChain(reductions) {
  return reductions.map(r => {
    const key = `${r.from}→${r.to}`;
    return {
      ...r,
      proof: REDUCTION_PROOFS[key] || { theorem: 'Unknown', statement: 'No proof available' },
    };
  });
}

/**
 * PA assignment demo descriptions.
 */
export const PA_DEMOS = {
  0: { title: 'PA#0: Minicrypt Clique Web Explorer', description: 'Interactive scaffold for exploring cryptographic reductions.' },
  1: { title: 'PA#1: OWF + PRG', description: 'One-Way Functions and Pseudorandom Generators with NIST tests.' },
  2: { title: 'PA#2: PRF (GGM Tree)', description: 'Pseudorandom Functions via GGM tree + distinguishing game.' },
  3: { title: 'PA#3: CPA-Secure Encryption', description: 'IND-CPA game with nonce-reuse attack demo.' },
  4: { title: 'PA#4: Modes of Operation', description: 'CBC, OFB, CTR mode animator with bit-flip and IV-reuse demos.' },
  5: { title: 'PA#5: MACs', description: 'PRF-MAC, CBC-MAC, EUF-CMA game, and length-extension demo.' },
  6: { title: 'PA#6: CCA-Secure Encryption', description: 'Encrypt-then-MAC with malleability comparison.' },
  7: { title: 'PA#7: Merkle-Damgard', description: 'Padding + chaining visualizer for arbitrary-length hashing.' },
  8: { title: 'PA#8: DLP CRHF', description: 'DLP-based compression + full CRHF with collision demo.' },
  9: { title: 'PA#9: Birthday Attack', description: 'Collision finding vs. theoretical birthday bound.' },
  10: { title: 'PA#10: HMAC', description: 'HMAC vs. length-extension + Encrypt-then-HMAC.' },
  15: { title: 'PA#15: Digital Signatures', description: 'RSA hash-then-sign, raw RSA forgery, EUF-CMA oracle.' },
  16: { title: 'PA#16: ElGamal', description: 'Enc/Dec, malleability, IND-CPA large vs tiny q, CCA discussion.' },
  17: { title: 'PA#17: CCA PKC', description: 'Encrypt-then-Sign signcryption; verify-then-decrypt; oracle rejects tampering.' },
};
