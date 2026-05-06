# Conformance Tests (PA5-PA10)

These checks are manual, in-app validations aligned to the PA5-PA10 deliverables.

## PA5: MACs
- PRF-MAC/CBC-MAC correctness
  - In the PA#5 tab, click "Generate MAC Oracle Queries".
  - Verify at least 10 messages render with tags and no errors.
- EUF-CMA forgery attempt
  - Enter a fresh message and a random tag; click "Submit Forgery".
  - Expected: "Forgery rejected" with 0 successes after 20 attempts.
- Length-extension demo (naive MAC)
  - Set Message="message", Suffix="suffix", click "Run Length-Extension Demo".
  - Expected: "forgery succeeds" in the result.

## PA6: CCA-Secure Encryption
- Encrypt-then-MAC correctness
  - In PA#6, click "Encrypt".
  - Expected: ciphertext and tag show; no errors.
- Malleability contrast
  - Click "Flip Bit" and check both panels.
  - Expected: CPA-only shows decrypted plaintext (corrupted).
  - Expected: CCA panel shows "rejected".

## PA7: Merkle-Damgard
- Padding and block chaining
  - In PA#7, type a short message (e.g., "abc").
  - Expected: block list includes padding and steps show chaining values.
- Avalanche check
  - Change 1 character and verify blocks and chaining values update.

## PA8: DLP CRHF
- Hash output
  - In PA#8, type multiple messages.
  - Expected: digest changes for each message.
- Collision hunt (toy)
  - Click "Collision Hunt (16-bit)".
  - Expected: collision found with evaluations near 2^(16/2) ~ 256.

## PA9: Birthday Attack
- Output-length sweep
  - In PA#9, run attack with n=8,10,12,14,16.
  - Expected: evaluations scale near 2^(n/2).

## PA10: HMAC
- Length extension vs HMAC
  - In PA#10, set Message="hello", Suffix="world", click "Run Demo".
  - Expected: naive MAC shows "forgery succeeds".
  - Expected: HMAC shows "rejected".
- Encrypt-then-HMAC
  - Click "Run EtH Check".
  - Expected: decrypt (flipped) is "rejected".
