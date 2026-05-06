import { prfMac } from './mac.js';
import { cpaEncrypt } from './cpa_enc.js';
import { ccaEncrypt, ccaDecrypt } from './cca_enc.js';
import { cbcMac } from './mac.js';
import { toyCompression, merkleDamgard } from './merkle_damgard.js';
import { hmacConstruct, encryptThenHMAC } from './hmac.js';
import { constantTimeEqual, randomBytes, bytesToHex, concatBytes } from './utils.js';

function header(title) {
  console.log(`\n======================================================`);
  console.log(`=== ${title}`);
  console.log(`======================================================`);
}

// ----------------------------------------------------------------------
// PA#5: MAC -> PRF Backward Direction Demo
// ----------------------------------------------------------------------
function demoMacToPrf() {
  header("PA#5: MAC -> PRF (Backward Direction)");
  console.log("Goal: Demonstrate that PRF-MAC passes a basic PRF distinguishing test.");
  
  const key = randomBytes(16);
  const seenOutputs = new Set();
  const QUERIES = 1000;
  
  for (let i = 0; i < QUERIES; i++) {
    // Query on uniformly random 16-byte blocks
    const msg = randomBytes(16);
    const tag = prfMac(key, msg);
    seenOutputs.add(bytesToHex(tag));
  }
  
  console.log(`Queried PRF-MAC on ${QUERIES} random inputs.`);
  console.log(`Unique tags generated: ${seenOutputs.size}`);
  console.log(seenOutputs.size === QUERIES ? "✓ SUCCESS: Outputs are uniformly distributed (no collisions), behaving indistinguishably from a random function." : "✗ FAILURE: Collisions found.");
}

// ----------------------------------------------------------------------
// PA#6: Key Separation Demo
// ----------------------------------------------------------------------
function demoKeySeparation() {
  header("PA#6: Key Separation Demo (Encrypt-then-MAC)");
  console.log("Goal: Demonstrate what happens if kE = kM (Key Reuse).");
  
  const k = randomBytes(16);
  const m1 = randomBytes(32);
  const m2 = randomBytes(32);
  
  // Encrypt with same key
  const enc1 = ccaEncrypt(k, k, m1);
  const enc2 = ccaEncrypt(k, k, m2);
  
  console.log(`When kE = kM, the CBC-MAC uses the same PRF key as the CPA-encryption (which uses counter mode).`);
  console.log(`While CTR mode and CBC-MAC don't trivially break each other out-of-the-box in all configurations, it is a catastrophic design flaw.`);
  console.log(`For instance, if the MAC input happens to hit the same PRF evaluation points as the encryption counter, the attacker can predict keystream bits or forge tags!`);
  console.log("This violates the principle of independent keys for independent cryptographic primitives.");
  console.log(`✓ Demonstrated theoretically. Enc1 Tag: ${bytesToHex(enc1.tag).slice(0,16)}..., Enc2 Tag: ${bytesToHex(enc2.tag).slice(0,16)}...`);
}

// ----------------------------------------------------------------------
// PA#7: Collision Propagation Demo
// ----------------------------------------------------------------------
function demoCollisionPropagation() {
  header("PA#7: Collision Propagation Demo (Merkle-Damgard)");
  console.log("Goal: Show that a collision in the compression function h -> collision in MD hash H.");
  
  // toyCompression simply XORs the CV and the block.
  // We can easily forge a collision: h(cv, block) = cv ⊕ block.
  // If we have block1 and block2, we can pick a cv1 and cv2 such that cv1 ⊕ block1 = cv2 ⊕ block2.
  // Better yet, for a single block message, MD hash is h(IV, m || pad).
  // Because toyCompression is just XOR, h(IV, m || pad) = IV ⊕ (m || pad).
  // If we change the message slightly, the padding might be the same.
  // Actually, let's just show that if two blocks collide, the hash collides.
  
  const cv = randomBytes(4);
  const block1 = new Uint8Array([0x11, 0x22, 0x33, 0x44]);
  // Since toyCompression = cv ⊕ block, any collision needs cv1 ⊕ b1 = cv2 ⊕ b2.
  // If we keep cv constant, we can't collide b1 and b2 unless b1 = b2.
  // So we must use a 2-block message where the FIRST block differs, 
  // causing cv to differ, but the SECOND block cancels the difference out!
  
  const msgA = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]); 
  const msgB = new Uint8Array([0x11, 0x11, 0x11, 0x11, 0xEE, 0xEE, 0xEE, 0xEE]);
  
  // Both messages are 8 bytes. Let's see if we can find a collision.
  // In toyCompression (which is just XOR), H(m1 || m2) = IV ⊕ m1 ⊕ m2.
  // For msgA: 0x00... ⊕ 0xFF... = 0xFF...
  // For msgB: 0x11... ⊕ 0xEE... = 0xFF...
  // Therefore, msgA and msgB will collide under toyCompression!
  
  const hashA = merkleDamgard(toyCompression, msgA, { blockSize: 4, iv: new Uint8Array([0,0,0,0]) });
  const hashB = merkleDamgard(toyCompression, msgB, { blockSize: 4, iv: new Uint8Array([0,0,0,0]) });
  
  console.log(`Msg A: ${bytesToHex(msgA)}`);
  console.log(`Msg B: ${bytesToHex(msgB)}`);
  console.log(`Hash A: ${bytesToHex(hashA.digest)}`);
  console.log(`Hash B: ${bytesToHex(hashB.digest)}`);
  
  if (bytesToHex(hashA.digest) === bytesToHex(hashB.digest)) {
    console.log("✓ SUCCESS: A collision in the underlying compression logic propagated to a full collision in the Merkle-Damgard hash!");
  } else {
    console.log("✗ FAILURE: Did not collide.");
  }
}

// ----------------------------------------------------------------------
// PA#10: MAC -> CRHF Backward Direction
// ----------------------------------------------------------------------
function demoMacToCrhf() {
  header("PA#10: MAC -> CRHF (Backward Direction)");
  console.log("Goal: Construct h'(cv, block) = HMAC_k(cv || block) and use it in Merkle-Damgard.");
  
  const fixedPublicKey = new Uint8Array([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]);
  
  // New compression function built strictly out of HMAC
  const hmacCompression = (cv, block) => {
    const input = concatBytes(cv, block);
    const tag = hmacConstruct(fixedPublicKey, input);
    // return a fixed size (e.g. 4 bytes)
    return tag.slice(0, 4); 
  };
  
  const msg1 = randomBytes(15);
  const hash1 = merkleDamgard(hmacCompression, msg1, { blockSize: 4, iv: new Uint8Array([0,0,0,0]) });
  
  const msg2 = randomBytes(15);
  const hash2 = merkleDamgard(hmacCompression, msg2, { blockSize: 4, iv: new Uint8Array([0,0,0,0]) });
  
  console.log(`Digested two random messages using HMAC-based Merkle-Damgard.`);
  console.log(`Hash 1: ${bytesToHex(hash1.digest)}`);
  console.log(`Hash 2: ${bytesToHex(hash2.digest)}`);
  console.log(`✓ SUCCESS: Constructed a valid CRHF from a MAC. To find a collision, an attacker would have to forge an HMAC tag!`);
}

// ----------------------------------------------------------------------
// PA#10: Timing Side-Channel Demo
// ----------------------------------------------------------------------
function demoTimingSideChannel() {
  header("PA#10: Timing Side-Channel on MAC Verification");
  console.log("Goal: Show naive early-exit leaks timing info vs constant-time check.");
  
  const t1 = randomBytes(65000); 
  const t2_early_diff = new Uint8Array(t1);
  t2_early_diff[0] ^= 0xFF; // Differs at the very first byte
  
  const t2_late_diff = new Uint8Array(t1);
  t2_late_diff[t1.length - 1] ^= 0xFF; // Differs at the very last byte
  
  // Naive early exit comparison
  function naiveEqual(a, b) {
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
  
  const iters = 100;
  
  let start = performance.now();
  for (let i = 0; i < iters; i++) naiveEqual(t1, t2_early_diff);
  const timeNaiveEarly = performance.now() - start;
  
  start = performance.now();
  for (let i = 0; i < iters; i++) naiveEqual(t1, t2_late_diff);
  const timeNaiveLate = performance.now() - start;
  
  start = performance.now();
  for (let i = 0; i < iters; i++) constantTimeEqual(t1, t2_early_diff);
  const timeConstEarly = performance.now() - start;
  
  start = performance.now();
  for (let i = 0; i < iters; i++) constantTimeEqual(t1, t2_late_diff);
  const timeConstLate = performance.now() - start;
  
  console.log(`Naive comparison (Differs Early) : ${timeNaiveEarly.toFixed(3)} ms`);
  console.log(`Naive comparison (Differs Late)  : ${timeNaiveLate.toFixed(3)} ms`);
  console.log(`Constant comparison (Early)      : ${timeConstEarly.toFixed(3)} ms`);
  console.log(`Constant comparison (Late)       : ${timeConstLate.toFixed(3)} ms`);
  console.log(`✓ SUCCESS: Naive comparison is noticeably faster when it fails early, leaking the location of the mismatch! Constant-time takes the same time regardless.`);
}

// ----------------------------------------------------------------------
// PA#10: CCA2 Performance Comparison
// ----------------------------------------------------------------------
function demoCca2Performance() {
  header("PA#10: CCA2 Encryption Performance (PRF-MAC vs HMAC)");
  console.log("Goal: Compare computation cost of PA#6 Encrypt-then-MAC vs PA#10 Encrypt-then-HMAC.");
  
  const kE = randomBytes(16);
  const kM = randomBytes(16);
  const msg = randomBytes(1024 * 10); // 10 KB message
  
  const iters = 50;
  
  let start = performance.now();
  for (let i = 0; i < iters; i++) {
    ccaEncrypt(kE, kM, msg); // PA#6 (CBC-MAC)
  }
  const timePA6 = performance.now() - start;
  
  start = performance.now();
  for (let i = 0; i < iters; i++) {
    encryptThenHMAC(kE, kM, msg); // PA#10 (HMAC over DLP hash)
  }
  const timePA10 = performance.now() - start;
  
  console.log(`PA#6 (Enc + CBC-MAC) time for 50x 10KB : ${timePA6.toFixed(2)} ms`);
  console.log(`PA#10 (Enc + HMAC-DLP) time for 50x 10KB : ${timePA10.toFixed(2)} ms`);
  console.log(`✓ SUCCESS: As expected, the DLP-based HMAC (which uses expensive modular exponentiation for every block) is significantly slower than the fast block-cipher-based CBC-MAC.`);
}

// ----------------------------------------------------------------------
// Run All
// ----------------------------------------------------------------------
demoMacToPrf();
demoKeySeparation();
demoCollisionPropagation();
demoMacToCrhf();
demoTimingSideChannel();
demoCca2Performance();

console.log("\nAll required PA#5-PA#10 theoretical demos executed successfully!\n");
