/**
 * Foundation Layer.
 *
 * Two concrete foundations:
 * 1. AESFoundation — wraps AES-128 as PRP/PRF. Exposes asOWF(), asPRF(), asPRP().
 * 2. DLPFoundation — wraps DLP-based OWF. Exposes asOWF(), asOWP().
 *
 * Both share a common interface so the rest of the app is foundation-agnostic.
 */

import { aesEncryptBlock, aesDecryptBlock } from './aes.js';
import { dlpOWF, aesOWF, DLP_PARAMS } from './owf.js';
import { prfEvaluate, ggmPRF } from './prf.js';
import { createPRP } from './prp.js';
import { createPRG, prgFromAES, prgFromDLP } from './prg.js';
import { bytesToHex, hexToBytes, randomBytes, modPow } from './utils.js';

/**
 * AES Foundation.
 * AES-128 is a concrete PRP. By the PRP/PRF switching lemma, it's also a PRF.
 * As an OWF: f(k) = AES_k(0^128).
 */
export function createAESFoundation() {
  return {
    name: 'AES-128',
    type: 'aes',
    description: 'AES-128 block cipher (PRP/PRF)',

    /** Use AES as a OWF: f(k) = AES_k(0^128) || k */
    asOWF() {
      return {
        name: 'AES-OWF',
        evaluate(k) {
          return aesOWF(k);
        }
      };
    },

    /** Use AES directly as a PRF: F_k(x) = AES_k(x) */
    asPRF() {
      return {
        name: 'AES-PRF',
        evaluate(key, input) {
          const output = aesEncryptBlock(key, input);
          return {
            output,
            steps: [
              { label: 'PRF (AES)', value: `F_k(${bytesToHex(input).slice(0,8)}...) = ${bytesToHex(output)}` }
            ]
          };
        }
      };
    },

    /** Use AES as a PRP (it already is one) */
    asPRP() {
      return {
        name: 'AES-PRP',
        encrypt(key, block) {
          return {
            output: aesEncryptBlock(key, block),
            steps: [{ label: 'PRP (AES)', value: `E_k(x) = AES_k(x)` }]
          };
        },
        decrypt(key, block) {
          return {
            output: aesDecryptBlock(key, block),
            steps: [{ label: 'PRP⁻¹ (AES)', value: `D_k(x) = AES⁻¹_k(x)` }]
          };
        }
      };
    },

    /** Build a PRG from AES: G(s) = F_s(0) || F_s(1) */
    asPRG() {
      return {
        name: 'AES-PRG',
        generate(seed, outputLen) {
          return prgFromAES(seed, outputLen);
        }
      };
    },
  };
}

/**
 * DLP Foundation.
 * The Discrete Logarithm Problem gives us a concrete OWF/OWP.
 */
export function createDLPFoundation() {
  return {
    name: 'DLP',
    type: 'dlp',
    description: `Discrete Logarithm Problem (p=${DLP_PARAMS.p}, g=${DLP_PARAMS.g})`,

    /** DLP as OWF: f(x) = g^x mod p */
    asOWF() {
      return {
        name: 'DLP-OWF',
        evaluate(x) {
          if (typeof x === 'object' && x instanceof Uint8Array) {
            // Convert bytes to BigInt
            let val = 0n;
            for (const b of x) val = (val << 8n) | BigInt(b);
            return dlpOWF(val % DLP_PARAMS.q);
          }
          return dlpOWF(x);
        }
      };
    },

    /** DLP is already a OWP (for the DLP foundation, identity) */
    asOWP() {
      return {
        name: 'DLP-OWP',
        evaluate(x) {
          const result = dlpOWF(typeof x === 'bigint' ? x : BigInt(x));
          return {
            ...result,
            steps: [
              ...result.steps,
              { label: 'OWP note', value: 'DLP is already a OWP (permutation on the subgroup)' }
            ]
          };
        }
      };
    },

    /** Build a PRG from DLP using hard-core bits */
    asPRG() {
      return {
        name: 'DLP-PRG',
        generate(seed, outputLen) {
          const s = typeof seed === 'bigint' ? seed : (() => {
            let val = 0n;
            for (const b of seed) val = (val << 8n) | BigInt(b);
            return val % DLP_PARAMS.q;
          })();
          return prgFromDLP(s, outputLen * 8);
        }
      };
    },
  };
}

/**
 * Get a foundation by type.
 */
export function getFoundation(type) {
  return type === 'aes' ? createAESFoundation() : createDLPFoundation();
}
