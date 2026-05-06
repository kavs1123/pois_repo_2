/**
 * PA#7: Merkle-Damgard Transform.
 * Provides a generic hash construction over a compression function.
 */

import { bytesToHex, concatBytes } from './utils.js';

/**
 * MD-strengthening padding.
 * Appends 0x80, zero padding, then 64-bit big-endian length (in bits).
 */
export function mdPad(totalLengthBytes, blockSize) {
  const bitLen = BigInt(totalLengthBytes) * 8n;
  const lenBytes = 8;
  const minPad = 1 + lenBytes; // 0x80 + length
  const rem = (totalLengthBytes + minPad) % blockSize;
  const padZeros = rem === 0 ? 0 : (blockSize - rem);
  const pad = new Uint8Array(minPad + padZeros);
  pad[0] = 0x80;
  for (let i = 0; i < lenBytes; i++) {
    pad[pad.length - 1 - i] = Number((bitLen >> BigInt(8 * i)) & 0xffn);
  }
  return pad;
}

/**
 * Merkle-Damgard hash for an arbitrary message.
 * @param {Function} compress - (cvBytes, blockBytes) => Uint8Array
 * @param {Uint8Array} message
 * @param {{ blockSize?: number, iv?: Uint8Array, trace?: boolean }} options
 */
export function merkleDamgard(compress, message, options = {}) {
  const blockSize = options.blockSize || 8;
  const iv = options.iv || new Uint8Array(4);
  const trace = Boolean(options.trace);

  const pad = mdPad(message.length, blockSize);
  const padded = concatBytes(message, pad);

  return merkleDamgardWithState(compress, padded, {
    blockSize,
    iv,
    trace,
    totalLengthBytes: 0,
    alreadyPadded: true,
  });
}

/**
 * Merkle-Damgard hash starting from a provided chaining value.
 * Useful for length-extension demonstrations.
 */
export function merkleDamgardWithState(compress, message, options = {}) {
  const blockSize = options.blockSize || 8;
  const iv = options.iv || new Uint8Array(4);
  const trace = Boolean(options.trace);
  const totalLengthBytes = options.totalLengthBytes || 0;
  const alreadyPadded = Boolean(options.alreadyPadded);

  const steps = [];
  let cv = new Uint8Array(iv);

  const pad = alreadyPadded ? new Uint8Array(0) : mdPad(totalLengthBytes + message.length, blockSize);
  const padded = alreadyPadded ? message : concatBytes(message, pad);

  if (trace) {
    steps.push({ label: 'Block size', value: `${blockSize} bytes` });
    steps.push({ label: 'IV', value: bytesToHex(cv) });
    if (!alreadyPadded) {
      steps.push({ label: 'Padding', value: bytesToHex(pad) });
    }
  }

  for (let i = 0; i < padded.length; i += blockSize) {
    const block = padded.slice(i, i + blockSize);
    const next = compress(cv, block);
    if (trace) {
      steps.push({ label: `Block ${i / blockSize}`, value: bytesToHex(block) });
      steps.push({ label: `CV ${i / blockSize + 1}`, value: bytesToHex(next) });
    }
    cv = next;
  }

  return { digest: cv, steps };
}

/**
 * Toy compression function for demos.
 * XORs the chaining value with the block, then folds to the output size.
 */
export function toyCompression(cv, block) {
  const out = new Uint8Array(cv.length);
  for (let i = 0; i < block.length; i++) {
    out[i % out.length] ^= block[i];
  }
  for (let i = 0; i < cv.length; i++) {
    out[i] ^= cv[i];
  }
  return out;
}

export const PA_NUMBER = 7;
export const STUB = false;