/*!
 * @hebcal/murmurhash3
 *
 * Pure-JavaScript implementation of the MurmurHash3 (x86) non-cryptographic
 * hash by Austin Appleby, hashing the UTF-8 byte encoding of the input string.
 *
 * The output is byte-for-byte identical to the native `murmurhash3` npm package
 * (hideo55's `MurmurHash3_x86_32` / `MurmurHash3_x86_128`) for every input,
 * so it is a drop-in replacement that preserves previously computed hashes.
 *
 * BSD 2-Clause Licensed.
 */

function rotl32(x: number, r: number): number {
  return (x << r) | (x >>> (32 - r));
}

function fmix32(h: number): number {
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  h ^= h >>> 16;
  return h;
}

function toBytes(key: string): Uint8Array {
  // Hash the UTF-8 encoding, matching the native binding's Utf8Value().
  return new TextEncoder().encode(key);
}

function readUInt32LE(b: Uint8Array, i: number): number {
  return (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;
}

/**
 * MurmurHash3 x86 32-bit, returning an unsigned 32-bit integer.
 * @param key input string (hashed as UTF-8)
 * @param seed optional 32-bit seed (default 0)
 */
export function murmur32Sync(key: string, seed = 0): number {
  const data = toBytes(key);
  const len = data.length;
  const nblocks = len >>> 2;
  let h1 = seed >>> 0;
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;

  for (let i = 0; i < nblocks; i++) {
    let k1 = readUInt32LE(data, i << 2);
    k1 = Math.imul(k1, c1);
    k1 = rotl32(k1, 15);
    k1 = Math.imul(k1, c2);
    h1 ^= k1;
    h1 = rotl32(h1, 13);
    h1 = (Math.imul(h1, 5) + 0xe6546b64) | 0;
  }

  const tail = nblocks << 2;
  let k1 = 0;
  switch (len & 3) {
    case 3:
      k1 ^= data[tail + 2] << 16;
    // falls through
    case 2:
      k1 ^= data[tail + 1] << 8;
    // falls through
    case 1:
      k1 ^= data[tail];
      k1 = Math.imul(k1, c1);
      k1 = rotl32(k1, 15);
      k1 = Math.imul(k1, c2);
      h1 ^= k1;
  }

  h1 ^= len;
  h1 = fmix32(h1);
  return h1 >>> 0;
}

function toHex8(n: number): string {
  return (n >>> 0).toString(16).padStart(8, '0');
}

/**
 * MurmurHash3 x86 32-bit, returning an 8-character zero-padded hex string.
 * @param key input string (hashed as UTF-8)
 * @param seed optional 32-bit seed (default 0)
 */
export function murmur32HexSync(key: string, seed = 0): string {
  return toHex8(murmur32Sync(key, seed));
}

/**
 * MurmurHash3 x86 128-bit, returning an array of four unsigned 32-bit integers.
 * @param key input string (hashed as UTF-8)
 * @param seed optional 32-bit seed (default 0)
 */
export function murmur128Sync(key: string, seed = 0): number[] {
  const data = toBytes(key);
  const len = data.length;
  const nblocks = (len / 16) | 0;

  let h1 = seed | 0;
  let h2 = seed | 0;
  let h3 = seed | 0;
  let h4 = seed | 0;

  const c1 = 0x239b961b;
  const c2 = 0xab0e9789;
  const c3 = 0x38b34ae5;
  const c4 = 0xa1e38b93;

  for (let i = 0; i < nblocks; i++) {
    const base = i * 16;
    let k1 = readUInt32LE(data, base);
    let k2 = readUInt32LE(data, base + 4);
    let k3 = readUInt32LE(data, base + 8);
    let k4 = readUInt32LE(data, base + 12);

    k1 = Math.imul(k1, c1);
    k1 = rotl32(k1, 15);
    k1 = Math.imul(k1, c2);
    h1 ^= k1;
    h1 = rotl32(h1, 19);
    h1 = (h1 + h2) | 0;
    h1 = (Math.imul(h1, 5) + 0x561ccd1b) | 0;

    k2 = Math.imul(k2, c2);
    k2 = rotl32(k2, 16);
    k2 = Math.imul(k2, c3);
    h2 ^= k2;
    h2 = rotl32(h2, 17);
    h2 = (h2 + h3) | 0;
    h2 = (Math.imul(h2, 5) + 0x0bcaa747) | 0;

    k3 = Math.imul(k3, c3);
    k3 = rotl32(k3, 17);
    k3 = Math.imul(k3, c4);
    h3 ^= k3;
    h3 = rotl32(h3, 15);
    h3 = (h3 + h4) | 0;
    h3 = (Math.imul(h3, 5) + 0x96cd1c35) | 0;

    k4 = Math.imul(k4, c4);
    k4 = rotl32(k4, 18);
    k4 = Math.imul(k4, c1);
    h4 ^= k4;
    h4 = rotl32(h4, 13);
    h4 = (h4 + h1) | 0;
    h4 = (Math.imul(h4, 5) + 0x32ac3b17) | 0;
  }

  const tail = nblocks * 16;
  let k1 = 0,
    k2 = 0,
    k3 = 0,
    k4 = 0;
  switch (len & 15) {
    case 15:
      k4 ^= data[tail + 14] << 16; // falls through
    case 14:
      k4 ^= data[tail + 13] << 8; // falls through
    case 13:
      k4 ^= data[tail + 12];
      k4 = Math.imul(k4, c4);
      k4 = rotl32(k4, 18);
      k4 = Math.imul(k4, c1);
      h4 ^= k4;
    // falls through
    case 12:
      k3 ^= data[tail + 11] << 24; // falls through
    case 11:
      k3 ^= data[tail + 10] << 16; // falls through
    case 10:
      k3 ^= data[tail + 9] << 8; // falls through
    case 9:
      k3 ^= data[tail + 8];
      k3 = Math.imul(k3, c3);
      k3 = rotl32(k3, 17);
      k3 = Math.imul(k3, c4);
      h3 ^= k3;
    // falls through
    case 8:
      k2 ^= data[tail + 7] << 24; // falls through
    case 7:
      k2 ^= data[tail + 6] << 16; // falls through
    case 6:
      k2 ^= data[tail + 5] << 8; // falls through
    case 5:
      k2 ^= data[tail + 4];
      k2 = Math.imul(k2, c2);
      k2 = rotl32(k2, 16);
      k2 = Math.imul(k2, c3);
      h2 ^= k2;
    // falls through
    case 4:
      k1 ^= data[tail + 3] << 24; // falls through
    case 3:
      k1 ^= data[tail + 2] << 16; // falls through
    case 2:
      k1 ^= data[tail + 1] << 8; // falls through
    case 1:
      k1 ^= data[tail];
      k1 = Math.imul(k1, c1);
      k1 = rotl32(k1, 15);
      k1 = Math.imul(k1, c2);
      h1 ^= k1;
  }

  h1 ^= len;
  h2 ^= len;
  h3 ^= len;
  h4 ^= len;

  h1 = (h1 + h2) | 0;
  h1 = (h1 + h3) | 0;
  h1 = (h1 + h4) | 0;
  h2 = (h2 + h1) | 0;
  h3 = (h3 + h1) | 0;
  h4 = (h4 + h1) | 0;

  h1 = fmix32(h1);
  h2 = fmix32(h2);
  h3 = fmix32(h3);
  h4 = fmix32(h4);

  h1 = (h1 + h2) | 0;
  h1 = (h1 + h3) | 0;
  h1 = (h1 + h4) | 0;
  h2 = (h2 + h1) | 0;
  h3 = (h3 + h1) | 0;
  h4 = (h4 + h1) | 0;

  return [h1 >>> 0, h2 >>> 0, h3 >>> 0, h4 >>> 0];
}

/**
 * MurmurHash3 x86 128-bit, returning a 32-character zero-padded hex string.
 * @param key input string (hashed as UTF-8)
 * @param seed optional 32-bit seed (default 0)
 */
export function murmur128HexSync(key: string, seed = 0): string {
  return murmur128Sync(key, seed).map(toHex8).join('');
}
