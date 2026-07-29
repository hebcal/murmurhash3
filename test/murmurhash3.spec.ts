import {expect, test, describe} from 'vitest';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {
  murmur32Sync,
  murmur32HexSync,
  murmur128Sync,
  murmur128HexSync,
} from '../src/murmurhash3';

type Fixture = {
  key: string;
  seed: number;
  m32: number;
  m32hex: string;
  m128: number[];
  m128hex: string;
};

const fixturesPath = fileURLToPath(new URL('./fixtures.json', import.meta.url));
const {cases} = JSON.parse(readFileSync(fixturesPath, 'utf8')) as {
  cases: Fixture[];
};

describe('byte-for-byte compatibility with native murmurhash3', () => {
  test(`fixture file has cases`, () => {
    expect(cases.length).toBeGreaterThan(500);
  });

  // One assertion block per fixture case: proves the pure-JS output equals the
  // frozen output captured from the native MurmurHash3_x86 implementation.
  for (const c of cases) {
    const label = `${JSON.stringify(c.key).slice(0, 24)} (len=${
      new TextEncoder().encode(c.key).length
    }, seed=${c.seed >>> 0})`;
    test(label, () => {
      expect(murmur32Sync(c.key, c.seed)).toBe(c.m32);
      expect(murmur32HexSync(c.key, c.seed)).toBe(c.m32hex);
      expect(murmur128Sync(c.key, c.seed)).toEqual(c.m128);
      expect(murmur128HexSync(c.key, c.seed)).toBe(c.m128hex);
    });
  }
});

describe('known reference vectors', () => {
  // From the upstream murmurhash3 test suite (seed 0).
  const vectors: Array<[string, number, number[]]> = [
    ['Hello', 0x12da77c8, [0x2360ae46, 0x5e6336c6, 0xad45b3f4, 0xad45b3f4]],
    ['Hello1', 0x6357e0a6, [0x8eb0cf41, 0x641b2401, 0xbc4c0dfc, 0xbc4c0dfc]],
    ['Hello2', 0xe5ce223e, [0xd3bcfc45, 0x66782162, 0x4beab2d1, 0x4beab2d1]],
    ['2', 0x0129e217, [0x9dd4f4e7, 0x3df769b3, 0x3df769b3, 0x3df769b3]],
    ['88', 0x7a0040a5, [0x28979fa9, 0x0b1b1a58, 0x0b1b1a58, 0x0b1b1a58]],
  ];
  for (const [key, h32, h128] of vectors) {
    test(key, () => {
      expect(murmur32Sync(key) >>> 0).toBe(h32 >>> 0);
      expect(murmur128Sync(key)).toEqual(h128.map(x => x >>> 0));
    });
  }
});

describe('edge cases', () => {
  test('empty string', () => {
    expect(murmur32HexSync('')).toBe('00000000');
    expect(murmur128HexSync('')).toBe('00000000000000000000000000000000');
    expect(murmur128Sync('')).toEqual([0, 0, 0, 0]);
  });

  test('seed defaults to 0', () => {
    expect(murmur32Sync('hebcal')).toBe(murmur32Sync('hebcal', 0));
    expect(murmur128Sync('hebcal')).toEqual(murmur128Sync('hebcal', 0));
  });

  test('hex forms are zero-padded to full width', () => {
    for (const c of cases) {
      expect(murmur32HexSync(c.key, c.seed)).toHaveLength(8);
      expect(murmur128HexSync(c.key, c.seed)).toHaveLength(32);
    }
  });

  test('32-bit results are unsigned', () => {
    for (const c of cases) {
      const v = murmur32Sync(c.key, c.seed);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThanOrEqual(0xffffffff);
      for (const w of murmur128Sync(c.key, c.seed)) {
        expect(w).toBeGreaterThanOrEqual(0);
        expect(w).toBeLessThanOrEqual(0xffffffff);
      }
    }
  });

  test('UTF-8 encoding: multibyte characters differ from their code points', () => {
    // Guards against a charCodeAt()-style implementation that is not UTF-8 safe.
    expect(murmur32HexSync('פרשת בראשית')).toBe('cf494c37');
    expect(murmur32HexSync('Rosh Chodesh Sh’vat')).toBe('71c0f82f');
  });
});
