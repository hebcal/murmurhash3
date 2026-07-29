# @hebcal/murmurhash3

Pure-JavaScript implementation of the [MurmurHash3](https://en.wikipedia.org/wiki/MurmurHash)
(x86) non-cryptographic hash by Austin Appleby, with TypeScript typings and no
native build step.

The output is **byte-for-byte identical** to the native
[`murmurhash3`](https://www.npmjs.com/package/murmurhash3) npm package
(`MurmurHash3_x86_32` / `MurmurHash3_x86_128`) for every input — including
non-ASCII strings, which are hashed as UTF-8 — so it is a drop-in replacement
that preserves previously computed hash values.

Because it is plain JavaScript, there is **no `node-gyp` / C++ compilation and no
`allowScripts` install step**. It works anywhere modern JavaScript runs.

## Install

```sh
npm install @hebcal/murmurhash3
```

## Usage

```js
import {
  murmur32Sync,
  murmur32HexSync,
  murmur128Sync,
  murmur128HexSync,
} from '@hebcal/murmurhash3';

murmur32Sync('Hello'); // 316307400
murmur32HexSync('Hello'); // '12da77c8'
murmur128Sync('Hello'); // [593538630, 1583560390, 2907026420, 2907026420]
murmur128HexSync('Hello'); // '2360ae465e6336c6ad45b3f4ad45b3f4'

// An optional 32-bit seed may be supplied (default 0):
murmur32HexSync('Hello', 0x9747b28c);
```

## API

All functions hash the UTF-8 encoding of `key` and accept an optional 32-bit
`seed` (default `0`).

| Function                       | Returns                                |
| ------------------------------ | -------------------------------------- |
| `murmur32Sync(key, seed?)`     | unsigned 32-bit integer (`number`)     |
| `murmur32HexSync(key, seed?)`  | 8-character zero-padded hex string     |
| `murmur128Sync(key, seed?)`    | array of four unsigned 32-bit integers |
| `murmur128HexSync(key, seed?)` | 32-character zero-padded hex string    |

Only the synchronous interface is provided. The native package's asynchronous
callback variants existed to offload work to a threadpool; for a pure-JS
computation that indirection has no benefit, so it is intentionally omitted.

## Compatibility

The `test/fixtures.json` file contains reference vectors captured directly from
the native `murmurhash3` package. The test suite asserts that this
implementation reproduces every one of them, locking byte-for-byte
compatibility across releases.

## License

BSD-2-Clause
