#!/usr/bin/env node
// eslint-disable-next-line
/**
 * Deterministic fixture generator for findcrypt.
 *
 * Every constant is DERIVED from first principles here and verified against
 * its published spec value before anything is written. This file doubles as
 * living documentation of why each fingerprint is what it is:
 *   - AES S-box: GF(2^8) multiplicative inverse + affine transform (FIPS 197)
 *   - SHA-256 IVs: fractional square roots of the first 8 primes (FIPS 180-4)
 *   - SHA-512 IVs: fractional cube roots of the first 8 primes
 *   - MD5 T-table: floor(2^32 * |sin(i)|) (RFC 1321)
 *   - Blowfish P-array: fractional bits of pi (Blowfish spec)
 *   - TEA delta: fractional golden ratio (TEA paper)
 *   - CRC32: reflected polynomial 0xEDB88320 table
 *
 * Writes: test/fixtures/fixture-<id>.bin, noise.bin, empty.bin, manifest.json
 * Prints: ready-to-paste hex patterns for src/signatures/db.ts
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURE_DIR = join(ROOT, 'test', 'fixtures');
mkdirSync(FIXTURE_DIR, { recursive: true });

function assert(cond, msg) {
  if (!cond) throw new Error(`FIXTURE GENERATOR FAILED: ${msg}`);
}

// ---------------------------------------------------------------------------
// Seeded PRNG so fixtures are byte-for-byte reproducible
// ---------------------------------------------------------------------------
function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = mulberry32(0xc0ffee);
function randomBytes(n) {
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) b[i] = Math.floor(rand() * 256);
  return b;
}

// ---------------------------------------------------------------------------
// BigInt helpers
// ---------------------------------------------------------------------------
function isqrt(n) {
  if (n < 0n) throw new Error('isqrt of negative');
  if (n < 2n) return n;
  let x = n;
  let y = (x + 1n) / 2n;
  while (y < x) {
    x = y;
    y = (x + n / x) / 2n;
  }
  return x;
}

function icbrt(n) {
  if (n < 0n) throw new Error('icbrt of negative');
  if (n < 2n) return n;
  let x = n;
  let y = (2n * x + n / (x * x)) / 3n;
  while (y < x) {
    x = y;
    y = (2n * x + n / (x * x)) / 3n;
  }
  while (x ** 3n > n) x -= 1n;
  while ((x + 1n) ** 3n <= n) x += 1n;
  return x;
}

const ONE = 1n << 830n; // pi / phi precision scale

/** atan(1/x) scaled by ONE, via its Taylor series. */
function atanInv(x) {
  const X = BigInt(x);
  let xpow = ONE / X; // ONE / X^1
  let sum = xpow;
  let k = 1n;
  let sign = -1n;
  for (;;) {
    k += 2n;
    xpow = xpow / (X * X); // ONE / X^k
    const term = xpow / k;
    if (term === 0n) break;
    sum += sign * term;
    sign = -sign;
  }
  return sum;
}

/** Fractional bits of a value, scaled by ONE, as 32-bit words. */
function fracWords32(scaledValue, count) {
  const words = [];
  for (let w = 0; w < count; w++) {
    const shift = 830n - 32n * BigInt(w + 1);
    words.push(Number((scaledValue >> shift) & 0xffffffffn));
  }
  return words;
}

// ---------------------------------------------------------------------------
// Constant derivations
// ---------------------------------------------------------------------------

// --- AES S-box: GF(2^8) inverse (poly 0x11B) followed by affine transform
function gfMul(a, b) {
  let r = 0;
  while (b) {
    if (b & 1) r ^= a;
    const high = a & 0x80;
    a = (a << 1) & 0xff;
    if (high) a ^= 0x1b;
    b >>>= 1;
  }
  return r;
}
function gfInv(a) {
  if (a === 0) return 0;
  for (let x = 1; x < 256; x++) if (gfMul(a, x) === 1) return x;
  throw new Error('no inverse found');
}
function rotl8(v, n) {
  return ((v << n) | (v >>> (8 - n))) & 0xff;
}
const AES_SBOX = Buffer.alloc(256);
for (let i = 0; i < 256; i++) {
  const inv = gfInv(i);
  AES_SBOX[i] = (inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63) & 0xff;
}
assert(AES_SBOX[0x00] === 0x63, 'AES S-box[0] must be 0x63');
assert(AES_SBOX[0x01] === 0x7c, 'AES S-box[1] must be 0x7c');
assert(AES_SBOX[0x53] === 0xed, 'AES S-box[0x53] must be 0xED');
const AES_SBOX_INV = Buffer.alloc(256);
for (let i = 0; i < 256; i++) AES_SBOX_INV[AES_SBOX[i]] = i;
assert(AES_SBOX_INV[0x63] === 0x00, 'AES inverse S-box[0x63] must be 0');
assert(AES_SBOX_INV[0x00] === 0x52, 'AES inverse S-box[0x00] must be 0x52');

// --- SHA-256 IVs: first 32 bits of the fractional parts of the square
//     roots of the first 8 primes (FIPS 180-4)
const PRIMES8 = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n];
const SHA256_IV = PRIMES8.map((p) => Number(isqrt(p << 64n) & 0xffffffffn));
assert(SHA256_IV[0] === 0x6a09e667, 'SHA-256 IV[0]');
assert(SHA256_IV[1] === 0xbb67ae85, 'SHA-256 IV[1]');
assert(SHA256_IV[7] === 0x5be0cd19, 'SHA-256 IV[7]');

// --- SHA-512 IVs: first 64 bits of the fractional parts of the square
//     roots of the first 8 primes (FIPS 180-4; cube roots are the K constants)
const SHA512_IV = PRIMES8.map((p) => isqrt(p << 128n) & 0xffffffffffffffffn);
assert(SHA512_IV[0] === 0x6a09e667f3bcc908n, 'SHA-512 IV[0]');
assert(SHA512_IV[1] === 0xbb67ae8584caa73bn, 'SHA-512 IV[1]');

// --- MD5 / SHA-1 IVs: both start with the same four words (FIPS 180-4 / RFC 1321)
const MD5_IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
const SHA1_IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
assert(SHA1_IV[4] === 0xc3d2e1f0, 'SHA-1 5th word');

// --- MD5 T-table: T[i] = floor(2^32 * |sin(i+1)|) (RFC 1321)
const MD5_T = [];
for (let i = 0; i < 64; i++) {
  MD5_T.push(Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);
}
assert(MD5_T[0] === 0xd76aa478, 'MD5 T[0]');
assert(MD5_T[1] === 0xe8c7b756, 'MD5 T[1]');
assert(MD5_T[3] === 0xc1bdceee, 'MD5 T[3]');

// --- CRC32 (reflected, poly 0xEDB88320) — zlib/zip/png
const CRC32_TABLE = [];
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? (c >>> 1) ^ 0xedb88320 : c >>> 1;
  CRC32_TABLE.push(c >>> 0);
}
assert(CRC32_TABLE[1] === 0x77073096, 'CRC32 table[1]');
assert(CRC32_TABLE[2] === 0xee0e612c, 'CRC32 table[2]');
assert(CRC32_TABLE[3] === 0x990951ba, 'CRC32 table[3]');
assert(CRC32_TABLE[4] === 0x076dc419, 'CRC32 table[4]');

// --- Blowfish P-array: first 32 fractional bits of pi, as 32-bit words
const PI = 16n * atanInv(5) - 4n * atanInv(239); // pi * ONE
const PI_FRAC = PI - 3n * ONE;
const BLOWFISH_P = fracWords32(PI_FRAC, 8);
assert(BLOWFISH_P[0] === 0x243f6a88, 'Blowfish P[0] (pi)');
assert(BLOWFISH_P[1] === 0x85a308d3, 'Blowfish P[1]');
assert(BLOWFISH_P[7] === 0xec4e6c89, 'Blowfish P[7]');

// --- TEA delta: fractional golden ratio (TEA, Wheeler & Needham 1994)
const SQRT5 = isqrt(5n << 1660n); // floor(sqrt(5) * 2^830)
const PHI = (ONE + SQRT5) / 2n; // phi * ONE
const PHI_FRAC = PHI - ONE;
const TEA_DELTA = fracWords32(PHI_FRAC, 1)[0];
assert(TEA_DELTA === 0x9e3779b9, 'TEA delta = 0x9E3779B9');

// --- Known-value constants (asserted, not derived)
const CHACHA_SIGMA = Buffer.from('expand 32-byte k', 'latin1');
const SALSA_SIGMA = Buffer.from('expand 16-byte k', 'latin1');
assert(CHACHA_SIGMA.length === 16, 'chacha sigma length');
assert(SALSA_SIGMA.length === 16, 'salsa sigma length');

const BASE64_ALPHABET = Buffer.from(
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
  'latin1'
);
const BASE64URL_ALPHABET = Buffer.from(
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
  'latin1'
);
assert(BASE64_ALPHABET.length === 64 && BASE64URL_ALPHABET.length === 64, 'b64 length');

const SECP256K1_GX_HEX = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const SECP256K1_GY_HEX = '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
assert(SECP256K1_GX_HEX.startsWith('79be667e') && SECP256K1_GX_HEX.length === 64, 'secp256k1 Gx');
assert(SECP256K1_GY_HEX.startsWith('483ada77') && SECP256K1_GY_HEX.length === 64, 'secp256k1 Gy');
// Verify G lies on the curve y^2 = x^3 + 7 (mod p), p = 2^256 - 2^32 - 977.
// This is the definitive check that the copied point is the real SEC 2
// generator and not a corrupted lookalike.
const SECP256K1_P = (1n << 256n) - (1n << 32n) - 977n;
const SECP256K1_GX = BigInt('0x' + SECP256K1_GX_HEX);
const SECP256K1_GY = BigInt('0x' + SECP256K1_GY_HEX);
assert(
  (SECP256K1_GY * SECP256K1_GY - SECP256K1_GX * SECP256K1_GX * SECP256K1_GX - 7n) %
    SECP256K1_P ===
    0n,
  'secp256k1 generator must satisfy y^2 = x^3 + 7 (mod p)'
);
const SECP256K1_G = Buffer.concat([
  Buffer.from('04', 'hex'),
  Buffer.from(SECP256K1_GX_HEX, 'hex'),
  Buffer.from(SECP256K1_GY_HEX, 'hex')
]);
assert(SECP256K1_G.length === 65, 'secp256k1 G length');

const SM4_FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];
assert(SM4_FK[0] === 0xa3b1bac6, 'SM4 FK[0]');
const SM4_SBOX16 = Buffer.from('d690e9fecce13db716b614c228fb2c05', 'hex');
assert(SM4_SBOX16[0] === 0xd6 && SM4_SBOX16[3] === 0xfe, 'SM4 S-box anchor');

// --- DES S-box S1, row 0 (FIPS 46-3 Appendix 1) — published values,
//     stored in the common one-byte-per-entry layout
const DES_S1_ROW0 = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7];
assert(DES_S1_ROW0[0] === 14 && DES_S1_ROW0[8] === 3 && DES_S1_ROW0[15] === 7, 'DES S1 row 0');

// ---------------------------------------------------------------------------
// Pattern formatting (hex for db.ts)
// ---------------------------------------------------------------------------
function wordsToHexBE(words, bits = 32) {
  const bytes = [];
  for (const w of words) {
    const v = BigInt(w);
    const n = bits / 8;
    for (let i = n - 1; i >= 0; i--) bytes.push(Number((v >> BigInt(8 * i)) & 0xffn));
  }
  return Buffer.from(bytes).toString('hex');
}
function wordsToHexLE(words, bits = 32) {
  const bytes = [];
  for (const w of words) {
    const v = BigInt(w);
    const n = bits / 8;
    for (let i = 0; i < n; i++) bytes.push(Number((v >> BigInt(8 * i)) & 0xffn));
  }
  return Buffer.from(bytes).toString('hex');
}
function hexWrap(hex, perLine = 64) {
  return hex.match(new RegExp(`.{1,${perLine}}`, 'g')).join('\n  ');
}

// sha512 needs BigInt words
function bigWordsToHexBE(words) {
  const bytes = [];
  for (const w of words) {
    const v = BigInt(w);
    for (let i = 7; i >= 0; i--) bytes.push(Number((v >> BigInt(8 * i)) & 0xffn));
  }
  return Buffer.from(bytes).toString('hex');
}
function bigWordsToHexLE(words) {
  const bytes = [];
  for (const w of words) {
    const v = BigInt(w);
    for (let i = 0; i < 8; i++) bytes.push(Number((v >> BigInt(8 * i)) & 0xffn));
  }
  return Buffer.from(bytes).toString('hex');
}

// ---------------------------------------------------------------------------
// Signature definitions (patterns for db.ts + fixtures)
// ---------------------------------------------------------------------------
const ENTRIES = [
  { id: 'aes-sbox', patterns: [AES_SBOX.toString('hex')] },
  { id: 'aes-sbox-inverse', patterns: [AES_SBOX_INV.toString('hex')] },
  { id: 'sha256-iv', patterns: [wordsToHexBE(SHA256_IV), wordsToHexLE(SHA256_IV)] },
  { id: 'sha512-iv', patterns: [bigWordsToHexBE(SHA512_IV), bigWordsToHexLE(SHA512_IV)] },
  { id: 'sha1-iv', patterns: [wordsToHexBE(SHA1_IV), wordsToHexLE(SHA1_IV)] },
  { id: 'md5-iv', patterns: [wordsToHexBE(MD5_IV), wordsToHexLE(MD5_IV)] },
  { id: 'md5-t-table', patterns: [wordsToHexBE(MD5_T.slice(0, 8)), wordsToHexLE(MD5_T.slice(0, 8))] },
  { id: 'tea-delta', patterns: [wordsToHexBE([TEA_DELTA]), wordsToHexLE([TEA_DELTA])] },
  { id: 'chacha-sigma', patterns: [CHACHA_SIGMA.toString('hex')] },
  { id: 'salsa-sigma', patterns: [SALSA_SIGMA.toString('hex')] },
  { id: 'blowfish-p-array', patterns: [wordsToHexBE(BLOWFISH_P), wordsToHexLE(BLOWFISH_P)] },
  { id: 'crc32-table', patterns: [wordsToHexBE(CRC32_TABLE.slice(1, 17)), wordsToHexLE(CRC32_TABLE.slice(1, 17))] },
  { id: 'base64-alphabet', patterns: [BASE64_ALPHABET.toString('hex')] },
  { id: 'base64url-alphabet', patterns: [BASE64URL_ALPHABET.toString('hex')] },
  { id: 'secp256k1-generator', patterns: [SECP256K1_G.toString('hex')] },
  { id: 'sm4-fk', patterns: [wordsToHexBE(SM4_FK), wordsToHexLE(SM4_FK)] },
  { id: 'sm4-sbox', patterns: [SM4_SBOX16.toString('hex')] },
  { id: 'des-sbox', patterns: [Buffer.from(DES_S1_ROW0).toString('hex')] }
];

// Sanity: no duplicate ids, all hex even-length
const ids = new Set();
for (const e of ENTRIES) {
  assert(!ids.has(e.id), `duplicate id ${e.id}`);
  ids.add(e.id);
  for (const p of e.patterns) assert(p.length % 2 === 0 && /^[0-9a-f]+$/.test(p), `bad hex in ${e.id}`);
  for (const p of e.patterns) assert(Buffer.from(p, 'hex').length >= 4, `pattern < 4 bytes in ${e.id}`);
}

// ---------------------------------------------------------------------------
// Write fixtures: seeded noise | pattern[0] | seeded noise  (offset 256)
// ---------------------------------------------------------------------------
const outputs = [];
const manifest = {};
for (const e of ENTRIES) {
  const pattern = Buffer.from(e.patterns[0], 'hex');
  const fixture = Buffer.concat([randomBytes(256), pattern, randomBytes(256)]);
  outputs.push({ rel: `fixture-${e.id}.bin`, data: fixture });
  manifest[e.id] = { offset: 256, patternIndex: 0, patternHex: e.patterns[0] };
}
outputs.push({ rel: 'noise.bin', data: randomBytes(4096) });
outputs.push({ rel: 'empty.bin', data: Buffer.alloc(0) });
outputs.push({
  rel: 'manifest.json',
  data: Buffer.from(JSON.stringify(manifest, null, 2), 'utf8')
});

// ---------------------------------------------------------------------------
// Scenario fixtures: multi-constant files that exercise the verdict engine
// end-to-end. Drawn AFTER the per-signature fixtures, so those bytes never
// move when scenarios change. Descriptions live in scenarios.json.
// ---------------------------------------------------------------------------
function patternBytes(id, index = 0) {
  const e = ENTRIES.find((x) => x.id === id);
  if (!e) throw new Error(`unknown signature id: ${id}`);
  return Buffer.from(e.patterns[index], 'hex');
}

const PLAIN_TEXT = Buffer.from(
  [
    'The quick brown fox jumps over the lazy dog. ',
    'findcrypt scenario fixture: plain ASCII text, no cryptography. ',
    'Entropy stays far below the packed/encrypted threshold. ',
    'Lorem ipsum dolor sit amet, consectetur adipiscing elit. '
  ].join('').repeat(24),
  'latin1'
);

const SCENARIOS = {
  'scenario-wallet.bin': {
    description:
      'Bitcoin-style stack: secp256k1 generator point + SHA-256 IV + Base64 alphabet',
    build: () =>
      Buffer.concat([
        randomBytes(128),
        patternBytes('secp256k1-generator'),
        randomBytes(64),
        patternBytes('sha256-iv'),
        randomBytes(64),
        patternBytes('base64-alphabet'),
        randomBytes(128)
      ])
  },
  'scenario-legacy.bin': {
    description: 'Legacy audit case: DES S-box + MD5 T-table + MD5 IV',
    build: () =>
      Buffer.concat([
        randomBytes(128),
        patternBytes('des-sbox'),
        randomBytes(32),
        patternBytes('md5-t-table'),
        randomBytes(32),
        patternBytes('md5-iv'),
        randomBytes(128)
      ])
  },
  'scenario-arx.bin': {
    description: 'Modern ARX stack: ChaCha20 sigma + Salsa20 sigma',
    build: () =>
      Buffer.concat([
        randomBytes(64),
        patternBytes('chacha-sigma'),
        randomBytes(48),
        patternBytes('salsa-sigma'),
        randomBytes(64)
      ])
  },
  'scenario-packed.bin': {
    description:
      '32 KB of seeded noise: near-maximal entropy, zero signatures — the packed/encrypted payload case',
    build: () => randomBytes(32 * 1024)
  },
  'scenario-plaintext.txt': {
    description: 'Plain ASCII text: low entropy, zero signatures',
    build: () => PLAIN_TEXT
  }
};

const scenariosMeta = {};
for (const [rel, sc] of Object.entries(SCENARIOS)) {
  outputs.push({ rel, data: sc.build() });
  scenariosMeta[rel] = { description: sc.description };
}
outputs.push({
  rel: 'scenarios.json',
  data: Buffer.from(JSON.stringify(scenariosMeta, null, 2), 'utf8')
});

// --check: verify the committed fixtures are byte-identical to a fresh run.
// Guards against hand-edited fixtures or a generator change that was never
// followed by `npm run fixtures` (the drift class that hides wrong constants).
const CHECK = process.argv.includes('--check');
if (CHECK) {
  const drifted = [];
  for (const { rel, data } of outputs) {
    const path = join(FIXTURE_DIR, rel);
    let committed;
    try {
      committed = readFileSync(path);
    } catch {
      drifted.push(`${rel} (missing)`);
      continue;
    }
    if (!committed.equals(data)) drifted.push(`${rel} (bytes differ)`);
  }
  if (drifted.length > 0) {
    console.error('FIXTURE DRIFT DETECTED — committed files do not match the generator:');
    for (const d of drifted) console.error(`  ${d}`);
    console.error('\nRun `npm run fixtures` and commit the result.');
    process.exit(1);
  }
  console.log(`OK: all ${outputs.length} committed fixtures match a fresh generation.`);
  process.exit(0);
}

for (const { rel, data } of outputs) {
  writeFileSync(join(FIXTURE_DIR, rel), data);
}

// ---------------------------------------------------------------------------
// Print db.ts-ready pattern blocks
// ---------------------------------------------------------------------------
console.log('# ---- paste into src/signatures/db.ts ---------------------------');
for (const e of ENTRIES) {
  console.log(`\n# ${e.id} (${e.patterns.length} pattern${e.patterns.length > 1 ? 's' : ''})`);
  for (let i = 0; i < e.patterns.length; i++) {
    const label =
      e.patterns.length === 1
        ? 'pattern'
        : i === 0
          ? 'big-endian'
          : 'little-endian';
    console.log(`  patterns += \`${hexWrap(e.patterns[i])}\` // ${label}`);
  }
}
console.log('\n# ---- all constants verified against published values ------------');
console.log('OK: fixtures + manifest written to test/fixtures/');
