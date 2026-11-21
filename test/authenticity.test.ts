import { describe, it, expect } from 'vitest';
import { SIGNATURES } from '../src/signatures/db.js';
import { normalizeHex } from '../src/core/scanner.js';
import { VERDICT_RULES } from '../src/inference/rules.js';
import { Category } from '../src/signatures/categories.js';
import type { SignatureEntry } from '../src/signatures/types.js';

/**
 * ============================================================================
 *  INDEPENDENT AUTHENTICITY VERIFICATION OF THE SIGNATURE DATABASE
 * ============================================================================
 *
 * The fixtures + manifest prove that db.ts matches scripts/gen-fixtures.mjs.
 * But a bug in the GENERATOR would pass those tests: db and fixtures would be
 * consistently wrong together. This file closes that hole by re-deriving
 * every constant a second time, HERE, from its published standard — using
 * different code (and where possible a different method) than the generator:
 *
 *   AES S-box        GF(2^8) inverse via generator-3 log/exp tables (FIPS 197)
 *   SHA-256 IV       fractional square roots of primes 2..19      (FIPS 180-4 §5.3.1)
 *   SHA-512 IV       fractional square roots, 64-bit words        (FIPS 180-4 §5.3.5)
 *   SHA-1 IV         published words                              (FIPS 180-4 §5.3.1)
 *   MD5 IV           published words                              (RFC 1321 §3.3)
 *   MD5 T-table      floor(2^32 * |sin(i)|)                       (RFC 1321 §3.4)
 *   TEA delta        fractional golden ratio                      (Wheeler & Needham 1994)
 *   DES S1 row 0     published table                              (FIPS 46-3 App. 1)
 *   ChaCha/Salsa     sigma strings                                (RFC 8439 §2.1)
 *   Blowfish P       published pi hex words                       (Blowfish spec App. A)
 *   CRC32 table      reflected polynomial 0xEDB88320              (IEEE 802.3)
 *   Base64(+url)     published alphabets                          (RFC 4648)
 *   secp256k1 G      published generator point                    (SEC 2 §2.4.1)
 *   SM4 FK/S-box     published constants                          (GB/T 32907-2016)
 *
 * If someone typos a byte in db.ts, `npm test` now fails HERE first.
 */

// ---------------------------------------------------------------------------
// Independent math helpers (deliberately not shared with gen-fixtures.mjs)
// ---------------------------------------------------------------------------
function isqrt(n: bigint): bigint {
  if (n < 2n) return n;
  let x = n;
  let y = (x + 1n) / 2n;
  while (y < x) {
    x = y;
    y = (x + n / x) / 2n;
  }
  return x;
}

/** First `bits` bits of the fractional part of sqrt(n), as a bigint. */
function fracSqrtBits(n: bigint, bits: number): bigint {
  // sqrt(n) * 2^bits = sqrt(n * 2^(2*bits)); floor, then keep low `bits` bits.
  return isqrt(n << BigInt(2 * bits)) & ((1n << BigInt(bits)) - 1n);
}

const PRIMES8 = [2, 3, 5, 7, 11, 13, 17, 19].map(BigInt);

/** Serialize 32-bit words big-endian / little-endian to hex. */
function wordsHexBE(words: bigint[] | number[], bits = 32): string {
  return words
    .map((w) => BigInt(w).toString(16).padStart(bits / 4, '0'))
    .join('');
}
function wordsHexLE(words: bigint[] | number[], bits = 32): string {
  return words
    .map((w) =>
      BigInt(w)
        .toString(16)
        .padStart(bits / 4, '0')
        .match(/../g)!
        .reverse()
        .join('')
    )
    .join('');
}

// --- AES S-box from first principles: log/exp tables over GF(2^8), poly 0x11b
function deriveAesSbox(): number[] {
  const exp = new Array<number>(255);
  const log = new Array<number>(256).fill(0);
  let x = 1;
  for (let i = 0; i < 255; i++) {
    exp[i] = x;
    log[x] = i;
    // multiply x by generator 3 in GF(2^8)
    let y = x ^ (x << 1); // x*3 = x*2 ^ x
    if (x & 0x80) y ^= 0x11b; // reduce by the AES polynomial
    x = y & 0xff;
  }
  const rotl = (b: number, n: number) => ((b << n) | (b >> (8 - n))) & 0xff;
  const sbox = new Array<number>(256);
  sbox[0] = 0x63;
  for (let i = 1; i < 256; i++) {
    const inv = exp[(255 - log[i]) % 255]; // multiplicative inverse
    sbox[i] = inv ^ rotl(inv, 1) ^ rotl(inv, 2) ^ rotl(inv, 3) ^ rotl(inv, 4) ^ 0x63;
  }
  return sbox;
}

// --- CRC32 reflected lookup table (the one zlib / zip embed)
function deriveCrc32Table(): number[] {
  const table = new Array<number>(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
}

// --- MD5 T constants: floor(2^32 * |sin(i)|), i = 1..8 (radians)
function deriveMd5T(count: number): number[] {
  const t: number[] = [];
  for (let i = 1; i <= count; i++) {
    t.push(Math.floor(Math.abs(Math.sin(i)) * 2 ** 32));
  }
  return t;
}

// ---------------------------------------------------------------------------
// The expected constants, derived / published above
// ---------------------------------------------------------------------------
const AES_SBOX = deriveAesSbox();
const AES_SBOX_INV = (() => {
  const inv = new Array<number>(256);
  for (let i = 0; i < 256; i++) inv[AES_SBOX[i]] = i;
  return inv;
})();

const SHA256_IV = PRIMES8.map((p) => fracSqrtBits(p, 32));
const SHA512_IV = PRIMES8.map((p) => fracSqrtBits(p, 64));
const SHA1_IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
const MD5_IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
const MD5_T8 = deriveMd5T(8);
const TEA_DELTA = Math.floor(((Math.sqrt(5) - 1) / 2) * 2 ** 32); // 0x9E3779B9
const DES_S1_ROW0 = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7];
const CHACHA_SIGMA = Buffer.from('expand 32-byte k', 'latin1');
const SALSA_SIGMA = Buffer.from('expand 16-byte k', 'latin1');
const BLOWFISH_P9 = [
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
  0x082efa98, 0xec4e6c89
];
const CRC32_TABLE = deriveCrc32Table();
const BASE64_ALPHABET = Buffer.from(
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
  'latin1'
);
const BASE64URL_ALPHABET = Buffer.from(
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
  'latin1'
);
const SECP256K1_G = Buffer.concat([
  Buffer.from('04', 'hex'),
  Buffer.from(
    '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',
    'hex'
  ),
  Buffer.from(
    '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8',
    'hex'
  )
]);
const SM4_FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];
const SM4_SBOX16 = Buffer.from('d690e9fecce13db716b614c228fb2c05', 'hex');

/**
 * id -> expected pattern bytes, exactly as they must appear in db.ts.
 * Single-pattern entries: the raw bytes. Word-table entries: [BE, LE].
 */
const EXPECTED: Record<string, string[]> = {
  'aes-sbox': [Buffer.from(AES_SBOX).toString('hex')],
  'aes-sbox-inverse': [Buffer.from(AES_SBOX_INV).toString('hex')],
  'sha256-iv': [wordsHexBE(SHA256_IV), wordsHexLE(SHA256_IV)],
  'sha512-iv': [wordsHexBE(SHA512_IV, 64), wordsHexLE(SHA512_IV, 64)],
  'sha1-iv': [wordsHexBE(SHA1_IV), wordsHexLE(SHA1_IV)],
  'md5-iv': [wordsHexBE(MD5_IV), wordsHexLE(MD5_IV)],
  'md5-t-table': [wordsHexBE(MD5_T8), wordsHexLE(MD5_T8)],
  'tea-delta': [
    wordsHexBE([TEA_DELTA]),
    wordsHexLE([TEA_DELTA])
  ],
  'des-sbox': [Buffer.from(DES_S1_ROW0).toString('hex')],
  'chacha-sigma': [CHACHA_SIGMA.toString('hex')],
  'salsa-sigma': [SALSA_SIGMA.toString('hex')],
  'blowfish-p-array': [wordsHexBE(BLOWFISH_P9), wordsHexLE(BLOWFISH_P9)],
  'crc32-table': [
    wordsHexBE(CRC32_TABLE.slice(1, 17)),
    wordsHexLE(CRC32_TABLE.slice(1, 17))
  ],
  'base64-alphabet': [BASE64_ALPHABET.toString('hex')],
  'base64url-alphabet': [BASE64URL_ALPHABET.toString('hex')],
  'secp256k1-generator': [SECP256K1_G.toString('hex')],
  'sm4-fk': [wordsHexBE(SM4_FK), wordsHexLE(SM4_FK)],
  'sm4-sbox': [SM4_SBOX16.toString('hex')]
};

// Sanity anchors for the derived values themselves (double-locking: if the
// derivation above is broken, these well-known published values catch it).
describe('derivation sanity anchors', () => {
  it('AES S-box anchors (FIPS 197): sbox[0]=0x63, sbox[1]=0x7c, inv[0]=0x52', () => {
    expect(AES_SBOX[0]).toBe(0x63);
    expect(AES_SBOX[1]).toBe(0x7c);
    expect(AES_SBOX[255]).toBe(0x16);
    expect(AES_SBOX_INV[0]).toBe(0x52);
  });

  it('SHA-256 IV anchor: h0 = 0x6a09e667 (fractional sqrt of 2)', () => {
    expect(SHA256_IV[0]).toBe(0x6a09e667n);
    expect(SHA512_IV[0]).toBe(0x6a09e667f3bcc908n);
  });

  it('secp256k1 generator point satisfies y^2 = x^3 + 7 (mod p)', () => {
    // p = 2^256 - 2^32 - 977, the secp256k1 field prime (SEC 2 §2.4.1)
    const p = (1n << 256n) - (1n << 32n) - 977n;
    const Gx = BigInt('0x' + SECP256K1_G.subarray(1, 33).toString('hex'));
    const Gy = BigInt('0x' + SECP256K1_G.subarray(33, 65).toString('hex'));
    expect((Gy * Gy - Gx * Gx * Gx - 7n) % p).toBe(0n);
    expect(Gx.toString(16)).toBe(
      '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    );
  });

  it('MD5 T-table anchors (RFC 1321): T[1]=0xd76aa478, T[2]=0xe8c7b756', () => {
    expect(MD5_T8[0]).toBe(0xd76aa478);
    expect(MD5_T8[1]).toBe(0xe8c7b756);
    expect(MD5_T8[2]).toBe(0x242070db);
    expect(MD5_T8[3]).toBe(0xc1bdceee);
  });

  it('TEA delta anchor: 0x9E3779B9', () => {
    expect(TEA_DELTA).toBe(0x9e3779b9);
  });

  it('CRC32 table anchors: entry[1]=0x77073096, entry[2]=0xEE0E612C', () => {
    expect(CRC32_TABLE[1]).toBe(0x77073096);
    expect(CRC32_TABLE[2]).toBe(0xee0e612c);
  });
});

describe('signature database authenticity (db.ts vs published standards)', () => {
  const byId = new Map(SIGNATURES.map((s) => [s.id, s]));

  it('every database id has an independent expected value in this file', () => {
    const missing = SIGNATURES.filter((s) => !EXPECTED[s.id]).map((s) => s.id);
    expect(missing, `signatures lacking independent verification: ${missing}`).toEqual([]);
    const extra = Object.keys(EXPECTED).filter((id) => !byId.has(id));
    expect(extra, `stale expectations for removed signatures: ${extra}`).toEqual([]);
  });

  for (const sig of SIGNATURES) {
    it(`${sig.id}: patterns match the standard-derived bytes (both byte orders)`, () => {
      const expected = EXPECTED[sig.id];
      expect(sig.patterns.length).toBe(expected.length);
      for (let i = 0; i < expected.length; i++) {
        expect(
          normalizeHex(sig.patterns[i]),
          `${sig.id} pattern[${i}] differs from independently derived bytes`
        ).toBe(expected[i]);
      }
    });
  }

  it('SHA-512 IV is square-root derived — first 32 bits equal SHA-256 h0', () => {
    const sha512Words = SHA512_IV;
    expect(sha512Words[0] >> 32n).toBe(BigInt(SHA256_IV[0]));
    expect(wordsHexBE(SHA512_IV, 64)).toBe(
      '6a09e667f3bcc908bb67ae8584caa73b3c6ef372fe94f82ba54ff53a5f1d36f1' +
        '510e527fade682d19b05688c2b3e6c1f1f83d9abfb41bd6b5be0cd19137e2179'
    );
  });
});

describe('signature database structural integrity', () => {
  it('ids are unique and kebab-case', () => {
    const ids = SIGNATURES.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(id).toMatch(/^[a-z0-9]+(-[a-z0-9]+)*$/);
  });

  it('patterns are valid non-trivial hex and match the declared length', () => {
    for (const sig of SIGNATURES) {
      for (const raw of sig.patterns) {
        const hex = normalizeHex(raw);
        expect(hex).toMatch(/^[0-9a-f]+$/);
        expect(hex.length % 2).toBe(0);
        expect(hex.length / 2).toBeGreaterThanOrEqual(4);
      }
      const primary = Buffer.from(normalizeHex(sig.patterns[0]), 'hex');
      expect(primary.length, `${sig.id} lengthBytes vs pattern[0]`).toBe(sig.lengthBytes);
    }
  });

  it('categories are from the known enum', () => {
    const valid = new Set(Object.values(Category));
    for (const sig of SIGNATURES) expect(valid.has(sig.category)).toBe(true);
  });

  it('occludedBy references an existing signature id', () => {
    const ids = new Set(SIGNATURES.map((s) => s.id));
    for (const sig of SIGNATURES) {
      if (sig.occludedBy) expect(ids.has(sig.occludedBy), `${sig.id}.occludedBy`).toBe(true);
    }
  });

  it('every signature id referenced by a verdict rule exists', () => {
    const ids = new Set(SIGNATURES.map((s) => s.id));
    for (const rule of VERDICT_RULES) {
      for (const term of [...(rule.requiresAny ?? []), ...(rule.requiresAll ?? []), ...(rule.forbidsAny ?? [])]) {
        if (term.startsWith('category:')) continue;
        expect(ids.has(term), `rule ${rule.id} references unknown signature ${term}`).toBe(true);
      }
    }
  });

  it('the fixture manifest covers exactly the database (no orphan fixtures)', () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const manifest = JSON.parse(
      require('node:fs').readFileSync('test/fixtures/manifest.json', 'utf8')
    ) as Record<string, unknown>;
    const ids = new Set(SIGNATURES.map((s) => s.id));
    expect(new Set(Object.keys(manifest))).toEqual(ids);
  });
});
