import { Category } from './categories.js';
import type { SignatureEntry } from './types.js';

/**
 * ============================================================================
 *  findcrypt SIGNATURE DATABASE v1
 * ============================================================================
 *
 *  This file is pure DATA — no logic. Adding a signature means:
 *    1. add an object below (get the constant's bytes from its standard),
 *    2. run `npm run fixtures` to plant it in a fixture binary,
 *    3. extend the expected-entry list in test/scanner.test.ts,
 *    4. `npm test` — the suite verifies every pattern against its fixture.
 *
 *  Word-table signatures carry BOTH byte orders: real binaries store these
 *  tables in native endianness (usually little-endian on x86/ARM), but
 *  big-endian builds and network-order constants exist in the wild.
 *
 *  Every constant was derived from first principles and verified against its
 *  published spec value — see scripts/gen-fixtures.mjs for the derivations
 *  (GF(2^8) inversion for AES, BigInt square roots for SHA-2 IVs, Machin's
 *  formula for the pi-derived Blowfish tables, the golden ratio for TEA).
 * ============================================================================
 */
export const SIGNATURES: readonly SignatureEntry[] = [
  {
    id: 'aes-sbox',
    name: 'AES S-Box',
    algorithm: 'AES',
    category: Category.SYMMETRIC,
    patterns: [
      '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0' +
      'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275' +
      '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf' +
      'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2' +
      'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb' +
      'e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08' +
      'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e' +
      'e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16'
    ],
    lengthBytes: 256,
    description:
      'Software AES implementation present (FIPS 197). Note: AES-NI builds carry no S-box.',
    story:
      'The S-box is the multiplicative inverse in GF(2^8) under an affine transform — every byte maps to its field inverse. Table-driven implementations embed all 256 bytes verbatim, making AES the easiest cipher to spot in a binary.',
    source: 'FIPS 197 §5.1.1',
    aliases: ['Rijndael S-box']
  },
  {
    id: 'aes-sbox-inverse',
    name: 'AES Inverse S-Box',
    algorithm: 'AES',
    category: Category.SYMMETRIC,
    patterns: [
      '52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb' +
      '547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd125' +
      '72f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d84' +
      '90d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b' +
      '3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e' +
      '47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af4' +
      '1fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cef' +
      'a0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d'
    ],
    lengthBytes: 256,
    description:
      'AES decryption support: the codebase encrypts AND decrypts — full AES, not just a hash of it.',
    story:
      'Decryption runs the cipher backwards, which requires the inverse substitution table. Finding both boxes side by side (they are usually adjacent in .rodata) is the classic signature of a complete AES implementation.',
    source: 'FIPS 197 §5.3.2',
    aliases: ['AES decryption table']
  },
  {
    id: 'sha256-iv',
    name: 'SHA-256 Initial Hash Values',
    algorithm: 'SHA-256',
    category: Category.HASH,
    patterns: [
      '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19',
      '67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b'
    ],
    lengthBytes: 32,
    wordSizeBytes: 4,
    description:
      'Modern hashing present: certificates, HMAC, key derivation, Bitcoin.',
    story:
      "SHA-2's initial state is the first 32 bits of the fractional parts of the square roots of the first eight primes (2, 3, 5, 7, 11, 13, 17, 19) — deliberate nothing-up-my-sleeve numbers so nobody could hide a weakness in the constants.",
    source: 'FIPS 180-4 §5.3.1',
    aliases: ['SHA-2 IVs']
  },
  {
    id: 'sha512-iv',
    name: 'SHA-512 Initial Hash Values',
    algorithm: 'SHA-512',
    category: Category.HASH,
    patterns: [
      '6a09e667f3bcc908bb67ae8584caa73b3c6ef372fe94f82ba54ff53a5f1d36f1' +
      '510e527fade682d19b05688c2b3e6c1f1f83d9abfb41bd6b5be0cd19137e2179',
      '08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5' +
      'd182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b'
    ],
    lengthBytes: 64,
    wordSizeBytes: 8,
    description: '64-bit SHA-2 variant present — high-security or 64-bit-optimized hashing.',
    story:
      'Same construction as SHA-256 but with 64 fractional bits from the square roots of the same eight primes. Notice the first 8 hex digits match SHA-256 — both begin with the square root of 2.',
    source: 'FIPS 180-4 §5.3.5',
    aliases: ['SHA-2 IVs (64-bit)']
  },
  {
    id: 'sha1-iv',
    name: 'SHA-1 Initial Hash Values',
    algorithm: 'SHA-1',
    category: Category.HASH,
    patterns: [
      '67452301efcdab8998badcfe10325476c3d2e1f0',
      '0123456789abcdeffedcba9876543210f0e1d2c3'
    ],
    lengthBytes: 20,
    wordSizeBytes: 4,
    description:
      'SHA-1 present — cryptographically broken (collisions since 2017); an audit finding in modern software.',
    story:
      "The first four words are the classic 0x67452301 sequence (from MD4/MD5 heritage); the fifth word 0xC3D2E1F0 is what distinguishes SHA-1's 160-bit state. These four-plus-one words are the single most famous constant block in cryptography.",
    source: 'RFC 3174 / FIPS 180-4 §5.3.1',
    occludedBy: undefined,
    aliases: []
  },
  {
    id: 'md5-iv',
    name: 'MD5 Initial Hash Values',
    algorithm: 'MD5',
    category: Category.HASH,
    patterns: [
      '67452301efcdab8998badcfe10325476',
      '0123456789abcdeffedcba9876543210'
    ],
    lengthBytes: 16,
    wordSizeBytes: 4,
    description:
      'MD5 present — broken for 30 years; legacy code, malware integrity checks, or fake-prng misuse.',
    story:
      "A = 0x67452301 counts in nibbles: 67 45 23 01. MD5 shares its first four words with SHA-1, so this engine disambiguates: when SHA-1's longer 20-byte pattern matches at the same offset, this 16-byte hit is a prefix re-detection and is dropped.",
    source: 'RFC 1321 §3.3',
    occludedBy: 'sha1-iv',
    aliases: ['MD5 chaining variables']
  },
  {
    id: 'md5-t-table',
    name: 'MD5 T-Table (sine constants)',
    algorithm: 'MD5',
    category: Category.HASH,
    patterns: [
      'd76aa478e8c7b756242070dbc1bdceeef57c0faf4787c62aa8304613fd469501',
      '78a46ad756b7c7e8db702024eecebdc1af0f7cf52ac68747134630a8019546fd'
    ],
    lengthBytes: 32,
    wordSizeBytes: 4,
    description:
      'Unmistakable MD5: 64 sine-derived constants. Also disambiguates MD5 from SHA-1 (shared IVs).',
    story:
      'Each of MD5\'s 64 round constants is floor(2^32 × |sin(i)|) — RFC 1321 literally defines the algorithm through a trigonometric table. No other algorithm uses these values.',
    source: 'RFC 1321 §3.4',
    aliases: ['MD5 K table']
  },
  {
    id: 'tea-delta',
    name: 'TEA Delta Constant (0x9E3779B9)',
    algorithm: 'TEA/XTEA/XXTEA',
    category: Category.SYMMETRIC,
    patterns: ['9e3779b9', 'b979379e'],
    lengthBytes: 4,
    wordSizeBytes: 4,
    description:
      'TEA-family block cipher — CTF reversing classic, common in firmware and lightweight crypto.',
    story:
      '0x9E3779B9 is the fractional part of the golden ratio in 32 bits (2654435769). Wheeler and Needham chose it for TEA because golden-ratio multiples scatter well; the same value resurfaced as Q_w in RC6 and in dozens of hash mixers. A 4-byte pattern — corroborate with context before betting on it.',
    source: 'Wheeler & Needham, "TEA, a Tiny Encryption Algorithm" (1994)',
    aliases: ['golden ratio constant', 'RC6 Q_w']
  },
  {
    id: 'des-sbox',
    name: 'DES S-Box S1',
    algorithm: 'DES/3DES',
    category: Category.SYMMETRIC,
    patterns: ['0e040d01020f0b08030a060c05090007'],
    lengthBytes: 16,
    description:
      'DES or 3DES block cipher — broken since 1999, disallowed by NIST; an audit finding in any 2026 binary.',
    story:
      'Row 0 of the first DES S-box (14, 4, 13, 1, 2, 15, ...) in the standard one-byte-per-entry layout. The S-box values were famously designed behind closed doors at IBM/NSA to resist differential cryptanalysis — a story that predates public differential attacks by 15 years. DES keys are exhaustible on commodity hardware today.',
    source: 'FIPS 46-3 Appendix 1; NIST SP 800-131A Rev. 2',
    aliases: ['3DES', 'Triple-DES', 'Data Encryption Standard']
  },
  {
    id: 'chacha-sigma',
    name: 'ChaCha20 Sigma ("expand 32-byte k")',
    algorithm: 'ChaCha20',
    category: Category.SYMMETRIC,
    patterns: ['657870616e642033322d62797465206b'],
    lengthBytes: 16,
    description:
      'Modern ARX stream cipher: WireGuard, TLS 1.3, libsodium, SSH. Table-free design — this string is its only fingerprint.',
    story:
      'ChaCha works purely on add-rotate-XOR operations and carries no S-box; the 16-byte sigma constant "expand 32-byte k" seeds every block. Finding it means a deliberately modern, software-friendly crypto stack.',
    source: 'RFC 8439 §2.3',
    aliases: ['expand 32-byte k']
  },
  {
    id: 'salsa-sigma',
    name: 'Salsa20 Sigma ("expand 16-byte k")',
    algorithm: 'Salsa20',
    category: Category.SYMMETRIC,
    patterns: ['657870616e642031362d62797465206b'],
    lengthBytes: 16,
    description:
      'Salsa20 — ChaCha\'s predecessor (eSTREAM portfolio); shows in older libsodium/crypto++ code.',
    story:
      'Daniel J. Bernstein\'s original sigma string. ChaCha is Salsa20 with a different core walk; both constants say "expand the 32-byte key into the state" in literal ASCII.',
    source: 'Bernstein, "The Salsa20 family of stream ciphers" (2005)',
    aliases: ['expand 16-byte k']
  },
  {
    id: 'blowfish-p-array',
    name: 'Blowfish P-Array (digits of pi)',
    algorithm: 'Blowfish',
    category: Category.SYMMETRIC,
    patterns: [
      '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89',
      '886a3f24d308a3852e8a191344737003223809a4d0319f2998fa2e08896c4eec'
    ],
    lengthBytes: 32,
    wordSizeBytes: 4,
    description:
      'Blowfish family — either legacy bulk encryption or bcrypt password hashing (check for "$2a$" strings).',
    story:
      'The 18-entry P-array starts with the hexadecimal digits of pi: 0x243F6A88 0x85A308D3 0x13198A2E... Blowfish\'s expensive key schedule was recycled in 1999 as bcrypt — the pi digits in a binary usually mean one of the two.',
    source: 'Schneier, "Description of a New Variable-Length Key, 64-Bit Block Cipher (Blowfish)" (1993)',
    aliases: ['bcrypt key schedule', 'pi constants']
  },
  {
    id: 'crc32-table',
    name: 'CRC32 Lookup Table',
    algorithm: 'CRC32',
    category: Category.CHECKSUM,
    patterns: [
      '77073096ee0e612c990951ba076dc419706af48fe963a5359e6495a30edb8832' +
      '79dcb8a4e0d5e91e97d2d98809b64c2b7eb17cbde7b82d0790bf1d911db71064',
      '963007772c610eeeba51099919c46d078ff46a7035a563e9a395649e3288db0e' +
      'a4b8dc791ee9d5e088d9d2972b4cb609bd7cb17e072db8e7911dbf906410b71d'
    ],
    lengthBytes: 64,
    wordSizeBytes: 4,
    description:
      'CRC32 integrity code: zip, png, zlib, network protocols. A checksum, not encryption — re-read high entropy as compression.',
    story:
      'Each table entry is the remainder of the reflected polynomial 0xEDB88320. Ubiquitous in compression formats — which is exactly why finding it next to high entropy usually means "compressed", not "encrypted".',
    source: 'zlib / RFC 1952',
    aliases: ['CRC-32/ISO-HDLC table']
  },
  {
    id: 'base64-alphabet',
    name: 'Base64 Standard Alphabet',
    algorithm: 'Base64',
    category: Category.ENCODING,
    patterns: [
      '4142434445464748494a4b4c4d4e4f505152535455565758595a' +
      '6162636465666768696a6b6c6d6e6f707172737475767778797a' +
      '303132333435363738392b2f'
    ],
    lengthBytes: 64,
    description:
      'Base64 encoding present — data staging, config blobs, exfiltration prep in malware. Encoding, not encryption.',
    story:
      'RFC 4648\'s 64-character alphabet A-Za-z0-9+/. Nearly every binary that moves data as text embeds it; treat it as a clue to where data gets serialized, then look at what happens next to it.',
    source: 'RFC 4648 §4',
    aliases: []
  },
  {
    id: 'base64url-alphabet',
    name: 'Base64 URL-Safe Alphabet',
    algorithm: 'Base64url',
    category: Category.ENCODING,
    patterns: [
      '4142434445464748494a4b4c4d4e4f505152535455565758595a' +
      '6162636465666768696a6b6c6d6e6f707172737475767778797a' +
      '303132333435363738392d5f'
    ],
    lengthBytes: 64,
    description:
      'URL-safe Base64 — strongly associated with JWTs and web-token handling.',
    story:
      "Same alphabet with '+'/'/' swapped for '-'/'_' so the output survives URLs and filenames. Finding the URL-safe variant specifically hints at JWT (JWS) machinery.",
    source: 'RFC 4648 §5',
    aliases: ['base64url']
  },
  {
    id: 'secp256k1-generator',
    name: 'secp256k1 Generator Point',
    algorithm: 'secp256k1',
    category: Category.ASYMMETRIC,
    patterns: [
      '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817' +
      '98483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4' +
      'b8'
    ],
    lengthBytes: 65,
    description:
      'Bitcoin-curve key handling: wallets, blockchain toolkits, or DeFi backend code.',
    story:
      'The uncompressed SEC1 generator point 0x04 || Gx || Gy of the secp256k1 curve Bitcoin made famous. Its presence (typically via libsecp256k1) is close to conclusive that the binary touches cryptocurrency keys.',
    source: 'SEC 2: Recommended Elliptic Curve Domain Parameters §2.4.1',
    aliases: ['Bitcoin generator point']
  },
  {
    id: 'sm4-fk',
    name: 'SM4 FK Constants',
    algorithm: 'SM4',
    category: Category.SYMMETRIC,
    patterns: [
      'a3b1bac656aa3350677d9197b27022dc',
      'c6bab1a35033aa5697917d67dc2270b2'
    ],
    lengthBytes: 16,
    wordSizeBytes: 4,
    description:
      'SM4 — Chinese national standard block cipher (GB/T 32907). Supply-chain and compliance signal.',
    story:
      'The FK system parameters 0xA3B1BAC6... seed SM4\'s key schedule. SM4 is mandatory in Chinese commercial cryptography, so its constants appear in software built for that market.',
    source: 'GB/T 32907-2016',
    aliases: []
  },
  {
    id: 'sm4-sbox',
    name: 'SM4 S-Box (anchor)',
    algorithm: 'SM4',
    category: Category.SYMMETRIC,
    patterns: ['d690e9fecce13db716b614c228fb2c05'],
    lengthBytes: 16,
    description: 'SM4 substitution box (first 16 bytes) — corroborates sm4-fk.',
    story:
      'SM4\'s 8x8 S-box begins D6 90 E9 FE CC E1 3D B7... Like AES\'s, it ships as a byte table; this 16-byte anchor distinguishes SM4 from the near-identical-looking constant blocks of other ciphers.',
    source: 'GB/T 32907-2016',
    aliases: []
  }
];
