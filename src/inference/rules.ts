import type { VerdictRule } from './types.js';

/**
 * Verdict rules — pure data. The engine evaluates these; the guidance text
 * is the "so what" that turns a raw match dump into an analyst lead.
 */
export const VERDICT_RULES: readonly VerdictRule[] = [
  {
    id: 'crypto-present',
    label: 'Cryptographic primitives detected',
    confidence: 'LOW',
    when: 'HAS_FINDINGS',
    explanation:
      'Known algorithm constants are embedded in this file. Open each fingerprint offset in a disassembler (Ghidra, radare2, IDA): the tables sit inside the implementing function, and hardcoded keys are often stored nearby.'
  },
  {
    id: 'aes-table',
    label: 'Table-driven AES implementation',
    confidence: 'HIGH',
    when: 'ANY',
    requiresAny: ['aes-sbox', 'aes-sbox-inverse'],
    explanation:
      'An AES S-box marks a software AES implementation (FIPS 197). CPU AES-NI builds carry no S-box, so a clean scan does not disprove AES. Finding both the box and its inverse usually means full encrypt+decrypt support — typical of ransomware payloads, TLS stacks and file-encryption tools.'
  },
  {
    id: 'sha2-modern',
    label: 'SHA-2 family hashing present',
    confidence: 'MEDIUM',
    when: 'ANY',
    requiresAny: ['sha256-iv', 'sha512-iv'],
    explanation:
      "SHA-2's initial values are the fractional square/cube roots of the first primes — deliberate nothing-up-my-sleeve numbers. SHA-2 is the modern baseline: certificates, HMAC, key derivation. Corroborate with secp256k1 for cryptocurrency usage."
  },
  {
    id: 'legacy-hash',
    label: 'Obsolete cryptography — audit finding',
    confidence: 'HIGH',
    when: 'ANY',
    requiresAny: ['md5-iv', 'md5-t-table', 'sha1-iv', 'des-sbox'],
    explanation:
      'MD5 and SHA-1 are cryptographically broken (practical collisions), and DES was exhausted back in 1999 (Deep Crack) with 3DES reaching end-of-life in 2024 (NIST SP 800-131A Rev. 2). In modern software these indicate legacy code paths, malware integrity checks, or outdated vendor crypto — worth an audit note either way.'
  },
  {
    id: 'arx-stream',
    label: 'ARX stream cipher: ChaCha/Salsa family',
    confidence: 'HIGH',
    when: 'ANY',
    requiresAny: ['chacha-sigma', 'salsa-sigma'],
    explanation:
      'The sigma constant is the ONLY table these designs embed — ARX ciphers work purely on add-rotate-xor operations. Used by WireGuard, TLS 1.3 and libsodium; its presence implies a deliberately modern crypto stack.'
  },
  {
    id: 'tea-family',
    label: 'TEA/XTEA/XXTEA block cipher',
    confidence: 'MEDIUM',
    when: 'ANY',
    requiresAny: ['tea-delta'],
    explanation:
      '0x9E3779B9 is the golden-ratio constant of the TEA cipher family — a CTF reversing classic and common in embedded firmware. It also appears in some hash functions and RC6, so corroborate with the surrounding code before concluding.'
  },
  {
    id: 'wallet-crypto',
    label: 'Cryptocurrency key handling',
    confidence: 'HIGH',
    when: 'ANY',
    requiresAny: ['secp256k1-generator'],
    explanation:
      'The secp256k1 generator point is the fingerprint of Bitcoin-style cryptography. With SHA-256 also present, this is almost certainly wallet or blockchain code.'
  },
  {
    id: 'gb-standard',
    label: 'Chinese national standard cryptography (SM4)',
    confidence: 'HIGH',
    when: 'ANY',
    requiresAny: ['sm4-fk', 'sm4-sbox'],
    explanation:
      'SM4 (GB/T 32907-2016) appears in software built for the Chinese market, often for regulatory compliance — useful supply-chain context when auditing a vendor binary.'
  },
  {
    id: 'blowfish-family',
    label: 'Blowfish family — bcrypt or legacy encryption',
    confidence: 'MEDIUM',
    when: 'ANY',
    requiresAny: ['blowfish-p-array'],
    explanation:
      'The P-array begins with the digits of pi. Blowfish itself is legacy encryption, but its key schedule lives on inside bcrypt password hashing — look for "$2a$" strings to tell them apart.'
  },
  {
    id: 'checksum-code',
    label: 'CRC32 integrity code — compression, not encryption',
    confidence: 'LOW',
    when: 'ANY',
    requiresAny: ['crc32-table'],
    explanation:
      'CRC32 is a checksum, not cryptography: it marks zip/png/zlib-style code. Use it to re-read high entropy as compression rather than encryption before chasing a decryption that is not there.'
  },
  {
    id: 'base64-layer',
    label: 'Base64 encoding layer',
    confidence: 'LOW',
    when: 'ANY',
    requiresAny: ['base64-alphabet', 'base64url-alphabet'],
    explanation:
      'Base64 is encoding, not encryption — the URL-safe variant hints at JWT/web-token code. In malware it commonly marks data staged for exfiltration; look for network code near the encoder.'
  },
  {
    id: 'packed-or-custom',
    label: 'High entropy with no known signatures',
    confidence: 'HIGH',
    when: 'NO_FINDINGS',
    minEntropy: 7.9,
    explanation:
      'Near-maximal entropy and zero fingerprints: the payload is packed (UPX, VMProtect), uses table-free hardware crypto, or implements custom crypto. Try unpacking and rescanning, or dump memory at runtime.'
  }
];
