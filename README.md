# findcrypt

> **Find cryptographic fingerprints in any file.** AES S-boxes, SHA initial
> values, ChaCha sigma constants, the TEA golden ratio, secp256k1's generator
> point — every crypto implementation embeds constants, and findcrypt maps
> them, with entropy analysis, string extraction and analyst-ready verdicts.

[![npm version](https://img.shields.io/npm/v/findcrypt.svg)](https://www.npmjs.com/package/findcrypt)
[![CI](https://github.com/kn1ght073/findcrypt/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Zero runtime dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](./package.json)

```bash
npx findcrypt /path/to/binary          # no install needed
npm install -g findcrypt                # or install globally
```

---

## Why this exists

Crypto doesn't hide silently in binaries. Implementations carry S-boxes,
lookup tables and "nothing-up-my-sleeve" initial values — and those bytes are
fingerprints. findcrypt is the free, standalone answer to a classic RE tool
(the IDA Pro *findcrypt* plugin), usable by anyone with Node.js installed:

1. **Malware triage** — before opening a disassembler, know what crypto a
   sample ships: table-driven AES + near-maximum entropy is the shape of a
   ransomware payload; Base64 + XOR is data staging for exfiltration.
2. **CTF reversing** — the 0x9E3779B9 delta tells you it's a TEA-family
   cipher in one second instead of one hour of scrolling through Ghidra.
3. **Security audits** — finding DES, MD5 or SHA-1 in a 2026 firmware image
   is a report-ready finding: obsolete crypto in production.
4. **Verifying vendor claims** — a product marketing "military-grade AES"
   with zero AES constants in its binary is lying to you. Run the scan,
   keep the receipt.

## Live demo — scanning a real OpenSSL build

```text
$ npx findcrypt /usr/lib/x86_64-linux-gnu/libcrypto.so.3

findcrypt v0.2.0 — cryptographic fingerprint scanner
File: libcrypto.so.3  (6,521,408 bytes)
Entropy: 6.218 bits/byte [###################-----] — elevated — typical of machine code with some high-entropy regions
  peak window 7.955 @ 0x004dbdc2

Fingerprints (10)
  AES S-Box          SYMMETRIC  256 B  0x0047b800, 0x0047b900, 0x0047ba00 (+1 more)
  AES Inverse S-Box  SYMMETRIC  256 B  0x0047c440, 0x0047c560, 0x0047c680 (+1 more)
  SHA-256 Initial Hash Values  HASH  32 B  @ 0x004ab8e0
  SHA-512 Initial Hash Values  HASH  64 B  @ 0x004ab9c0
  MD5 Initial Hash Values      HASH  16 B  @ 0x004ab8a0
  ChaCha20 Sigma ("expand 32-byte k")  SYMMETRIC  16 B  @ 0x004b6940
  Blowfish P-Array (digits of pi)      SYMMETRIC  32 B  @ 0x004aa1c0
  TEA Delta Constant (0x9E3779B9)      SYMMETRIC   4 B  @ 0x00389c6a
  Base64 Standard Alphabet  ENCODING  64 B  @ 0x004f9380
  SM4 S-Box (anchor)       SYMMETRIC  16 B  @ 0x00509be0

Verdicts
  [HIGH]     Table-driven AES implementation
  [HIGH]     Obsolete cryptography — audit finding (MD5)
  [HIGH]     ARX stream cipher: ChaCha/Salsa family
  [HIGH]     Chinese national standard cryptography (SM4)
  [MEDIUM]   Blowfish family — bcrypt or legacy encryption
  [LOW]      Base64 encoding layer
  ...

Strings (5000+)
  0x00000384  ascii  "PBLN"
```

Every offset is a landmark: open it in Ghidra/radare2 and you are inside the
implementing function, not scrolling blindly. On the 126 MB `node`
executable it finds 12 algorithm families in under 2 seconds.

## Usage

### CLI

```text
Usage:
  findcrypt <file> [more files...] [options]
  cat sample.bin | findcrypt -

Options:
  --json               machine-readable JSON report
  --markdown           GitHub-flavored Markdown report
  --min-entropy <n>   only report files with entropy >= n (0-8)
  --no-strings         skip string extraction
  --min-str-len <n>    minimum string length (default 4)
  --version            print version
  --help               show this help

Exit codes:  0 fingerprints found · 1 none found · 2 operational error
```

Exit codes make it scriptable: chain it in CI, pipe it over SSH, loop it
over a malware corpus.

### Programmatic API

```js
import { scanFile, scanBuffer } from 'findcrypt';

const result = await scanFile('./sample.bin', { minStringLength: 6 });
console.log(result.entropy.fileEntropy);            // 7.31
for (const f of result.findings) {
  console.log(f.name, f.algorithm, f.offsets);     // with every offset
}
for (const v of result.verdicts) {
  console.log(v.confidence, v.label);               // ranked analyst guidance
}
```

The CLI is a thin wrapper over this API — every real decision lives in the
library. Fully typed results, ESM + CJS builds, zero runtime dependencies.

## Methodology — why crypto leaves fingerprints

Three mechanical facts make constant-scanning work:

1. **Table-driven designs embed their tables.** AES is a substitution-permutation
   network; its S-box is 256 bytes of the multiplicative inverse in GF(2^8)
   under an affine transform (FIPS 197 §5.1.1). Implementations that don't
   use CPU AES-NI store those 256 bytes verbatim.
2. **Specs fix initial values.** SHA-256's state starts with the first 32
   bits of the square roots of the first eight primes (FIPS 180-4 §5.3.1).
   The bytes are the same everywhere, by definition.
3. **Even table-free designs carry magic.** ChaCha/Salsa are pure
   add-rotate-XOR, yet still embed the ASCII string "expand 32-byte k"
   (RFC 8439 §2.3). It is the only fingerprint they have — and it is enough.

Word-table signatures match both byte orders (a big-endian MIPS firmware and
an x86 laptop store SHA-256's IVs differently). MD5 and SHA-1 share their
first four initial words, so the engine drops an MD5 hit when SHA-1's longer
(five-word) pattern matches at the same offset — a data-driven
`occludedBy` rule, not a code special-case.

Every constant in the database was derived from first principles and verified
against its published value before shipping — see
`scripts/gen-fixtures.mjs` (GF(2^8) inversion for AES, BigInt square roots
for SHA-2, Machin's formula for the pi digits behind Blowfish, the golden
ratio for TEA).

## Signature dictionary (v1)

| Signature | What finding it tells you |
|---|---|
| AES S-box / inverse | Full software AES (encrypt+decrypt). Ransomware/TLS/file-encryption shape |
| SHA-256 / SHA-512 IVs | Modern baseline hashing — certs, HMAC, KDF, Bitcoin |
| SHA-1 / MD5 IVs, MD5 T-table | Obsolete hashing — an audit finding in 2026 |
| DES S-box S1 | DES/3DES — broken since 1999, NIST-disallowed; audit finding |
| TEA delta `0x9E3779B9` | TEA/XTEA/XXTEA (CTF classic) — also used by hash mixers, corroborate |
| ChaCha / Salsa sigma | Modern ARX stream cipher — WireGuard, TLS 1.3, libsodium |
| Blowfish P-array | bcrypt password hashing or legacy Blowfish encryption |
| CRC32 table | Compression/integrity code (zip/png/zlib) — not encryption |
| Base64 (std / URL-safe) | Encoding layer: data staging, config blobs, JWTs |
| secp256k1 generator | Bitcoin-curve key handling — wallet/blockchain code |
| SM4 FK + S-box | Chinese national standard cryptography (GB/T 32907-2016) |

Each entry in `src/signatures/db.ts` carries its story and primary source
citation. The database is pure data: adding a signature never touches engine
code.

## Verdict combinations

| Scan shows | Verdict |
|---|---|
| AES S-boxes, high entropy | Table-driven AES — ransomware/TLS/encryption tooling |
| secp256k1 + SHA-256 | Cryptocurrency key handling |
| ChaCha/Ed-style stack | Deliberately modern crypto |
| DES / MD5 / SHA-1 | Obsolete crypto — audit finding |
| Nothing + entropy ≥ 7.9 | Packed, encrypted or custom crypto — unpack and rescan |
| Base64 + low real crypto | Obfuscation layer, not "military-grade encryption" |

## Limitations (honest ones)

- **A clean scan is not proof of absence.** AES-NI implementations use CPU
  instructions and carry no S-box; a binary can absolutely use AES without
  matching. Bit-sliced and computed-table implementations also evade.
- **RC4 has no static constant.** Its state is derived at runtime; detection
  requires disassembly, not byte scanning.
- **Packed/encrypted sections hide constants.** UPX/VMProtect payloads show
  high entropy and nothing else — unpack first, rescan after.
- **Short patterns can collide.** The 4-byte TEA delta also appears in hash
  mixers and RC6 (as `Q_w`); treat 4-byte hits as leads, not conclusions.
  Longer table signatures are effectively collision-proof.
- **256 MB file cap.** Files are read into memory (documented in the API);
  split oversized inputs or target offsets with a hex editor.
- **Constants ≠ secure usage.** Finding AES says the table is present — not
  that keys are managed correctly.

## Adding a signature (contributing)

1. Find the constant in its standard (FIPS, RFC, or national spec).
2. Add an object to `src/signatures/db.ts` — id, byte pattern(s), story, source.
3. `npm run fixtures` regenerates `test/fixtures/` deterministically.
4. `npm test` — the suite auto-verifies every pattern against its fixture,
   both endiannesses, and the MD5/SHA-1 occlusion rule.

## Testing

The full development guide — suite map, fixture design, a bug-hunting
checklist for your own machine, and the add-a-signature loop — lives in
[TESTING.md](./TESTING.md). Quick start: `npm install && npm run build && npm test`.

## License

MIT — see [LICENSE](./LICENSE).
