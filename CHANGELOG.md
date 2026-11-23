# Changelog

All notable changes to findcrypt are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- PE/ELF section mapping — resolve raw offsets to `.text/.rodata/.data`
  and report virtual addresses alongside file offsets.
- Single-byte XOR key detection — re-scan under each of the 256 keys to
  surface cheaply obfuscated constants and alphabets.
- Directory scanning (`findcrypt ./samples/`) and a `--max-matches` cap.

## [0.1.0] - 2026-11-23

First release. findcrypt maps the constants every crypto implementation
embeds — AES S-boxes, SHA initial values, the ChaCha sigma constants, the
TEA golden ratio, secp256k1's generator point — and turns them, together
with entropy profiling and string extraction, into analyst-ready verdicts.
Zero runtime dependencies, Node 18+.

Every constant in the database is re-derived from first principles (GF(2^8)
inversion for AES, BigInt square roots for SHA-2, Machin's formula, the sine
table, the golden ratio) or byte-diffed against its published spec value;
the secp256k1 generator point is verified on-curve via y^2 = x^3 + 7 (mod p).

### Added

- Signature scanning engine: byte-pattern search with match caps,
  per-signature offset grouping and match context capture; word-table
  signatures match both little- and big-endian storage.
- Signature database v1 — 18 fingerprints, each with its source citation
  and the story behind the constant: AES S-box + inverse, SHA-1/256/512
  initial values, MD5 initial values + T-table, TEA delta, ChaCha/Salsa
  sigma, Blowfish P-array, CRC32 table, Base64 (std + URL-safe) alphabets,
  secp256k1 generator point, SM4 FK constants + S-box anchor, DES S-box S1
  (FIPS 46-3).
- MD5/SHA-1 shared-prefix disambiguation via a data-driven `occludedBy`
  rule.
- Shannon entropy: whole-file value, sampled sliding-window profile, peak
  window, and a plain-language classification.
- ASCII + UTF-16LE string extraction with length filtering.
- Data-driven verdict engine: 12 rules mapping fingerprint combinations to
  analyst guidance (ransomware-style AES, wallet code, obsolete crypto,
  packed/high-entropy, GB-standard crypto, ...).
- CLI (`findcrypt`): terminal reporter (ANSI, honors `NO_COLOR`),
  `--json`, `--markdown`, `--min-entropy`, `--no-strings`, `--min-str-len`,
  stdin support via `-`.
- Public typed API: `scanBuffer`, `scanFile`, exported signatures + rules
  data; exit-code contract: 0 = fingerprints found, 1 = none,
  2 = operational error.
- Deterministic fixture generator (`scripts/gen-fixtures.mjs`) that derives
  every constant from its standard and verifies it before writing fixtures;
  `npm run fixtures:check` guards against drift.
- Test suite (vitest): 170 tests across 14 files — per-signature fixtures
  in both byte orders, entropy known values, inference ordering, report
  schema contracts, a 25-case CLI flag matrix, end-to-end verdict pins on
  scenario fixtures, real-world scans (Node's statically-linked OpenSSL,
  system libcrypto, `/bin/ls`), and an authenticity suite that re-derives
  every db.ts constant inside the test itself.
- CI: GitHub Actions matrix, Linux/macOS/Windows x Node 18/20/22/24, with
  the fixture drift gate before type-check and tests, plus an
  `npm pack --dry-run` publish gate.
- Publish gates: `prepack` builds and `prepublishOnly` re-runs type-check,
  build and the full test suite, so a broken version cannot ship.
- Community and hygiene files: `CONTRIBUTING.md`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, issue/PR templates, `TESTING.md` (the development
  guide: suite map, fixture design, the add-a-signature loop) and
  `.editorconfig`; package metadata for npm discoverability.
