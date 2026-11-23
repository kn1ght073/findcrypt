# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Test infrastructure and verification hardening — no runtime code changes.

### Added

- `test/authenticity.test.ts` — every db.ts constant re-derived a second time,
  inside the test, from its published standard (GF(2^8) log/exp tables for
  AES, BigInt fractional square roots for SHA-2, the sine table for MD5, the
  golden ratio for TEA, the reflected CRC32 algorithm, an on-curve proof of
  the secp256k1 generator) plus structural integrity checks (unique ids, hex
  validity, occludedBy/rule references, manifest coverage).
- `scripts/gen-fixtures.mjs --check` (`npm run fixtures:check`) — drift guard
  proving committed fixtures are byte-identical to a fresh generation; wired
  into the test suite (with a self-test of the detector) and into CI before
  type-check and tests.
- Scenario fixtures (`scenario-wallet/legacy/arx/packed/plaintext`) for
  end-to-end verdict testing, described in `test/fixtures/scenarios.json`.
- `test/disambiguation.test.ts` — MD5/SHA-1 shared-IV occlusion pinned from
  every side, including the library pipeline and little-endian patterns.
- `test/boundaries.test.ts` — constants at offset 0 / EOF / shifted by one /
  back to back, degenerate inputs, scanner options, and a 2 MB performance
  regression guard (< 5 s).
- `test/cli.matrix.test.ts` — 25-case flag matrix and operational error paths
  (multi-file runs, invalid values, directories, unreadable files, unicode
  names, stdin, `--json` over `--markdown`).
- `test/output-contract.test.ts` — the JSON/Markdown schema contract: complete
  envelope, in-bounds ascending offsets, zero ANSI escapes under
  `FORCE_COLOR=1`, and ESM/CJS dual-format interop checks.
- `test/verdicts.test.ts` — end-to-end verdicts on the scenario fixtures with
  confidence ordering, through both the API and the CLI.
- `test/realworld.test.ts` — scans the Node runtime itself (statically-linked
  OpenSSL), the system libcrypto when present, `/bin/ls`, and this repo's own
  generator source.
- `TESTING.md` — the development guide: suite map, fixture design, a local
  bug-hunting checklist, and the add-a-signature loop.
- CI: Node 24 added to the matrix; fixture drift gate added before tests.

### Changed

- Test count grew from 67 to 170 across 14 files; `npm test` still finishes
  in seconds.

## [0.2.0] - 2026-11-23

Full audit pass over v0.1.0: every signature constant was re-derived from
first principles (GF(2^8) inversion, BigInt square roots, Machin's formula,
the sine table, the golden ratio) or byte-diffed against its published spec
value, and the secp256k1 generator point was verified on-curve via
y^2 = x^3 + 7 (mod p).

### Added

- DES S-box S1 signature (FIPS 46-3) — the obsolete-crypto verdict promised
  in the README now has its detector; DES/3DES findings join the audit
  verdict alongside MD5 and SHA-1.
- Curve-equation verification of the secp256k1 generator point inside the
  fixture generator, so a corrupted constant can never pass silently.
- `typecheck` script alias (matches CI).
- Package metadata for npm discoverability: repository, homepage, bugs,
  author fields.

### Fixed

- README badges pointed at `PLACEHOLDER-OWNER` instead of this repository.
- `prepack` build hook added: `npm publish` from a fresh clone can no
  longer ship an empty tarball (`dist/` is gitignored and was not rebuilt
  automatically before packing).

### Changed

- Version 0.2.0.

## [0.1.0] - 2026-11-22

### Added

- Signature scanning engine: byte-pattern search with match caps, per-signature
  match grouping, offset reporting and match context capture.
- Signature database v1 — 17 fingerprints, each with its source citation and
  the story behind the constant: AES S-box + inverse, SHA-256/512 initial
  values, SHA-1/MD5 initial values, MD5 T-table, TEA delta, ChaCha/Salsa
  sigma, Blowfish P-array, CRC32 table, Base64 (std + URL-safe) alphabets,
  secp256k1 generator point, SM4 FK constants + S-box anchor.
- Endianness coverage: word-table signatures match both little- and
  big-endian storage.
- MD5/SHA-1 shared-prefix disambiguation via a data-driven `occludedBy` rule.
- Shannon entropy: whole-file value, sampled sliding-window profile, peak
  window, and a plain-language classification.
- ASCII + UTF-16LE string extraction with length filtering.
- Data-driven verdict engine: 12 rules mapping fingerprint combinations to
  analyst guidance (ransomware-style AES, wallet code, obsolete crypto,
  packed/high-entropy, GB-standard crypto, ...).
- CLI (`findcrypt`): terminal (ANSI, honors NO_COLOR), `--json`, `--markdown`,
  `--min-entropy`, `--no-strings`, `--min-str-len`, stdin support via `-`.
- Public typed API: `scanBuffer`, `scanFile`, exported signatures + rules data.
- Exit-code contract: 0 = fingerprints found, 1 = none, 2 = operational error.
- Test suite (vitest): per-signature fixture tests, entropy known-values,
  strings, inference, report formats, CLI smoke tests.
- GitHub Actions CI: Linux/macOS/Windows x Node 20/22.
- Deterministic fixture generator (`scripts/gen-fixtures.mjs`) that derives
  constants from first principles (GF(2^8) inversion for AES, BigInt sqrt/cbrt
  for SHA IVs, Machin's formula for pi-derived Blowfish tables) and verifies
  each against its published spec value before writing fixtures.
