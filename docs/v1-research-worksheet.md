# findcrypt v1.0.0 — Signature Research Worksheet

This is YOUR research work — the part you can defend in any interview. v0.1.0
(17 signatures) is already published by the engine build; v1.0.0 is where you
add entries you researched yourself. Each one: find the constant in its
source document, add the object to `src/signatures/db.ts` (copy an existing
entry's shape), extend `scripts/gen-fixtures.mjs`, run `npm run fixtures`,
run `npm test`. 30–60 minutes each once you get going.

## Tier 1 — high value, well-documented (do these first)

| # | Signature | Source to read | What to extract | Notes |
|---|---|---|---|---|
| 1 | DES S-boxes (S1–S8) | FIPS 46-3 (nist.gov, free PDF) | 8 tables × 64 entries + PC-1/PC-2 permutation tables | The classic legacy-crypto marker. Note: C implementations embed S-boxes as 64-entry (or 256-entry expanded) byte tables — search for the embedded form, not the spec layout |
| 2 | Ed25519 sqrt(-1) | RFC 8032 §5.1 | 19681161376707505956807079324971251 (32 bytes, little-endian) | Modern secure-messenger fingerprint. 32-byte pattern = collision-proof |
| 3 | SHA-256 round constants (K table) | FIPS 180-4 §4.2.2 | 64 words = fractional cube roots of first 64 primes | Pairs beautifully with the IV story: IVs=sqrt, K=cbrt. gen-fixtures' `icbrt` helper is already written and verified |
| 4 | secp256r1 (NIST P-256) G point | SEC 2 §2.6 / NIST SP 800-186 | 65-byte uncompressed 04‖Gx‖Gy | THE differentiator: P-256 = standard TLS/compliance; secp256k1 = Bitcoin. Same engine, opposite verdicts |
| 5 | Keccak/SHA-3 round constants (RC) | FIPS 202 | 24 × 64-bit LFSR-derived words | Computable! RC generation is a 3-line LFSR — you write the derivation, not copy bytes. Interview gold |
| 6 | SM3 IVs | GB/T 32905-2016 | 7380166f 19ccc4d0 2e9fe62b ... 8 words | Completes the Chinese-suite story next to SM4 |

## Tier 2 — solid additions

| # | Signature | Source | Notes |
|---|---|---|---|
| 7 | Blowfish S-boxes (4×256 words) | Blowfish spec (pi digits continued) | gen script already computes pi; extend to ~3800 words |
| 8 | RC5/RC6 magic constants | Rivest's RC5 paper | P_w=0xB7E15163, Q_w=0x9E3779B9. Q equals TEA's delta — same constant, different algorithms; document the collision in the story field |
| 9 | CRC16-CCITT table | CRC catalog (reveng.wiki) | Network-protocol code marker |
| 10 | MurmurHash3 constants | smhasher (GitHub) | 0xcc9e2d51, 0x1b873593 — non-crypto hash used by Redis/LevelDB |
| 11 | SipHash sigma string | Aumasson/Bernstein SipHash paper | ASCII "somepseudorandomlygeneratedbytes" — HashDoS defense marker |
| 12 | GOST Magma S-box (CryptoPro-A) | RFC 4357 | Russian national standard — completes the regional-crypto story (CN/US/RU) |
| 13 | ARIA S-box | RFC 5794 | Korean national standard |
| 14 | Camellia S-box | RFC 3713 | NTT/Mitsubishi cipher, Japanese e-government |

## Tier 3 — engine stretch features (pick ONE if time allows)

- **PE/ELF section mapping**: parse section headers, map raw offsets to
  `.text/.rodata/.data` — findings like "AES S-box in .rodata @ va 0x47b800".
- **Single-byte XOR key detection**: XOR the file with each 256 keys and
  re-scan for known alphabets/strings — catches cheap obfuscation.
- **Directory scanning** (`findcrypt ./samples/`) and `--max-matches`.

## Non-goals (say this in the viva/demo)

No disassembly, no dynamic analysis, no decryption, no YARA, no plugins,
no implementing crypto algorithms — detection only. These are design
decisions with rationale in the architecture doc, not missing features.

## Version plan

- **v0.2.0** (Monday morning): Tier 1 signatures #1–#4 + updated dictionary
- **v1.0.0** (Monday, before 11:59 PM IST): Tier 1 #5–6 + (if time) one
  Tier-3 stretch; final README polish; submit the Google Form
- Every publish: `npm version minor` then `npm publish` — `prepublishOnly`
  re-runs type-check, build and the full test suite automatically, so a
  broken version cannot ship.

## Demo script for the evaluators (2 minutes)

1. `npx findcrypt /usr/bin/node` — 12 algorithm families in ~2 seconds
2. Scan any Windows .exe — UTF-16LE strings demo
3. The verdict story: AES + high entropy → ransomware shape; secp256k1 → wallet
4. Show `src/signatures/db.ts` — the data file with sources and stories
5. Show the test suite: every signature fixture-verified, both endiannesses,
   66+ tests
