import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { scanBuffer as rawScan, normalizeHex } from '../src/core/scanner.js';
import { disambiguate } from '../src/inference/engine.js';
import { scanBuffer as pipeline } from '../src/index.js';
import { SIGNATURES } from '../src/signatures/db.js';
import type { Finding, SignatureEntry } from '../src/signatures/types.js';

/**
 * THE T1 TRAP, MADE PERMANENT
 * ===========================
 * MD5 and SHA-1 share their first four initial words (0x67452301, 0xefcdab89,
 * 0x98badcfe, 0x10325476) — MD4 lineage. A naive scanner therefore reports
 * "MD5" inside every SHA-1 implementation. The engine disambiguates via the
 * data-driven occludedBy rule: when the longer SHA-1 pattern matches at the
 * SAME offset, the MD5 hit there is a prefix re-detection and is dropped.
 *
 * These tests pin every side of that behavior — including the sides that must
 * NOT change: a genuine MD5 (without SHA-1 following) and a binary containing
 * both algorithms at different offsets.
 */

function patternOf(id: string, index = 0): Buffer {
  const entry = SIGNATURES.find((s) => s.id === id);
  if (!entry) throw new Error(`no such signature: ${id}`);
  return Buffer.from(normalizeHex(entry.patterns[index]), 'hex');
}

function ids(findings: Finding[]): string[] {
  return findings.map((f) => f.signatureId);
}

describe('disambiguation: the MD5/SHA-1 shared initial words', () => {
  it('SHA-1 fixture: raw scan sees both, disambiguation drops the MD5 echo', () => {
    const buffer = readFileSync('test/fixtures/fixture-sha1-iv.bin');

    const raw = rawScan(buffer, SIGNATURES);
    expect(ids(raw)).toContain('sha1-iv');
    expect(ids(raw)).toContain('md5-iv'); // the shared prefix really does match

    const clean = disambiguate(raw, SIGNATURES);
    expect(ids(clean)).toContain('sha1-iv');
    expect(ids(clean)).not.toContain('md5-iv'); // ...and is correctly occluded
  });

  it('MD5-only fixture: the genuine MD5 hit survives disambiguation', () => {
    const buffer = readFileSync('test/fixtures/fixture-md5-iv.bin');
    const raw = rawScan(buffer, SIGNATURES);
    expect(ids(raw)).toContain('md5-iv');
    expect(ids(raw)).not.toContain('sha1-iv');

    const clean = disambiguate(raw, SIGNATURES);
    expect(ids(clean)).toContain('md5-iv');
  });

  it('both algorithms at DIFFERENT offsets: both survive (real co-presence)', () => {
    // A legacy binary can genuinely implement MD5 and SHA-1 side by side.
    // Occlusion is per-offset, so both findings must be kept.
    const md5 = patternOf('md5-iv'); // 16 bytes
    const sha1 = patternOf('sha1-iv'); // 20 bytes
    const buffer = Buffer.concat([
      Buffer.alloc(50, 0x41),
      md5, // offset 50 — pure MD5 IV
      Buffer.alloc(30, 0x42),
      sha1, // offset 96 — pure SHA-1 IV
      Buffer.alloc(10, 0x43)
    ]);
    const clean = disambiguate(rawScan(buffer, SIGNATURES), SIGNATURES);
    expect(clean.find((f) => f.signatureId === 'md5-iv')?.offsets).toEqual([50]);
    expect(clean.find((f) => f.signatureId === 'sha1-iv')?.offsets).toEqual([96]);
  });

  it('occlusion also works for the little-endian patterns', () => {
    const sha1Le = patternOf('sha1-iv', 1);
    const buffer = Buffer.concat([Buffer.alloc(64, 0x41), sha1Le, Buffer.alloc(8, 0x42)]);
    const clean = disambiguate(rawScan(buffer, SIGNATURES), SIGNATURES);
    expect(ids(clean)).toContain('sha1-iv');
    expect(ids(clean)).not.toContain('md5-iv');
  });

  it('the public pipeline (index.scanBuffer) applies disambiguation too', () => {
    // Library consumers must never receive the raw MD5 echo for a SHA-1 hit.
    const buffer = readFileSync('test/fixtures/fixture-sha1-iv.bin');
    const result = pipeline(buffer);
    expect(ids(result.findings)).toContain('sha1-iv');
    expect(ids(result.findings)).not.toContain('md5-iv');
  });
});

describe('occludedBy data integrity', () => {
  const entriesWithOccluder = SIGNATURES.filter((s) => s.occludedBy);

  it('at least one occlusion rule exists (md5-iv <- sha1-iv)', () => {
    const md5 = SIGNATURES.find((s) => s.id === 'md5-iv') as SignatureEntry;
    expect(md5.occludedBy).toBe('sha1-iv');
    expect(entriesWithOccluder.length).toBeGreaterThanOrEqual(1);
  });

  it('every occluder pattern strictly extends the occluded pattern (prefix relation is real)', () => {
    for (const entry of entriesWithOccluder) {
      const occluder = SIGNATURES.find((s) => s.id === entry.occludedBy);
      expect(occluder, `${entry.id} occludedBy unknown id`).toBeDefined();
      const shorter = entry.patterns.map(normalizeHex);
      const longer = (occluder as SignatureEntry).patterns.map(normalizeHex);
      const anyPrefix = longer.some((l) =>
        shorter.some((s) => l.length > s.length && l.startsWith(s))
      );
      expect(anyPrefix, `${entry.id} -> ${entry.occludedBy} is not a real prefix relation`).toBe(true);
    }
  });
});
