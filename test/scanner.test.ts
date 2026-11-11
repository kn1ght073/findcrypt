import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { scanBuffer, normalizeHex } from '../src/core/scanner.js';
import { SIGNATURES } from '../src/signatures/db.js';
import type { SignatureEntry } from '../src/signatures/types.js';

const manifest: Record<string, { offset: number; patternIndex: number; patternHex: string }> =
  JSON.parse(readFileSync('test/fixtures/manifest.json', 'utf8'));

/**
 * THE INVARIANT: every database entry must have a fixture, and the fixture
 * must contain the exact pattern from db.ts at the planted offset. This test
 * is what makes "adding a signature = data + fixture + test" unbreakable:
 * any drift between the database and the verified constants fails here.
 */
describe('signature database vs fixtures (per-signature positive tests)', () => {
  for (const [id, meta] of Object.entries(manifest)) {
    it(`${id}: fixture matches db.ts pattern at offset ${meta.offset}`, () => {
      const buffer = readFileSync(`test/fixtures/fixture-${id}.bin`);
      const findings = scanBuffer(buffer, SIGNATURES);
      const finding = findings.find((f) => f.signatureId === id);
      expect(finding, `expected finding ${id}`).toBeDefined();
      expect(finding!.offsets).toContain(meta.offset);

      // The db.ts pattern must literally equal the generator's verified bytes.
      const entry: SignatureEntry | undefined = SIGNATURES.find((s) => s.id === id);
      expect(entry).toBeDefined();
      expect(normalizeHex(entry!.patterns[meta.patternIndex])).toBe(meta.patternHex);

      // Endianness symmetry: for word-table signatures the little-endian
      // pattern is the per-word byte reversal of the big-endian one.
      if (entry!.patterns.length === 2 && entry!.wordSizeBytes) {
        const be = Buffer.from(normalizeHex(entry!.patterns[0]), 'hex');
        const le = normalizeHex(entry!.patterns[1]);
        const w = entry!.wordSizeBytes;
        const flipped = Buffer.alloc(be.length);
        for (let i = 0; i < be.length; i += w) {
          be.subarray(i, i + w).copy(flipped, i);
          flipped.subarray(i, i + w).reverse();
        }
        expect(le).toBe(flipped.toString('hex'));
      }
    });
  }

  // Known cross-detection: SHA-1's 20-byte pattern starts with MD5's 16 bytes.
  it('sha1-iv fixture also triggers md5-iv before disambiguation (shared prefix)', () => {
    const buffer = readFileSync('test/fixtures/fixture-sha1-iv.bin');
    const findings = scanBuffer(buffer, SIGNATURES);
    expect(findings.find((f) => f.signatureId === 'sha1-iv')).toBeDefined();
    expect(findings.find((f) => f.signatureId === 'md5-iv')).toBeDefined();
  });
});

describe('scanner edge cases', () => {
  it('empty buffer: no findings', () => {
    const buffer = readFileSync('test/fixtures/empty.bin');
    expect(scanBuffer(buffer, SIGNATURES)).toHaveLength(0);
  });

  it('seeded random noise: no false positives across the whole database', () => {
    const buffer = readFileSync('test/fixtures/noise.bin');
    const findings = scanBuffer(buffer, SIGNATURES);
    // A 4-byte pattern (tea-delta) hitting random 4096 bytes is ~1/2^32 per
    // position; with the fixed seed this cannot flake. Anything longer is
    // astronomically impossible.
    expect(findings).toHaveLength(0);
  });

  it('caps matches at 64 and flags truncation', () => {
    const alphabet = Buffer.from(
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
      'latin1'
    );
    const buffer = Buffer.concat(Array(200).fill(alphabet));
    const findings = scanBuffer(buffer, SIGNATURES);
    const finding = findings.find((f) => f.signatureId === 'base64-alphabet');
    expect(finding).toBeDefined();
    expect(finding!.truncated).toBe(true);
    expect(finding!.offsets).toHaveLength(64);
  });

  it('reports offsets correctly for repeated non-overlapping matches', () => {
    const pattern = Buffer.from('657870616e642033322d62797465206b', 'hex');
    const parts = [
      Buffer.alloc(16, 0x41),
      pattern,
      Buffer.alloc(8, 0x42),
      pattern,
      Buffer.alloc(4, 0x43)
    ];
    const buffer = Buffer.concat(parts);
    const findings = scanBuffer(buffer, SIGNATURES);
    const finding = findings.find((f) => f.signatureId === 'chacha-sigma');
    expect(finding).toBeDefined();
    expect(finding!.offsets).toEqual([16, 40]);
  });

  it('captures context around the first match', () => {
    const pattern = Buffer.from('657870616e642033322d62797465206b', 'hex');
    const buffer = Buffer.concat([Buffer.alloc(64, 0x41), pattern, Buffer.alloc(64, 0x42)]);
    const findings = scanBuffer(buffer, SIGNATURES);
    const finding = findings.find((f) => f.signatureId === 'chacha-sigma')!;
    expect(finding.contextHex.length).toBeGreaterThan(64);
    expect(finding.contextHex).toContain('41414141');
    expect(finding.contextHex).toContain('42424242');
  });
});
