import { describe, it, expect } from 'vitest';
import { scanBuffer, normalizeHex } from '../src/core/scanner.js';
import { SIGNATURES } from '../src/signatures/db.js';

/**
 * Boundary conditions for the scanning engine. Real-world layouts put
 * constants in awkward places — first byte of the file, last bytes before
 * EOF, back to back, shifted by one — and a scanner that only ever sees
 * "256 bytes of noise, then the constant" (the fixture layout) can hide
 * off-by-one bugs at those edges.
 */

function patternOf(id: string, index = 0): Buffer {
  const entry = SIGNATURES.find((s) => s.id === id);
  if (!entry) throw new Error(`no such signature: ${id}`);
  return Buffer.from(normalizeHex(entry.patterns[index]), 'hex');
}

/** Independent seeded PRNG (different seed than the fixture generator). */
function mulberry32(seed: number) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x9e3779b9) | 0;
    let t = Math.imul(a ^ (a >>> 16), 0x21f0aaad);
    t = Math.imul(t ^ (t >>> 15), 0x735a2d97);
    return ((t ^= t >>> 15) >>> 0) / 4294967296;
  };
}
function noise(n: number, seed = 0x5eed): Buffer {
  const rand = mulberry32(seed);
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) b[i] = Math.floor(rand() * 256);
  return b;
}

const SBOX = patternOf('aes-sbox'); // 256 bytes
const SIGMA = patternOf('chacha-sigma'); // 16 bytes

describe('constant placement boundaries', () => {
  it('constant at offset 0 is found', () => {
    const buffer = Buffer.concat([SBOX, noise(64)]);
    const f = scanBuffer(buffer, SIGNATURES).find((x) => x.signatureId === 'aes-sbox');
    expect(f?.offsets).toEqual([0]);
  });

  it('constant ending exactly at EOF is found', () => {
    const buffer = Buffer.concat([noise(64), SIGMA]);
    const f = scanBuffer(buffer, SIGNATURES).find((x) => x.signatureId === 'chacha-sigma');
    expect(f?.offsets).toEqual([64]);
  });

  it('a file that IS exactly the constant matches at offset 0', () => {
    const f = scanBuffer(SBOX, SIGNATURES).find((x) => x.signatureId === 'aes-sbox');
    expect(f?.offsets).toEqual([0]);
  });

  it('constant shifted by one byte still matches at its exact offset', () => {
    const buffer = Buffer.concat([Buffer.alloc(1, 0x00), SIGMA, Buffer.alloc(1, 0x00)]);
    const f = scanBuffer(buffer, SIGNATURES).find((x) => x.signatureId === 'chacha-sigma');
    expect(f?.offsets).toEqual([1]);
  });

  it('two different constants back to back are both found at exact offsets', () => {
    const inv = patternOf('aes-sbox-inverse');
    const buffer = Buffer.concat([noise(16), SBOX, inv, noise(16)]);
    const findings = scanBuffer(buffer, SIGNATURES);
    expect(findings.find((x) => x.signatureId === 'aes-sbox')?.offsets).toEqual([16]);
    expect(findings.find((x) => x.signatureId === 'aes-sbox-inverse')?.offsets).toEqual([272]);
  });

  it('a pattern longer than the buffer is skipped without error', () => {
    const buffer = noise(100);
    expect(scanBuffer(buffer, SIGNATURES)).toHaveLength(0);
    const tiny = Buffer.concat([SIGMA.subarray(0, 4), noise(10)]); // 4-byte TEA-size match zone
    const findings = scanBuffer(tiny, SIGNATURES);
    // 14 random bytes cannot legitimately match anything; if they do, it is a bug
    expect(findings).toHaveLength(0);
  });
});

describe('degenerate inputs', () => {
  it('1-byte and 3-byte files: no findings, no crash', () => {
    expect(scanBuffer(Buffer.from([0x9e]), SIGNATURES)).toHaveLength(0);
    expect(scanBuffer(Buffer.from([0x9e, 0x37, 0x79]), SIGNATURES)).toHaveLength(0);
  });

  it('empty buffer: no findings', () => {
    expect(scanBuffer(Buffer.alloc(0), SIGNATURES)).toHaveLength(0);
  });
});

describe('scanner options', () => {
  it('maxMatchesPerSignature caps offsets and flags truncation', () => {
    const buffer = Buffer.concat(Array(10).fill(SIGMA));
    const findings = scanBuffer(buffer, SIGNATURES, { maxMatchesPerSignature: 3 });
    const f = findings.find((x) => x.signatureId === 'chacha-sigma');
    expect(f?.offsets).toHaveLength(3);
    expect(f?.truncated).toBe(true);
    expect(f?.matchCount).toBe(3);
  });

  it('contextBytes: 0 yields the tightest context, default captures neighbors', () => {
    const buffer = Buffer.concat([Buffer.alloc(32, 0x41), SIGMA, Buffer.alloc(32, 0x42)]);
    const tight = scanBuffer(buffer, SIGNATURES, { contextBytes: 0 }).find(
      (x) => x.signatureId === 'chacha-sigma'
    );
    const normal = scanBuffer(buffer, SIGNATURES).find(
      (x) => x.signatureId === 'chacha-sigma'
    );
    expect(tight!.contextHex.length).toBeLessThanOrEqual(2 * SIGMA.length * 2);
    expect(normal!.contextHex).toContain('41414141');
    expect(normal!.contextHex).toContain('42424242');
  });

  it('offsets are sorted ascending even when matches are found out of order', () => {
    // two patterns of the same signature (BE at high offset, LE at low offset)
    const be = patternOf('sha256-iv', 0);
    const le = patternOf('sha256-iv', 1);
    const buffer = Buffer.concat([noise(8), le, noise(8), be, noise(8)]);
    const f = scanBuffer(buffer, SIGNATURES).find((x) => x.signatureId === 'sha256-iv');
    expect(f?.offsets).toEqual([...(f?.offsets ?? [])].sort((a, b) => a - b));
    expect(f?.offsets).toEqual([8, 8 + le.length + 8]);
  });
});

describe('performance regression guard', () => {
  it('2 MB of seeded noise scans with zero findings in under 5 seconds', () => {
    const buffer = noise(2 * 1024 * 1024, 0xf00d);
    const start = performance.now();
    const findings = scanBuffer(buffer, SIGNATURES);
    const elapsed = performance.now() - start;
    expect(findings).toHaveLength(0);
    // Generous bound: catches accidental O(n^2) blowups, passes on any CI runner.
    expect(elapsed, `scan took ${elapsed.toFixed(0)} ms`).toBeLessThan(5000);
  });
});
