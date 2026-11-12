import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  shannonEntropy,
  classifyEntropy,
  entropyProfile
} from '../src/core/entropy.js';

describe('shannonEntropy known values', () => {
  it('empty buffer → 0', () => {
    expect(shannonEntropy(Buffer.alloc(0))).toBe(0);
  });

  it('all-zero buffer → 0', () => {
    expect(shannonEntropy(Buffer.alloc(4096))).toBe(0);
  });

  it('perfectly uniform buffer → exactly 8 bits/byte', () => {
    const buffer = Buffer.alloc(4096);
    for (let i = 0; i < 4096; i++) buffer[i] = i % 256;
    expect(shannonEntropy(buffer)).toBeCloseTo(8.0, 10);
  });

  it('two symbols → exactly 1 bit', () => {
    const buffer = Buffer.from('0101010101010101'.repeat(32), 'latin1');
    expect(shannonEntropy(buffer)).toBeCloseTo(1.0, 10);
  });

  it('seeded random noise lands near 8 bits/byte', () => {
    const noise = readFileSync('test/fixtures/noise.bin');
    expect(shannonEntropy(noise)).toBeGreaterThan(7.5);
  });
});

describe('classifyEntropy', () => {
  it('buckets the canonical ranges', () => {
    expect(classifyEntropy(0)).toContain('low');
    expect(classifyEntropy(3)).toContain('mixed');
    expect(classifyEntropy(6.0)).toContain('machine code');
    expect(classifyEntropy(7.0)).toContain('compressed');
    expect(classifyEntropy(7.95)).toContain('encrypted');
  });
});

describe('entropyProfile windows', () => {
  it('empty buffer: no windows, null peak', () => {
    const profile = entropyProfile(Buffer.alloc(0));
    expect(profile.windows).toHaveLength(0);
    expect(profile.peak).toBeNull();
  });

  it('single-window file: one window at offset 0', () => {
    const profile = entropyProfile(Buffer.alloc(100, 0x41));
    expect(profile.windows).toHaveLength(1);
    expect(profile.windows[0]!.offset).toBe(0);
  });

  it('localizes a high-entropy region in an otherwise uniform file', () => {
    const noise = readFileSync('test/fixtures/noise.bin'); // 4096 bytes ≈ 8.0
    const buffer = Buffer.concat([Buffer.alloc(4096, 0x00), noise.subarray(0, 4096)]);
    const profile = entropyProfile(buffer, { windowSize: 1024, maxWindows: 16 });
    expect(profile.peak).not.toBeNull();
    expect(profile.peak!.offset).toBeGreaterThanOrEqual(4096);
    expect(profile.peak!.entropy).toBeGreaterThan(7.5);
    expect(profile.windows[0]!.entropy).toBe(0);
  });

  it('strides sampling for large files (window cap respected)', () => {
    const buffer = Buffer.alloc(4096 * 200, 0x61); // 800 KB of 'a'
    const profile = entropyProfile(buffer, { windowSize: 4096, maxWindows: 64 });
    expect(profile.windows.length).toBeLessThanOrEqual(64);
  });
});
