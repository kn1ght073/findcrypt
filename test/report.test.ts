import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { scanBuffer } from '../src/index.js';
import { toTerminal, supportsColor } from '../src/report/terminal.js';
import { toJSON } from '../src/report/json.js';
import { toMarkdown } from '../src/report/markdown.js';

const fixture = readFileSync('test/fixtures/fixture-aes-sbox.bin');
const result = scanBuffer(fixture, { includeStrings: false });

describe('terminal report', () => {
  it('names the algorithm and the planted offset', () => {
    const text = toTerminal(result, { color: false });
    expect(text).toContain('AES S-Box');
    expect(text).toContain('0x00000100');
    expect(text).toContain('Table-driven AES implementation');
    expect(text).toContain('Entropy:');
    expect(text).not.toContain('\u001b');
  });

  it('emits ANSI color when requested', () => {
    const text = toTerminal(result, { color: true });
    expect(text).toContain('\u001b');
  });

  it('no-findings scan prints "none found"', () => {
    const noise = readFileSync('test/fixtures/noise.bin');
    const text = toTerminal(scanBuffer(noise, { includeStrings: false }), { color: false });
    expect(text).toContain('none found');
  });
});

describe('json report', () => {
  it('round-trips through JSON.parse with full structure', () => {
    const parsed = JSON.parse(toJSON(result));
    expect(parsed.tool).toBe('findcrypt');
    expect(parsed.findings[0].signatureId).toBe('aes-sbox');
    expect(parsed.findings[0].offsets).toContain(256);
    expect(parsed.entropy.fileEntropy).toBeGreaterThan(0);
    expect(Array.isArray(parsed.verdicts)).toBe(true);
  });
});

describe('markdown report', () => {
  it('renders a GFM table with the finding', () => {
    const md = toMarkdown(result);
    expect(md).toContain('## findcrypt report');
    expect(md).toContain('| AES S-Box | SYMMETRIC |');
    expect(md).toContain('### Verdicts');
  });
});

describe('NO_COLOR convention', () => {
  it('supportsColor() respects NO_COLOR', () => {
    const before = process.env['NO_COLOR'];
    process.env['NO_COLOR'] = '1';
    try {
      expect(supportsColor()).toBe(false);
    } finally {
      if (before === undefined) delete process.env['NO_COLOR'];
      else process.env['NO_COLOR'] = before;
    }
  });
});
