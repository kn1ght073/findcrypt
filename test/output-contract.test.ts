import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

/**
 * The OUTPUT CONTRACT: the exact shape of --json and --markdown output.
 * These formats are the tool's public interface — CI pipelines, jq filters
 * and reports consume them, so every field must exist, every offset must be
 * in bounds, and machine output must stay byte-clean (no ANSI escapes even
 * when the process thinks it is attached to a color terminal).
 */

const CLI = 'dist/cli/main.js';
const hasBuild = existsSync(CLI);

function runCli(args: string[], env: Record<string, string> = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 120_000,
    env: { ...process.env, ...env }
  });
}

const ANSI = /\u001b/;

interface JsonFinding {
  signatureId: string;
  name: string;
  algorithm: string;
  category: string;
  matchLength: number;
  offsets: number[];
  matchCount: number;
  truncated: boolean;
  contextHex: string;
}

interface JsonReport {
  tool: string;
  version: string;
  file?: string;
  size: number;
  durationMs: number;
  entropy: { fileEntropy: number; windows: unknown[]; peak: unknown; classification: string };
  findings: JsonFinding[];
  verdicts: { ruleId: string; label: string; confidence: string; explanation: string }[];
  strings: { offset: number; encoding: string; text: string }[];
}

describe.skipIf(!hasBuild)('JSON output contract', () => {
  const FILE = 'test/fixtures/scenario-wallet.bin';
  const r = runCli(['--json', FILE], { FORCE_COLOR: '1', NO_COLOR: '' });
  const report: JsonReport = JSON.parse(r.stdout);

  it('exit 0 and top-level envelope is complete', () => {
    expect(r.status).toBe(0);
    expect(report.tool).toBe('findcrypt');
    expect(report.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(report.file).toBe(FILE);
    expect(report.size).toBe(statSync(FILE).size);
    expect(report.durationMs).toBeGreaterThanOrEqual(0);
    expect(Array.isArray(report.entropy.windows)).toBe(true);
    expect(typeof report.entropy.classification).toBe('string');
  });

  it('every finding carries the full schema with in-bounds, ascending offsets', () => {
    expect(report.findings.length).toBeGreaterThan(0);
    for (const f of report.findings) {
      expect(f.signatureId).toMatch(/^[a-z0-9-]+$/);
      expect(f.name.length).toBeGreaterThan(0);
      expect(f.algorithm.length).toBeGreaterThan(0);
      expect(['SYMMETRIC', 'ASYMMETRIC', 'HASH', 'ENCODING', 'CHECKSUM']).toContain(f.category);
      expect(f.matchLength).toBeGreaterThan(0);
      expect(f.offsets.length).toBeGreaterThan(0);
      expect(f.matchCount).toBe(f.offsets.length);
      expect(f.offsets).toEqual([...f.offsets].sort((a, b) => a - b));
      for (const o of f.offsets) {
        expect(o).toBeGreaterThanOrEqual(0);
        expect(o + f.matchLength).toBeLessThanOrEqual(report.size);
      }
      expect(f.contextHex).toMatch(/^[0-9a-f]*$/);
      expect(f.contextHex.length % 2).toBe(0);
    }
  });

  it('verdicts carry ruleId/label/confidence/explanation', () => {
    expect(report.verdicts.length).toBeGreaterThan(0);
    for (const v of report.verdicts) {
      expect(v.ruleId).toMatch(/^[a-z0-9-]+$/);
      expect(v.label.length).toBeGreaterThan(0);
      expect(['HIGH', 'MEDIUM', 'LOW']).toContain(v.confidence);
      expect(v.explanation.length).toBeGreaterThan(0);
    }
  });

  it('strings carry offset/encoding/text', () => {
    expect(report.strings.length).toBeGreaterThan(0);
    for (const s of report.strings) {
      expect(s.offset).toBeGreaterThanOrEqual(0);
      expect(['ascii', 'utf16le']).toContain(s.encoding);
      expect(typeof s.text).toBe('string');
    }
  });

  it('NO ANSI escape sequences anywhere in --json, even with FORCE_COLOR', () => {
    expect(r.stdout).not.toMatch(ANSI);
    expect(r.stderr).not.toMatch(ANSI);
  });

  it('output is valid UTF-8 JSON with no trailing garbage', () => {
    expect(() => JSON.parse(r.stdout)).not.toThrow();
    expect(r.stdout.trimEnd() + '\n').toBe(r.stdout);
  });
});

describe.skipIf(!hasBuild)('Markdown output contract', () => {
  it('renders a fingerprint table with one row per finding and a verdicts section', () => {
    const r = runCli(['--markdown', 'test/fixtures/scenario-legacy.bin']);
    expect(r.status).toBe(0);
    const out = r.stdout;
    expect(out).toContain('## findcrypt report');
    expect(out).toContain('| Signature | Category | Size | Offsets |');
    expect(out).toContain('|---|---|---|---|');
    expect(out).toContain('### Verdicts');
    expect(out).toContain('Obsolete cryptography');
    // three findings -> three table rows beyond the header
    const rows = out.split('\n').filter((l) => l.startsWith('| ') && !l.startsWith('| Sign'));
    expect(rows.length).toBe(3);
  });

  it('markdown stays ANSI-clean too', () => {
    const r = runCli(['--markdown', 'test/fixtures/scenario-legacy.bin'], { FORCE_COLOR: '1' });
    expect(r.stdout).not.toMatch(ANSI);
  });
});

describe.skipIf(!hasBuild)('dual-format package: ESM and CJS interop', () => {
  it('dist/index.cjs is requireable and exports a working scanBuffer', () => {
    const r = spawnSync(
      process.execPath,
      [
        '-e',
        `const fc = require('./dist/index.cjs');
         const buf = require('fs').readFileSync('test/fixtures/scenario-wallet.bin');
         const res = fc.scanBuffer(buf);
         if (res.findings.some(f => f.signatureId === 'secp256k1-generator')) {
           console.log('cjs-ok');
         } else { throw new Error('no finding via CJS build'); }`
      ],
      { encoding: 'utf8', timeout: 60_000 }
    );
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout.trim()).toBe('cjs-ok');
  });

  it('the version exported by the library matches package.json', () => {
    const r = spawnSync(
      process.execPath,
      ['-e', `console.log(require('./dist/index.cjs').TOOL_VERSION)`],
      { encoding: 'utf8' }
    );
    const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
    expect(r.stdout.trim()).toBe(pkg.version);
  });
});
