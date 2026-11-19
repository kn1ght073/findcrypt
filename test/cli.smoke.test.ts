import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const CLI = 'dist/cli/main.js';
const hasBuild = existsSync(CLI);

function runCli(args: string[]) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 120_000
  });
}

/**
 * Smoke tests run against the BUILT bundle — mirrors what an npm user gets.
 * Skipped locally until `npm run build` has run once; CI always builds first.
 */
describe.skipIf(!hasBuild)('CLI smoke tests (against dist/)', () => {
  it('--help exits 0 with usage text', () => {
    const r = runCli(['--help']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('Usage:');
    expect(r.stdout).toContain('--json');
  });

  it('--version prints the version', () => {
    const r = runCli(['--version']);
    expect(r.status).toBe(0);
    expect(r.stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it('scans a fixture: exit 0, algorithm named, offset reported', () => {
    const r = runCli(['test/fixtures/fixture-tea-delta.bin']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('TEA');
    expect(r.stdout).toContain('0x00000100');
  });

  it('random noise: exit 1, no fingerprints', () => {
    const r = runCli(['test/fixtures/noise.bin']);
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('none found');
  });

  it('empty file: exit 1 (valid JSON when requested)', () => {
    const r = runCli(['--json', 'test/fixtures/empty.bin']);
    expect(r.status).toBe(1);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.findings).toHaveLength(0);
  });

  it('missing file: exit 2 with error on stderr', () => {
    const r = runCli(['does-not-exist.bin']);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('findcrypt:');
  });

  it('--json output parses and contains the verdict block', () => {
    const r = runCli(['--json', 'test/fixtures/fixture-sha256-iv.bin']);
    expect(r.status).toBe(0);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.findings[0].signatureId).toBe('sha256-iv');
    expect(parsed.verdicts.length).toBeGreaterThan(0);
  });

  it('--markdown renders a table row', () => {
    const r = runCli(['--markdown', 'test/fixtures/fixture-chacha-sigma.bin']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('| ChaCha20 Sigma');
  });

  it('stdin via -', () => {
    const r = spawnSync(
      process.execPath,
      [CLI, '-'],
      {
        encoding: 'utf8',
        input: readFileSync('test/fixtures/fixture-blowfish-p-array.bin')
      }
    );
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('Blowfish');
    expect(r.stdout).toContain('<stdin>');
  });

  it('unknown flag: exit 2', () => {
    const r = runCli(['--frobnicate']);
    expect(r.status).toBe(2);
  });
});
