import { describe, it, expect, afterAll } from 'vitest';
import { existsSync, mkdtempSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

/**
 * The flag matrix and every operational error path. The smoke suite covers
 * the happy paths; this file tries to BREAK the CLI the way real users do:
 * bad values, missing values, directories, unreadable files, unicode names,
 * contradictory flags, and multi-file runs with mixed results.
 */

const CLI = 'dist/cli/main.js';
const hasBuild = existsSync(CLI);

function runCli(args: string[], input?: Buffer) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 120_000,
    input
  });
}

const SCRATCH = mkdtempSync(join(tmpdir(), 'findcrypt-cli-'));
afterAll(() => rmSync(SCRATCH, { recursive: true, force: true }));

describe.skipIf(!hasBuild)('CLI flag matrix', () => {
  it('multiple files with mixed results: exit 0 and both files reported', () => {
    const r = runCli([
      'test/fixtures/fixture-tea-delta.bin',
      'test/fixtures/noise.bin'
    ]);
    expect(r.status).toBe(0); // at least one file has findings
    expect(r.stdout).toContain('fixture-tea-delta.bin');
    expect(r.stdout).toContain('noise.bin');
  });

  it('multiple files with --json wrap results in { results: [...] }', () => {
    const r = runCli([
      '--json',
      'test/fixtures/fixture-tea-delta.bin',
      'test/fixtures/noise.bin'
    ]);
    expect(r.status).toBe(0);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.results).toHaveLength(2);
    expect(parsed.results[0].findings.length).toBeGreaterThan(0);
    expect(parsed.results[1].findings).toHaveLength(0);
  });

  it('single file with --json stays a plain object (no wrapper)', () => {
    const r = runCli(['--json', 'test/fixtures/fixture-tea-delta.bin']);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.results).toBeUndefined();
    expect(parsed.findings).toBeDefined();
  });

  it('--json beats --markdown when both are given', () => {
    const r = runCli(['--json', '--markdown', 'test/fixtures/fixture-tea-delta.bin']);
    expect(() => JSON.parse(r.stdout)).not.toThrow();
  });

  it('--min-entropy filters out low-entropy files: JSON [] and exit 1', () => {
    const r = runCli(['--json', '--min-entropy', '8', 'test/fixtures/noise.bin']);
    // noise entropy is ~8 but has no findings... it should NOT be filtered by
    // entropy (7.99 < 8.0 fails the filter) — exit 1 with []
    expect(r.status).toBe(1);
    expect(r.stdout.trim()).toBe('[]');
  });

  it('--min-entropy in terminal mode explains the skip on stderr', () => {
    const r = runCli(['--min-entropy', '8', 'test/fixtures/scenario-plaintext.txt']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('skipped');
    expect(r.stderr).toContain('scenario-plaintext.txt');
  });

  it('--min-entropy accepts a valid fractional threshold', () => {
    const r = runCli(['--min-entropy', '6.0', 'test/fixtures/scenario-wallet.bin']);
    expect(r.status).toBe(0);
  });

  const BAD_FLAG_CASES: Array<[string, string?]> = [
    ['--min-entropy', '9'], // above 8
    ['--min-entropy', '-1'], // negative
    ['--min-entropy', 'abc'], // not a number
    ['--min-entropy'], // missing value
    ['--min-str-len', '0'], // below 1
    ['--min-str-len', '1025'], // above 1024
    ['--min-str-len'], // missing value
    ['--frobnicate'] // unknown flag
  ];
  for (const [flag, value] of BAD_FLAG_CASES) {
    it(`${[flag, value].filter((x) => x !== undefined).join(' ')} is rejected with exit 2`, () => {
      const args = value === undefined ? [flag] : [flag, value];
      const r = runCli(args);
      expect(r.status, `expected exit 2 for: ${args.join(' ')}`).toBe(2);
      expect(r.stderr).toContain('findcrypt');
    });
  }

  it('--min-str-len 8 is accepted and affects string extraction', () => {
    const r = runCli(['--json', '--min-str-len', '8', 'test/fixtures/scenario-wallet.bin']);
    expect(r.status).toBe(0);
    const parsed = JSON.parse(r.stdout);
    for (const s of parsed.strings) expect(s.text.length).toBeGreaterThanOrEqual(8);
  });

  it('--no-strings omits string extraction in JSON', () => {
    const r = runCli(['--json', '--no-strings', 'test/fixtures/scenario-wallet.bin']);
    expect(r.status).toBe(0);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.strings).toHaveLength(0);
  });

  it('-h is an alias for --help', () => {
    const r = runCli(['-h']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('Usage:');
  });
});

describe.skipIf(!hasBuild)('CLI operational error paths', () => {
  it('no arguments: exit 2 with usage on stderr', () => {
    const r = runCli([]);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('Usage');
  });

  it('directory as input: exit 2, directories are not scanned', () => {
    const r = runCli([SCRATCH]);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/directory|regular file|not a/i);
  });

  it('missing file: exit 2 with a clear message', () => {
    const r = runCli(['no/such/file.bin']);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('findcrypt');
  });

  it('unicode filenames are handled', () => {
    const path = join(SCRATCH, 'malware-样本-🔬.bin');
    writeFileSync(path, Buffer.from('657870616e642033322d62797465206b', 'hex'));
    const r = runCli([path]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('ChaCha');
  });

  it.skipIf(process.platform === 'win32')(
    'unreadable file (chmod 000): exit 2, not a crash',
    () => {
      const path = join(SCRATCH, 'secret.bin');
      writeFileSync(path, Buffer.alloc(64, 0x41));
      chmodSync(path, 0o000);
      try {
        const r = runCli([path]);
        expect(r.status).toBe(2);
        expect(r.stderr).toContain('findcrypt');
      } finally {
        chmodSync(path, 0o644); // let afterAll cleanup remove it
      }
    }
  );

  it('stdin via - with a sigma constant: exit 0', () => {
    const r = runCli(['-'], Buffer.from('657870616e642033322d62797465206b', 'hex'));
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('ChaCha');
  });

  it('bare -- is treated as an unknown option (exit 2)', () => {
    // Documents current behavior: POSIX end-of-options is NOT special-cased.
    const r = runCli(['--']);
    expect(r.status).toBe(2);
  });
});
