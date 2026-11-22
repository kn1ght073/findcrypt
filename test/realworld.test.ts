import { describe, it, expect } from 'vitest';
import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

/**
 * REAL-WORLD TARGETS. Unit fixtures are synthetic; these tests run the tool
 * against software that actually exists on the machine:
 *
 *  - process.execPath — official Node builds statically link OpenSSL, so the
 *    runtime binary itself is full of crypto tables (AES S-boxes, SHA IVs...).
 *    Always available on every OS and CI runner.
 *  - the system libcrypto (OpenSSL) when present — skipped otherwise.
 *  - an ordinary system binary (ls/cat) — must complete cleanly even with no
 *    findings.
 *  - this repository's own fixture generator — its source contains the ASCII
 *    sigma constants and Base64 alphabet as string literals, a self-referential
 *    demonstration that byte signatures also match inside text files.
 */

const CLI = 'dist/cli/main.js';
const hasBuild = existsSync(CLI);

function runCli(args: string[]) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 180_000
  });
}

const LIBCRYPTO_CANDIDATES = [
  '/usr/lib/x86_64-linux-gnu/libcrypto.so.3',
  '/usr/lib/x86_64-linux-gnu/libcrypto.so',
  '/usr/lib/aarch64-linux-gnu/libcrypto.so.3',
  '/usr/lib64/libcrypto.so.3',
  '/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib',
  '/usr/local/opt/openssl@3/lib/libcrypto.3.dylib'
];

describe.skipIf(!hasBuild)('real-world binaries', () => {
  it(
    'the Node runtime itself: exit 0 with multiple distinct signatures',
    { timeout: 240_000 },
    () => {
      const r = runCli(['--json', '--no-strings', process.execPath]);
      expect(r.status, r.stderr).toBe(0);
      const parsed = JSON.parse(r.stdout);
      const ids = parsed.findings.map((f: { signatureId: string }) => f.signatureId);
      expect(ids.length).toBeGreaterThanOrEqual(3); // OpenSSL links plenty of tables
      expect(parsed.verdicts.length).toBeGreaterThan(0);
    }
  );

  it.runIf(LIBCRYPTO_CANDIDATES.some(existsSync))(
    'system libcrypto: AES-family tables detected',
    { timeout: 120_000 },
    () => {
      const lib = LIBCRYPTO_CANDIDATES.find(existsSync)!;
      const r = runCli(['--json', '--no-strings', lib]);
      expect(r.status, r.stderr).toBe(0);
      const parsed = JSON.parse(r.stdout);
      const ids = parsed.findings.map((f: { signatureId: string }) => f.signatureId);
      // Either AES table counts. ARM64 OpenSSL builds encrypt with hardware
      // AES instructions and keep only the inverse (decryption) table —
      // observed on macOS runners with homebrew's libcrypto.3.dylib.
      const aesTables = ids.filter((id: string) => id.startsWith('aes-'));
      expect(aesTables.length).toBeGreaterThanOrEqual(1);
    }
  );

  it.skipIf(!(existsSync('/bin/ls') || existsSync('/bin/cat')))(
    'an ordinary system binary completes cleanly (exit 0 or 1, never 2)',
    { timeout: 120_000 },
    () => {
      const target = existsSync('/bin/ls') ? '/bin/ls' : '/bin/cat';
      const r = runCli(['--json', '--no-strings', target]);
      expect([0, 1], r.stderr).toContain(r.status);
      expect(() => JSON.parse(r.stdout)).not.toThrow();
    }
  );

  it('this repo’s own generator source: ASCII constants match inside a text file', () => {
    // scripts/gen-fixtures.mjs literally contains 'expand 32-byte k' and the
    // Base64 alphabet as string literals — byte signatures do not care that
    // the surrounding file is JavaScript source.
    const r = runCli(['--json', '--no-strings', 'scripts/gen-fixtures.mjs']);
    expect(r.status).toBe(0);
    const parsed = JSON.parse(r.stdout);
    const ids = parsed.findings.map((f: { signatureId: string }) => f.signatureId);
    expect(ids).toContain('chacha-sigma');
    expect(ids).toContain('base64-alphabet');
  });
});
