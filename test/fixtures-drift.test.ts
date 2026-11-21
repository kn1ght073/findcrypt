import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';

/**
 * The committed fixture binaries must be exactly what scripts/gen-fixtures.mjs
 * produces. If someone edits a fixture by hand, or changes the generator (or a
 * constant inside it) without re-running `npm run fixtures`, the whole
 * "fixture proves the database" chain silently rots. `--check` mode fails with
 * a per-file list; this test wires that guard into `npm test` and CI.
 */
describe('fixture drift guard (gen-fixtures --check)', () => {
  it('committed fixtures are byte-identical to a fresh generation', () => {
    const r = spawnSync(process.execPath, ['scripts/gen-fixtures.mjs', '--check'], {
      encoding: 'utf8',
      timeout: 30_000
    });
    expect(r.status, `drift detected:\n${r.stdout}\n${r.stderr}`).toBe(0);
    expect(r.stdout).toContain('OK');
  });

  it('the drift detector actually detects drift (self-test on a tampered copy)', () => {
    // Flip one byte of a fixture in a scratch copy of the tree and confirm
    // --check would flag it. We only verify the guard's logic here by
    // corrupting the real file and restoring it immediately — if anything
    // throws in between, the test fails loudly rather than silently.
    const fs = require('node:fs');
    const path = 'test/fixtures/fixture-tea-delta.bin';
    const original = fs.readFileSync(path);
    try {
      const tampered = Buffer.from(original);
      tampered[300] ^= 0xff;
      fs.writeFileSync(path, tampered);
      const r = spawnSync(process.execPath, ['scripts/gen-fixtures.mjs', '--check'], {
        encoding: 'utf8',
        timeout: 30_000
      });
      expect(r.status).toBe(1);
      expect(r.stderr).toContain('FIXTURE DRIFT DETECTED');
      expect(r.stderr).toContain('fixture-tea-delta.bin');
    } finally {
      fs.writeFileSync(path, original);
    }
    // And the restored state passes again.
    const r2 = spawnSync(process.execPath, ['scripts/gen-fixtures.mjs', '--check'], {
      encoding: 'utf8',
      timeout: 30_000
    });
    expect(r2.status).toBe(0);
  });
});
