import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { scanBuffer } from '../src/index.js';

/**
 * Verdict inference, end-to-end. The scenario fixtures combine several
 * constants the way real binaries do; these tests pin what an analyst should
 * be told for each case — including confidence ordering (HIGH first) and the
 * no-crypto / packed distinction, which is the tool's most valuable call.
 */

interface ScenarioCase {
  file: string;
  findings: string[];
  verdicts: string[];
  minEntropy?: number;
  maxEntropy?: number;
}

const CASES: ScenarioCase[] = [
  {
    file: 'scenario-wallet.bin',
    findings: ['secp256k1-generator', 'sha256-iv', 'base64-alphabet'],
    verdicts: ['wallet-crypto', 'sha2-modern', 'crypto-present', 'base64-layer']
  },
  {
    file: 'scenario-legacy.bin',
    findings: ['des-sbox', 'md5-t-table', 'md5-iv'],
    verdicts: ['legacy-hash', 'crypto-present']
  },
  {
    file: 'scenario-arx.bin',
    findings: ['chacha-sigma', 'salsa-sigma'],
    verdicts: ['arx-stream', 'crypto-present']
  },
  {
    file: 'scenario-packed.bin',
    findings: [],
    verdicts: ['packed-or-custom'],
    minEntropy: 7.9
  },
  {
    file: 'scenario-plaintext.txt',
    findings: [],
    verdicts: [],
    maxEntropy: 5.5
  }
];

const CLI = 'dist/cli/main.js';

function runCli(args: string[]) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 60_000 });
}

describe('verdict inference on scenario fixtures (library API)', () => {
  for (const c of CASES) {
    it(`${c.file}: ${c.findings.length} signatures -> [${c.verdicts.join(', ') || 'no verdicts'}]`, () => {
      const buffer = readFileSync(`test/fixtures/${c.file}`);
      const result = scanBuffer(buffer);

      const foundIds = result.findings.map((f) => f.signatureId);
      for (const id of c.findings) expect(foundIds).toContain(id);

      const ruleIds = result.verdicts.map((v) => v.ruleId);
      expect(ruleIds).toEqual(c.verdicts); // exactly these verdicts, nothing speculative

      if (c.minEntropy !== undefined) {
        expect(result.entropy.fileEntropy).toBeGreaterThanOrEqual(c.minEntropy);
      }
      if (c.maxEntropy !== undefined) {
        expect(result.entropy.fileEntropy).toBeLessThanOrEqual(c.maxEntropy);
      }
    });
  }

  it('verdicts are ordered HIGH -> MEDIUM -> LOW', () => {
    const result = scanBuffer(readFileSync('test/fixtures/scenario-wallet.bin'));
    const rank = { HIGH: 0, MEDIUM: 1, LOW: 2 } as const;
    const confidences = result.verdicts.map((v) => rank[v.confidence]);
    expect(confidences).toEqual([...confidences].sort((a, b) => a - b));
  });

  it('every scenario fixture is documented in scenarios.json', () => {
    const meta = JSON.parse(readFileSync('test/fixtures/scenarios.json', 'utf8'));
    for (const c of CASES) {
      expect(meta[c.file]?.description, `${c.file} missing from scenarios.json`).toBeTruthy();
    }
  });
});

describe('verdicts through the CLI', () => {
  it('wallet scenario: exit 0, JSON carries the wallet verdict', () => {
    const r = runCli(['--json', 'test/fixtures/scenario-wallet.bin']);
    expect(r.status).toBe(0);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.verdicts.map((v: { ruleId: string }) => v.ruleId)).toContain('wallet-crypto');
    expect(parsed.findings.map((f: { signatureId: string }) => f.signatureId)).toContain(
      'secp256k1-generator'
    );
  });

  it('packed scenario: exit 1 (no fingerprints) but the packed verdict is still reported', () => {
    const r = runCli(['--json', 'test/fixtures/scenario-packed.bin']);
    expect(r.status).toBe(1); // no fingerprints — but the analyst still gets a lead
    const parsed = JSON.parse(r.stdout);
    expect(parsed.findings).toHaveLength(0);
    expect(parsed.verdicts.map((v: { ruleId: string }) => v.ruleId)).toContain('packed-or-custom');
  });

  it('plaintext scenario: exit 1, no verdicts, low-entropy classification', () => {
    const r = runCli(['--json', 'test/fixtures/scenario-plaintext.txt']);
    expect(r.status).toBe(1);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.findings).toHaveLength(0);
    expect(parsed.verdicts).toHaveLength(0);
    expect(parsed.entropy.classification).toMatch(/text|structured/i);
  });

  it('terminal mode names the verdict for humans', () => {
    const r = runCli(['test/fixtures/scenario-legacy.bin']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('Obsolete cryptography');
  });
});
