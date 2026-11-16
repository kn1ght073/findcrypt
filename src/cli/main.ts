#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import {
  scanBuffer,
  scanFile,
  FindcryptError,
  TOOL_VERSION,
  type ScanResult
} from '../index.js';
import { toTerminal } from '../report/terminal.js';
import { toJSON } from '../report/json.js';
import { toMarkdown } from '../report/markdown.js';

interface CliArgs {
  paths: string[];
  json: boolean;
  markdown: boolean;
  noStrings: boolean;
  minStrLen: number;
  minEntropy: number | null;
  version: boolean;
  help: boolean;
}

const USAGE = `findcrypt v${TOOL_VERSION} — find cryptographic fingerprints in any file

Usage:
  findcrypt <file> [more files...] [options]
  cat sample.bin | findcrypt -

Options:
  --json               machine-readable JSON report
  --markdown           GitHub-flavored Markdown report
  --min-entropy <n>    only report files with entropy >= n (0-8)
  --no-strings         skip string extraction
  --min-str-len <n>    minimum string length (default 4)
  --version            print version
  --help               show this help

Exit codes:
  0  fingerprints found
  1  no fingerprints found
  2  operational error (missing file, oversized input, bad flag)

Examples:
  npx findcrypt ./sample.bin
  findcrypt ./malware/*.bin --json
  findcrypt /usr/bin/node --min-entropy 6.5`;

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    paths: [],
    json: false,
    markdown: false,
    noStrings: false,
    minStrLen: 4,
    minEntropy: null,
    version: false,
    help: false
  };

  let i = 0;
  while (i < argv.length) {
    const arg = argv[i];
    switch (arg) {
      case '--json':
        args.json = true;
        break;
      case '--markdown':
        args.markdown = true;
        break;
      case '--no-strings':
        args.noStrings = true;
        break;
      case '--version':
        args.version = true;
        break;
      case '--help':
      case '-h':
        args.help = true;
        break;
      case '--min-str-len': {
        const value = Number(argv[++i]);
        if (!Number.isInteger(value) || value < 1 || value > 1024) {
          throw new FindcryptError('--min-str-len expects an integer 1-1024', 'ERR_BAD_FLAG');
        }
        args.minStrLen = value;
        break;
      }
      case '--min-entropy': {
        const value = Number(argv[++i]);
        if (Number.isNaN(value) || value < 0 || value > 8) {
          throw new FindcryptError('--min-entropy expects a number 0-8', 'ERR_BAD_FLAG');
        }
        args.minEntropy = value;
        break;
      }
      default:
        if (arg.startsWith('--')) {
          throw new FindcryptError(`Unknown option: ${arg} (see --help)`, 'ERR_BAD_FLAG');
        }
        args.paths.push(arg);
    }
    i++;
  }
  return args;
}

function render(
  results: ScanResult[],
  format: 'terminal' | 'json' | 'markdown'
): string {
  if (format === 'json') {
    const payload = results.length === 1 ? results[0] : { results };
    return toJSON(payload as unknown as ScanResult);
  }
  const sections = results.map((r) =>
    format === 'markdown' ? toMarkdown(r) : toTerminal(r)
  );
  return sections.join(format === 'markdown' ? '\n\n---\n\n' : '\n\n');
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    process.stdout.write(USAGE + '\n');
    return 0;
  }
  if (args.version) {
    process.stdout.write(`${TOOL_VERSION}\n`);
    return 0;
  }
  if (args.paths.length === 0) {
    process.stderr.write('No input file given. Usage:\n\n' + USAGE + '\n');
    return 2;
  }

  const format = args.json ? 'json' : args.markdown ? 'markdown' : 'terminal';
  const results: ScanResult[] = [];

  for (const p of args.paths) {
    let result: ScanResult;
    if (p === '-') {
      const stdin = readFileSync(0);
      result = scanBuffer(stdin, {
        includeStrings: !args.noStrings,
        minStringLength: args.minStrLen
      });
      result.file = '<stdin>';
    } else {
      result = await scanFile(p, {
        includeStrings: !args.noStrings,
        minStringLength: args.minStrLen
      });
    }
    if (args.minEntropy !== null && result.entropy.fileEntropy < args.minEntropy) {
      if (format === 'terminal') {
        process.stderr.write(
          `skipped ${p} (entropy ${result.entropy.fileEntropy.toFixed(3)} < ${args.minEntropy})\n`
        );
      }
      continue;
    }
    results.push(result);
  }

  if (format === 'json' && results.length === 0) {
    process.stdout.write('[]\n');
    return 1;
  }

  const output = render(results, format);
  process.stdout.write(output + '\n');

  return results.some((r) => r.findings.length > 0) ? 0 : 1;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    if (err instanceof FindcryptError) {
      process.stderr.write(`findcrypt: ${err.message}\n`);
    } else if (err instanceof Error && (err as NodeJS.ErrnoException).code === 'ENOENT') {
      process.stderr.write('findcrypt: file not found\n');
    } else {
      process.stderr.write(`findcrypt: unexpected error — ${(err as Error).message}\n`);
    }
    process.exitCode = 2;
  });
