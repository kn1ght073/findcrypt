import { stat, readFile } from 'node:fs/promises';
import { FindcryptError } from './errors.js';
import {
  scanBuffer as findSignatures,
  type ScannerOptions
} from './core/scanner.js';
import { entropyProfile, type EntropyReport } from './core/entropy.js';
import { extractStrings, type StringsOptions, type StringFinding } from './core/strings.js';
import { disambiguate, inferVerdicts } from './inference/engine.js';
import { VERDICT_RULES } from './inference/rules.js';
import { SIGNATURES } from './signatures/db.js';
import { TOOL_NAME, TOOL_VERSION } from './version.js';
import type { Finding } from './signatures/types.js';
import type { Verdict } from './inference/types.js';

export { FindcryptError } from './errors.js';
export { Category } from './signatures/categories.js';
export type { SignatureEntry, Finding } from './signatures/types.js';
export type { Verdict, VerdictRule, Confidence } from './inference/types.js';
export type { StringFinding };
export type { EntropyReport, WindowEntropy } from './core/entropy.js';
export { scanBuffer as findSignatureMatches, normalizeHex } from './core/scanner.js';
export { SIGNATURES } from './signatures/db.js';
export { VERDICT_RULES } from './inference/rules.js';
export { disambiguate, inferVerdicts } from './inference/engine.js';
export { TOOL_NAME, TOOL_VERSION } from './version.js';

/** Options accepted by the public scan API. */
export interface ScanOptions {
  /** Skip string extraction (default: extract). */
  includeStrings?: boolean;
  /** Minimum printable-run length for extracted strings (default 4). */
  minStringLength?: number;
  /** Hard cap on reported strings (default 5000). */
  maxStrings?: number;
  /** Sliding-window size in bytes for entropy profiling (default 4096). */
  entropyWindowSize?: number;
  /** Cap on sampled entropy windows (default 64). */
  maxEntropyWindows?: number;
  /** Cap on matches reported per signature (default 64). */
  maxMatchesPerSignature?: number;
}

/** Optional metadata about the scanned buffer (e.g. originating path). */
export interface ScanMeta {
  path?: string;
  size?: number;
}

/** The complete, structured result of one scan. */
export interface ScanResult {
  tool: string;
  version: string;
  file?: string;
  size: number;
  /** Wall-clock duration of the scan in milliseconds. */
  durationMs: number;
  entropy: EntropyReport;
  findings: Finding[];
  verdicts: Verdict[];
  strings: StringFinding[];
}

/** Input files larger than this are rejected (documented limitation). */
export const MAX_FILE_BYTES = 256 * 1024 * 1024;

/**
 * Full pipeline over an in-memory buffer: signature scan, disambiguation,
 * entropy profile, string extraction and verdict inference.
 */
export function scanBuffer(
  buffer: Buffer,
  options: ScanOptions & ScannerOptions & StringsOptions = {},
  meta: ScanMeta = {}
): ScanResult {
  const start = performance.now();

  const findings = disambiguate(
    findSignatures(buffer, SIGNATURES, options),
    SIGNATURES
  );
  const entropy = entropyProfile(buffer, {
    windowSize: options.entropyWindowSize,
    maxWindows: options.maxEntropyWindows
  });
  const strings =
    options.includeStrings === false
      ? []
      : extractStrings(buffer, {
          minLength: options.minStringLength,
          maxStrings: options.maxStrings
        });
  const verdicts = inferVerdicts(findings, entropy, VERDICT_RULES);

  return {
    tool: TOOL_NAME,
    version: TOOL_VERSION,
    file: meta.path,
    size: meta.size ?? buffer.length,
    durationMs: performance.now() - start,
    entropy,
    findings,
    verdicts,
    strings
  };
}

/**
 * Scan a file from disk. Enforces the 256 MB memory cap with a clear
 * operational error; resolves with a complete ScanResult.
 */
export async function scanFile(
  filePath: string,
  options: ScanOptions & ScannerOptions & StringsOptions = {}
): Promise<ScanResult> {
  let info;
  try {
    info = await stat(filePath);
  } catch {
    throw new FindcryptError(`File not found: ${filePath}`, 'ERR_FILE_NOT_FOUND');
  }
  if (!info.isFile()) {
    throw new FindcryptError(
      `Not a regular file: ${filePath} (directories are not scanned)`,
      'ERR_NOT_A_FILE'
    );
  }
  if (info.size > MAX_FILE_BYTES) {
    throw new FindcryptError(
      `File exceeds the ${Math.floor(MAX_FILE_BYTES / (1024 * 1024))} MB memory cap (${filePath}). ` +
        'Split the file or target offsets with a hex editor.',
      'ERR_FILE_TOO_LARGE'
    );
  }
  const buffer = await readFile(filePath);
  return scanBuffer(buffer, options, { path: filePath, size: info.size });
}
