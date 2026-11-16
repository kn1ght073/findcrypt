import { stat, readFile } from 'node:fs/promises';
import { FindcryptError } from './errors.js';
import {
  scanBuffer as findSignatures,
  type ScannerOptions
} from './core/scanner.js';
import { entropyProfile } from './core/entropy.js';
import { extractStrings, type StringsOptions } from './core/strings.js';
import { disambiguate, inferVerdicts } from './inference/engine.js';
import { VERDICT_RULES } from './inference/rules.js';
import { SIGNATURES } from './signatures/db.js';
import { TOOL_NAME, TOOL_VERSION } from './version.js';
import type { ScanMeta, ScanOptions, ScanResult } from './result.js';

export {
  FindcryptError
} from './errors.js';
export {
  Category
} from './signatures/categories.js';
export type { SignatureEntry, Finding } from './signatures/types.js';
export type { Verdict, VerdictRule, Confidence } from './inference/types.js';
export type { StringFinding } from './core/strings.js';
export type { EntropyReport, WindowEntropy } from './core/entropy.js';
export type { ScanOptions, ScanMeta, ScanResult } from './result.js';
export {
  shannonEntropy,
  classifyEntropy
} from './core/entropy.js';
export { extractStrings } from './core/strings.js';
export { scanBuffer as findSignatureMatches, normalizeHex } from './core/scanner.js';
export { SIGNATURES } from './signatures/db.js';
export { VERDICT_RULES } from './inference/rules.js';
export { disambiguate, inferVerdicts } from './inference/engine.js';
export { TOOL_NAME, TOOL_VERSION } from './version.js';

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
