import type { EntropyReport } from './core/entropy.js';
import type { Finding } from './signatures/types.js';
import type { StringFinding } from './core/strings.js';
import type { Verdict } from './inference/types.js';

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
