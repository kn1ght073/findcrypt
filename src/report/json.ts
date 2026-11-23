import type { ScanResult } from '../index.js';

/** Stable, machine-readable JSON report. */
export function toJSON(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
