import type { ScanResult } from '../result.js';

/** Stable, machine-readable JSON report. */
export function toJSON(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
