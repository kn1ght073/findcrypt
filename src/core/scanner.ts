import type { Finding, SignatureEntry } from '../signatures/types.js';

export interface ScannerOptions {
  /** Cap on matches reported per signature (default 64). */
  maxMatchesPerSignature?: number;
  /** Bytes of context captured around the first match (default 32). */
  contextBytes?: number;
}

const DEFAULT_MAX_MATCHES = 64;
const DEFAULT_CONTEXT = 32;

/** Strip whitespace/commas and lowercase a hex pattern. */
export function normalizeHex(hex: string): string {
  return hex.replace(/[\s,]+/g, '').toLowerCase();
}

/**
 * Scan a buffer for every signature's patterns.
 *
 * Uses Buffer#indexOf, which is backed by native optimized search — for the
 * current database size (~35 patterns) this outperforms any hand-rolled
 * search in JS while keeping the engine trivially correct.
 * Matches are non-overlapping per pattern; offsets across patterns of the
 * same signature are merged, deduplicated and capped.
 */
export function scanBuffer(
  buffer: Buffer,
  signatures: readonly SignatureEntry[],
  options: ScannerOptions = {}
): Finding[] {
  const cap = options.maxMatchesPerSignature ?? DEFAULT_MAX_MATCHES;
  const contextLen = options.contextBytes ?? DEFAULT_CONTEXT;

  const findings: Finding[] = [];
  for (const sig of signatures) {
    let offsets: number[] = [];
    let truncated = false;
    let matchLength = sig.lengthBytes;

    for (const rawHex of sig.patterns) {
      const pattern = Buffer.from(normalizeHex(rawHex), 'hex');
      if (pattern.length === 0 || pattern.length > buffer.length) continue;
      const { found, hitCap } = indexOfAll(buffer, pattern, cap);
      if (found.length > 0) {
        offsets = offsets.concat(found);
        if (pattern.length > matchLength) matchLength = pattern.length;
      }
      truncated = truncated || hitCap;
    }

    if (offsets.length === 0) continue;
    offsets = [...new Set(offsets)].sort((a, b) => a - b).slice(0, cap);
    const first = offsets[0] ?? 0;
    findings.push({
      signatureId: sig.id,
      name: sig.name,
      algorithm: sig.algorithm,
      category: sig.category,
      description: sig.description,
      matchLength,
      offsets,
      matchCount: offsets.length,
      truncated,
      contextHex: contextHex(buffer, first, matchLength, contextLen)
    });
  }
  return findings;
}

function indexOfAll(
  buffer: Buffer,
  pattern: Buffer,
  cap: number
): { found: number[]; hitCap: boolean } {
  const found: number[] = [];
  let from = 0;
  while (found.length < cap) {
    const idx = buffer.indexOf(pattern, from);
    if (idx === -1) return { found, hitCap: false };
    found.push(idx);
    from = idx + pattern.length;
  }
  const more = buffer.indexOf(pattern, from);
  return { found, hitCap: more !== -1 };
}

function contextHex(
  buffer: Buffer,
  offset: number,
  length: number,
  contextLen: number
): string {
  const start = Math.max(0, offset - contextLen);
  const end = Math.min(buffer.length, offset + length + contextLen);
  return buffer.subarray(start, end).toString('hex');
}
