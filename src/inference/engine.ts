import type { Finding, SignatureEntry } from '../signatures/types.js';
import { Category } from '../signatures/categories.js';
import type { EntropyReport } from '../core/entropy.js';
import { normalizeHex } from '../core/scanner.js';
import type { Confidence, Verdict, VerdictRule } from './types.js';

const ORDER: Record<Confidence, number> = { HIGH: 0, MEDIUM: 1, LOW: 2 };
const CATEGORY_PREFIX = 'category:';

/**
 * Apply the data-driven `occludedBy` rules: when signature A's pattern is a
 * strict prefix of signature B's pattern and both matched at the same offset,
 * the A match at that offset is a re-detection of the longer constant, not an
 * independent signal. Classic case: MD5's four initial words are the first
 * four of SHA-1's five; the SHA-1 hit occludes the MD5 hit at that offset.
 *
 * Matches at OTHER offsets are kept — a binary can genuinely contain both.
 */
export function disambiguate(
  findings: Finding[],
  signatures: readonly SignatureEntry[]
): Finding[] {
  const entryById = new Map(signatures.map((s) => [s.id, s]));
  const findingById = new Map(findings.map((f) => [f.signatureId, f]));

  const out: Finding[] = [];
  for (const finding of findings) {
    const entry = entryById.get(finding.signatureId);
    const occluderId = entry?.occludedBy;
    if (!occluderId) {
      out.push(finding);
      continue;
    }
    const occluder = findingById.get(occluderId);
    if (!occluder) {
      out.push(finding);
      continue;
    }
    const occluderEntry = entryById.get(occluderId);
    const prefixRelation = (occluderEntry?.patterns ?? []).some((long) =>
      (entry?.patterns ?? []).some(
        (short) =>
          normalizeHex(long).length > normalizeHex(short).length &&
          normalizeHex(long).startsWith(normalizeHex(short))
      )
    );
    let offsets = finding.offsets;
    if (prefixRelation) {
      offsets = offsets.filter((o) => !occluder.offsets.includes(o));
    }
    if (offsets.length > 0) {
      out.push({ ...finding, offsets, matchCount: offsets.length });
    }
  }
  return out;
}

/**
 * Evaluate all rules against a scan. A term matches if it is a signature id
 * present in the findings, or a `category:<NAME>` reference.
 */
export function inferVerdicts(
  findings: Finding[],
  entropy: EntropyReport,
  rules: readonly VerdictRule[]
): Verdict[] {
  const sigIds = new Set(findings.map((f) => f.signatureId));
  const categories = new Set(findings.map((f) => f.category));

  const matchesTerm = (term: string): boolean => {
    if (sigIds.has(term)) return true;
    if (term.startsWith(CATEGORY_PREFIX)) {
      return categories.has(term.slice(CATEGORY_PREFIX.length) as Category);
    }
    return false;
  };

  const verdicts: Verdict[] = [];
  for (const rule of rules) {
    if (rule.when === 'HAS_FINDINGS' && findings.length === 0) continue;
    if (rule.when === 'NO_FINDINGS' && findings.length > 0) continue;
    if (rule.minEntropy !== undefined && entropy.fileEntropy < rule.minEntropy) continue;
    if (rule.maxEntropy !== undefined && entropy.fileEntropy > rule.maxEntropy) continue;
    if (rule.requiresAny && !rule.requiresAny.some(matchesTerm)) continue;
    if (rule.requiresAll && !rule.requiresAll.every(matchesTerm)) continue;
    if (rule.forbidsAny && rule.forbidsAny.some(matchesTerm)) continue;
    verdicts.push({
      ruleId: rule.id,
      label: rule.label,
      confidence: rule.confidence,
      explanation: rule.explanation
    });
  }

  return verdicts.sort((a, b) => ORDER[a.confidence] - ORDER[b.confidence]);
}
