export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW';

export type RuleWhen = 'ANY' | 'HAS_FINDINGS' | 'NO_FINDINGS';

/**
 * A term is either a signature id (e.g. "aes-sbox") or a category reference
 * (e.g. "category:HASH").
 */
export type RuleTerm = string;

/**
 * Verdict rules are data, not code: the engine in engine.ts evaluates this
 * array without knowing anything about individual algorithms. New analyst
 * guidance is added by editing rules.ts only.
 */
export interface VerdictRule {
  id: string;
  label: string;
  confidence: Confidence;
  when: RuleWhen;
  /** At least one term must match. */
  requiresAny?: RuleTerm[];
  /** All terms must match. */
  requiresAll?: RuleTerm[];
  /** No term may match. */
  forbidsAny?: RuleTerm[];
  /** Minimum whole-file Shannon entropy (bits/byte). */
  minEntropy?: number;
  /** Maximum whole-file Shannon entropy (bits/byte). */
  maxEntropy?: number;
  /** What this verdict means and what the analyst should do next. */
  explanation: string;
}

/** One verdict emitted for a scan. */
export interface Verdict {
  ruleId: string;
  label: string;
  confidence: Confidence;
  explanation: string;
}
