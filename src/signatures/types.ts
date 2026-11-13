import { Category } from './categories.js';

/**
 * One cryptographic fingerprint.
 *
 * The database in db.ts is a plain array of these objects. Adding a new
 * signature means adding one object here, one fixture binary and one test —
 * no engine code changes.
 */
export interface SignatureEntry {
  /** Stable machine id (kebab-case); referenced by verdict rules and tests. */
  id: string;
  /** Human-readable name shown in reports. */
  name: string;
  /** Algorithm family, e.g. "AES" or "SHA-256". */
  algorithm: string;
  category: Category;
  /**
   * Hex-encoded byte patterns (whitespace tolerated). Multiple patterns
   * cover implementation variants: endianness of word tables, Salsa vs
   * ChaCha sigma, etc.
   */
  patterns: string[];
  /** Nominal pattern length in bytes (shown in reports). */
  lengthBytes: number;
  /** For word-table signatures: word size in BYTES. The little-endian pattern is the per-word byte reversal of the big-endian one (4 for SHA/MD5/CRC32-style 32-bit tables, 8 for SHA-512's 64-bit words). */
  wordSizeBytes?: number;
  /** One line: what a match means for the analyst. */
  description: string;
  /** Why the constant exists — the story behind the number. */
  story: string;
  /** Primary source document (standard/RFC citation). */
  source: string;
  /**
   * Data-driven disambiguation: if the referenced signature also matches at
   * the same offset with a strictly longer pattern that begins with one of
   * this entry's patterns, this entry's match at that offset is dropped.
   * Handles the MD5/SHA-1 shared initial-value prefix.
   */
  occludedBy?: string;
  /** Alternative names this constant or algorithm is known by. */
  aliases?: string[];
}

/** A signature that matched, with all its offsets and match context. */
export interface Finding {
  signatureId: string;
  name: string;
  algorithm: string;
  category: Category;
  /** Byte length of the matched pattern. */
  matchLength: number;
  /** One-line meaning of this fingerprint, copied from the signature entry. */
  description: string;
  /** Offsets where the pattern was found (non-overlapping, capped). */
  offsets: number[];
  matchCount: number;
  /** True when more matches existed than the cap allows. */
  truncated: boolean;
  /** +/- 32 bytes of context around the first match, hex-encoded. */
  contextHex: string;
}
