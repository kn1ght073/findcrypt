export interface WindowEntropy {
  offset: number;
  entropy: number;
}

export interface EntropyReport {
  /** Shannon entropy of the whole file, 0..8 bits per byte. */
  fileEntropy: number;
  /** Sampled sliding-window profile (capped at maxWindows entries). */
  windows: WindowEntropy[];
  /** The highest-entropy sampled window. */
  peak: WindowEntropy | null;
  /** Plain-language classification of the whole-file entropy. */
  classification: string;
}

export interface EntropyOptions {
  /** Sliding-window size in bytes (default 4096). */
  windowSize?: number;
  /** Cap on sampled windows (default 64). */
  maxWindows?: number;
}

const DEFAULT_WINDOW = 4096;
const DEFAULT_MAX_WINDOWS = 64;

/** Shannon entropy in bits per byte. */
export function shannonEntropy(buffer: Buffer): number {
  if (buffer.length === 0) return 0;
  const counts = new Array<number>(256).fill(0);
  for (let i = 0; i < buffer.length; i++) counts[buffer[i]]++;
  let h = 0;
  const total = buffer.length;
  for (let i = 0; i < 256; i++) {
    const c = counts[i];
    if (c === 0) continue;
    const p = c / total;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Thresholds follow common triage practice (e.g. packer detectors):
 *  - ~8.0: encrypted / packed / random
 *  - ~7.0+: compressed streams (zlib/deflate land near 7.2-7.6)
 *  - 5.5-6.8: text-heavy or mixed structured data
 */
export function classifyEntropy(entropy: number): string {
  if (entropy < 1) return 'low — uniform or mostly-empty data';
  if (entropy < 5.5) return 'mixed — typical of text or structured data';
  if (entropy < 6.8) return 'elevated — typical of machine code with some high-entropy regions';
  if (entropy < 7.2) return 'high — compressed or lightly obfuscated data regions likely';
  return 'very high — encrypted, packed, or random data';
}

/**
 * Whole-file entropy plus a sampled window profile. For files larger than
 * windowSize * maxWindows the windows are evenly strided so the profile
 * stays small for multi-hundred-MB inputs.
 */
export function entropyProfile(
  buffer: Buffer,
  options: EntropyOptions = {}
): EntropyReport {
  const windowSize = options.windowSize ?? DEFAULT_WINDOW;
  const maxWindows = options.maxWindows ?? DEFAULT_MAX_WINDOWS;

  const fileEntropy = shannonEntropy(buffer);
  const windows: WindowEntropy[] = [];

  if (buffer.length > 0 && windowSize > 0) {
    const step =
      buffer.length <= windowSize * maxWindows
        ? windowSize
        : Math.ceil(buffer.length / maxWindows);
    for (
      let offset = 0;
      offset < buffer.length && windows.length < maxWindows;
      offset += step
    ) {
      const slice = buffer.subarray(offset, Math.min(offset + windowSize, buffer.length));
      windows.push({ offset, entropy: shannonEntropy(slice) });
    }
  }

  let peak: WindowEntropy | null = null;
  for (const w of windows) {
    if (peak === null || w.entropy > peak.entropy) peak = w;
  }

  return {
    fileEntropy,
    windows,
    peak,
    classification: classifyEntropy(fileEntropy)
  };
}
