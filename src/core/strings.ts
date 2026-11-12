export interface StringFinding {
  offset: number;
  encoding: 'ascii' | 'utf16le';
  text: string;
}

export interface StringsOptions {
  /** Minimum printable-run length (default 4, like Unix `strings`). */
  minLength?: number;
  /** Hard cap on extracted strings (default 5000). */
  maxStrings?: number;
}

const DEFAULT_MIN = 4;
const DEFAULT_MAX = 5000;

interface Run {
  start: number;
  end: number;
  encoding: 'ascii' | 'utf16le';
}

function printable(b: number): boolean {
  return b >= 0x20 && b <= 0x7e;
}

/**
 * Extract printable ASCII and UTF-16LE runs, merged by offset.
 * Mirrors the classic RE workflow of running `strings` over a binary to find
 * config values, URLs, registry keys and other behavioral clues.
 */
export function extractStrings(
  buffer: Buffer,
  options: StringsOptions = {}
): StringFinding[] {
  const min = options.minLength ?? DEFAULT_MIN;
  const max = options.maxStrings ?? DEFAULT_MAX;
  const runs: Run[] = [];

  // ASCII pass
  let start = -1;
  for (let i = 0; i <= buffer.length; i++) {
    const b = i < buffer.length ? buffer[i] : -1;
    if (b >= 0x20 && b <= 0x7e) {
      if (start === -1) start = i;
    } else {
      if (start !== -1 && i - start >= min) runs.push({ start, end: i, encoding: 'ascii' });
      start = -1;
    }
  }

  // UTF-16LE pass: printable char followed by a zero high byte
  if (buffer.length >= 2) {
    start = -1;
    let end = -1;
    for (let i = 0; i + 1 < buffer.length; i += 2) {
      if (printable(buffer[i]) && buffer[i + 1] === 0x00) {
        if (start === -1) start = i;
        end = i + 2;
      } else {
        if (start !== -1 && (end - start) / 2 >= min) {
          runs.push({ start, end, encoding: 'utf16le' });
        }
        start = -1;
        end = -1;
      }
    }
    if (start !== -1 && (end - start) / 2 >= min) {
      runs.push({ start, end, encoding: 'utf16le' });
    }
  }

  runs.sort((a, b) => a.start - b.start);

  const out: StringFinding[] = [];
  for (const run of runs) {
    if (out.length >= max) break;
    const text =
      run.encoding === 'ascii'
        ? buffer.toString('latin1', run.start, run.end)
        : buffer.toString('utf16le', run.start, run.end);
    out.push({ offset: run.start, encoding: run.encoding, text });
  }
  return out;
}
