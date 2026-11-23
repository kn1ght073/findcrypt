import type { ScanResult } from '../index.js';

export interface TerminalOptions {
  /** Force color on/off. Default: auto-detect (TTY + !NO_COLOR). */
  color?: boolean;
}

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const MAGENTA = '\x1b[35m';

/** Respect the NO_COLOR convention and non-TTY pipes. */
export function supportsColor(): boolean {
  if (process.env['NO_COLOR']) return false;
  const stdout = process.stdout as NodeJS.WriteStream;
  if (!stdout.isTTY) return false;
  if (typeof stdout.hasColors === 'function') return stdout.hasColors();
  return true;
}

function hexOffset(offset: number): string {
  return '0x' + offset.toString(16).padStart(8, '0');
}

function formatOffsets(offsets: number[], truncated: boolean): string {
  const shown = offsets.slice(0, 3).map(hexOffset);
  const extra = offsets.length - shown.length;
  let s = shown.join(', ');
  if (extra > 0) s += ` (+${extra} more)`;
  if (truncated) s += ' (capped)';
  return s;
}

function entropyBar(entropy: number): string {
  const filled = Math.round((Math.min(entropy, 8) / 8) * 24);
  return '#'.repeat(filled) + '-'.repeat(24 - filled);
}

const CONFIDENCE_COLOR: Record<string, string> = {
  HIGH: RED,
  MEDIUM: YELLOW,
  LOW: DIM
};

export function toTerminal(result: ScanResult, options: TerminalOptions = {}): string {
  const useColor = options.color ?? supportsColor();
  const c = (code: string, text: string) => (useColor ? code + text + RESET : text);

  const lines: string[] = [];

  lines.push(
    c(
      BOLD + CYAN,
      `${result.tool} v${result.version} — cryptographic fingerprint scanner`
    )
  );
  const file = result.file ?? '<buffer>';
  lines.push(
    `File: ${c(BOLD, file)}  (${result.size.toLocaleString('en-US')} bytes)`
  );

  // Entropy
  const e = result.entropy;
  lines.push(
    `Entropy: ${e.fileEntropy.toFixed(3)} bits/byte ${c(DIM, `[${entropyBar(e.fileEntropy)}]`)} — ${e.classification}`
  );
  if (e.peak) {
    lines.push(
      c(
        DIM,
        `  peak window ${e.peak.entropy.toFixed(3)} @ ${hexOffset(e.peak.offset)}`
      )
    );
  }

  // Findings
  if (result.findings.length === 0) {
    lines.push(c(DIM, 'Fingerprints: none found'));
  } else {
    lines.push('');
    lines.push(
      c(
        BOLD,
        `Fingerprints (${result.findings.length})`
      )
    );
    for (const f of result.findings) {
      const cat = c(MAGENTA, f.category);
      lines.push(
        `  ${c(GREEN, f.name)}  ${cat}  ${f.matchLength} B  ${formatOffsets(f.offsets, f.truncated)}`
      );
      lines.push(c(DIM, `    ${f.description}`));
      if (f.contextHex) {
        lines.push(
          c(
            DIM,
            `    context: ${f.contextHex.slice(0, 64)}${f.contextHex.length > 64 ? '…' : ''}`
          )
        );
      }
    }
  }

  // Verdicts
  if (result.verdicts.length > 0) {
    lines.push('');
    lines.push(c(BOLD, 'Verdicts'));
    for (const v of result.verdicts) {
      const tag = c(CONFIDENCE_COLOR[v.confidence] ?? DIM, `[${v.confidence}]`);
      lines.push(`  ${tag}  ${c(BOLD, v.label)}`);
      lines.push(c(DIM, `    ${v.explanation}`));
    }
  }

  // Strings
  if (result.strings.length > 0) {
    lines.push('');
    lines.push(
      c(BOLD, `Strings (${result.strings.length}${result.strings.length >= 5000 ? '+' : ''})`)
    );
    const shown = result.strings.slice(0, 5);
    for (const s of shown) {
      const text = s.text.length > 64 ? s.text.slice(0, 61) + '…' : s.text;
      lines.push(
        c(
          DIM,
          `  ${hexOffset(s.offset)}  ${s.encoding.padEnd(8)}  "${text}"`
        )
      );
    }
    const rest = result.strings.length - shown.length;
    if (rest > 0) {
      lines.push(c(DIM, `  … ${rest} more (use the API or --json for the full list)`));
    }
  }

  lines.push(
    c(DIM, `  (${result.durationMs.toFixed(1)} ms)`)
  );

  return lines.join('\n');
}
