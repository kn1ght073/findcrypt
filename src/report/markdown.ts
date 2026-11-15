import type { ScanResult } from '../result.js';

function hexOffset(offset: number): string {
  return '0x' + offset.toString(16).padStart(8, '0');
}

/** GitHub-flavored Markdown report — designed for PR comments and docs. */
export function toMarkdown(result: ScanResult): string {
  const file = result.file ?? '<buffer>';
  const lines: string[] = [];

  lines.push(`## findcrypt report — \`${file}\``);
  lines.push('');
  lines.push(
    `- **Size:** ${result.size.toLocaleString('en-US')} bytes`
  );
  lines.push(
    `- **Entropy:** ${result.entropy.fileEntropy.toFixed(3)} bits/byte (${result.entropy.classification})`
  );

  if (result.findings.length === 0) {
    lines.push('');
    lines.push('**Fingerprints:** none found');
  } else {
    lines.push('');
    lines.push(`### Fingerprints (${result.findings.length})`);
    lines.push('');
    lines.push('| Signature | Category | Size | Offsets |');
    lines.push('|---|---|---|---|');
    for (const f of result.findings) {
      const offsets = f.offsets.map(hexOffset).join(', ');
      const suffix = f.truncated ? ' (capped)' : '';
      lines.push(
        `| ${f.name} | ${f.category} | ${f.matchLength} B | ${offsets}${suffix} |`
      );
    }
    lines.push('');
    for (const f of result.findings) {
      lines.push(`- **${f.name}** — ${f.description}`);
    }
  }

  if (result.verdicts.length > 0) {
    lines.push('');
    lines.push('### Verdicts');
    lines.push('');
    for (const v of result.verdicts) {
      lines.push(`- **[${v.confidence}] ${v.label}** — ${v.explanation}`);
    }
  }

  if (result.strings.length > 0) {
    lines.push('');
    lines.push(`### Strings (${result.strings.length})`);
    lines.push('');
    lines.push('```');
    for (const s of result.strings.slice(0, 20)) {
      lines.push(`${hexOffset(s.offset)}  ${s.encoding}  ${JSON.stringify(s.text)}`);
    }
    if (result.strings.length > 20) lines.push(`… ${result.strings.length - 20} more`);
    lines.push('```');
  }

  return lines.join('\n');
}
