import type { ScanResult } from './scan.js';
import { SEVERITIES } from './types.js';

export const FIX_URL = 'https://archestack.com/services/?ref=ship-check#audit-h';

export const textReport = ({ filesScanned, findings }: ScanResult, version: string): string => {
  const out = [`ship-check ${version} · ${filesScanned} files scanned`, ''];
  if (findings.length === 0) {
    out.push('No ship blockers found. This is a pattern scan of the code, not a full audit.');
    return out.join('\n');
  }
  for (const f of findings) {
    out.push(`${f.severity.toUpperCase().padEnd(8)}  ${f.title}`);
    out.push(`          ${f.file}${f.line ? `:${f.line}` : ''}`);
    out.push(`          Why: ${f.why}`);
    out.push(`          Fix: ${f.fix}`);
    out.push('');
  }
  const counts = SEVERITIES.map(
    (s) => [s, findings.filter((f) => f.severity === s).length] as const,
  )
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s}`);
  out.push(`${findings.length} findings: ${counts.join(', ')}`);
  out.push(`Want a developer to fix these? ${FIX_URL}`);
  return out.join('\n');
};
