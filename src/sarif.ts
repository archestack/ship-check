import type { ScanResult } from './scan.js';
import type { Finding, Severity } from './types.js';

// SARIF 2.1.0, the format GitHub code scanning reads. `security-severity` is what GitHub uses to
// label an alert critical (>= 9.0), high (7.0-8.9), medium (4.0-6.9) or low.
const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
};
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '3.0',
};

const rule = (f: Finding) => ({
  id: f.rule,
  name: f.rule,
  shortDescription: { text: f.title },
  help: { text: `${f.why}\nFix: ${f.fix}` },
  defaultConfiguration: { level: LEVEL[f.severity] },
  properties: { tags: ['security'], 'security-severity': SECURITY_SEVERITY[f.severity] },
});

export const sarifReport = ({ findings }: ScanResult, version: string): object => {
  const rules: ReturnType<typeof rule>[] = [];
  const index = new Map<string, number>();
  for (const f of findings) {
    if (index.has(f.rule)) continue;
    index.set(f.rule, rules.length);
    rules.push(rule(f));
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'ship-check',
            version,
            informationUri: 'https://github.com/archestack/ship-check',
            rules,
          },
        },
        results: findings.map((f) => ({
          ruleId: f.rule,
          ruleIndex: index.get(f.rule),
          level: LEVEL[f.severity],
          message: { text: `${f.title}. ${f.why} Fix: ${f.fix}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file, uriBaseId: '%SRCROOT%' },
                ...(f.line ? { region: { startLine: f.line } } : {}),
              },
            },
          ],
          properties: { 'security-severity': SECURITY_SEVERITY[f.severity] },
        })),
      },
    ],
  };
};
