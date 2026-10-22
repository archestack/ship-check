import { type Check, type Finding, type Severity, lineAt } from '../types.js';

// Key formats adapted from gitleaks (https://github.com/gitleaks/gitleaks, MIT License, Copyright (c)
// 2019 Zachary Rice). Only formats with a
// fixed prefix, so a match is almost always a real key; no entropy guessing.
interface Rule {
  id: string;
  name: string;
  pattern: RegExp;
  where: string;
  severity?: Severity;
  /** Return false to drop a match (placeholders, public keys). */
  keep?: (match: RegExpMatchArray) => boolean;
}

const RULES: Rule[] = [
  {
    id: 'aws-access-key',
    name: 'AWS access key',
    pattern: /\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b/g,
    where: 'AWS IAM → Users → Security credentials',
  },
  {
    id: 'github-token',
    name: 'GitHub token',
    pattern: /\b(?:gh[pousr]_[0-9a-zA-Z]{36}|github_pat_\w{82})\b/g,
    where: 'GitHub → Settings → Developer settings → Tokens',
  },
  {
    id: 'openai-key',
    name: 'OpenAI API key',
    pattern:
      /\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})/g,
    where: 'platform.openai.com → API keys',
  },
  {
    id: 'anthropic-key',
    name: 'Anthropic API key',
    pattern: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}/g,
    where: 'console.anthropic.com → API keys',
  },
  {
    id: 'stripe-secret-key',
    name: 'Stripe live secret key',
    pattern: /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b/g,
    where: 'Stripe → Developers → API keys',
  },
  {
    id: 'slack-token',
    name: 'Slack token',
    pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
    where: 'api.slack.com → Your apps',
  },
  {
    id: 'sendgrid-key',
    name: 'SendGrid API key',
    pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    where: 'SendGrid → Settings → API Keys',
  },
  {
    id: 'private-key',
    name: 'Private key',
    // Header plus key material, so code that strips the header (`pem.replace(...)`) does not match.
    pattern: /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----(?:\\[nr]|\s)+[A-Za-z0-9+/]{40}/g,
    where: 'the service that issued it',
  },
  {
    id: 'supabase-secret-key',
    name: 'Supabase secret key',
    pattern: /\bsb_secret_[A-Za-z0-9_-]{20,}/g,
    where: 'Supabase → Project Settings → API Keys',
  },
  {
    id: 'supabase-service-role-jwt',
    name: 'Supabase service-role key',
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,}/g,
    where: 'Supabase → Project Settings → API Keys',
    // A Supabase JWT is only secret when its role is service_role; the anon key is public by design.
    keep: (match) => {
      try {
        const payload = JSON.parse(Buffer.from(match[1] ?? '', 'base64url').toString('utf8'));
        return payload?.role === 'service_role';
      } catch {
        return false;
      }
    },
  },
  {
    id: 'database-url-password',
    name: 'Database URL with a password',
    severity: 'high',
    pattern:
      /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss):\/\/[^\s:@/'"`]+:([^\s@/'"`]+)@([^\s/:'"`?]+)/g,
    where: 'your database provider',
    keep: (match) => {
      const [password = '', host = ''] = [match[1], match[2]];
      if (/^(localhost|127\.0\.0\.1|0\.0\.0\.0|db|postgres|mysql|mongo|redis|host)$/i.test(host))
        return false;
      if (/[$<>{}*[\]]|^(password|pass|secret|changeme|xxx+|your[-_]?password)$/i.test(password))
        return false;
      return password.length >= 6;
    },
  },
];

const mask = (value: string): string =>
  value.length <= 12 ? `${value.slice(0, 4)}…` : `${value.slice(0, 10)}…`;

export const secrets: Check = ({ files }) => {
  const findings: Finding[] = [];
  for (const file of files) {
    for (const rule of RULES) {
      const seen = new Set<number>();
      for (const match of file.text.matchAll(rule.pattern)) {
        if (rule.keep && !rule.keep(match)) continue;
        const line = lineAt(file.text, match.index ?? 0);
        if (seen.has(line)) continue;
        seen.add(line);
        findings.push({
          rule: `secret/${rule.id}`,
          severity: rule.severity ?? 'critical',
          title: `${rule.name} in the code (${mask(match[0])})`,
          file: file.path,
          line,
          why: 'Anyone who can read this file can use the key, and git keeps it in history even after you delete the line.',
          fix: `Revoke it in ${rule.where}, issue a new one, and read it from an environment variable on the server only.`,
        });
      }
    }
  }
  return findings;
};
