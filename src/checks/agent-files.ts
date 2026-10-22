import { posix } from 'node:path';
import { type Check, type Finding, basename, lineAt } from '../types.js';

const AGENT_FILE = /^(AGENTS\.md|CLAUDE\.md|GEMINI\.md|\.cursorrules|copilot-instructions\.md)$/;
const MAX_LINES = 200;
const MD_LINK = /\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;
const AT_IMPORT = /(?:^|\s)@((?:\.{1,2}\/)?[\w-]+(?:\/[\w.-]+)*\.(?:md|mdc|txt|json|ya?ml))\b/g;

const linkTarget = (from: string, raw: string): string | undefined => {
  if (/^([a-z]+:|#|\/\/|<)/i.test(raw)) return undefined; // URLs, anchors, mail
  const target = decodeURIComponent(raw.split('#')[0] ?? '');
  if (!target) return undefined;
  return target.startsWith('/')
    ? target.slice(1)
    : posix.normalize(posix.join(posix.dirname(from), target));
};

export const agentFiles: Check = ({ files, exists }) => {
  const findings: Finding[] = [];
  const agentFiles = files.filter((file) => AGENT_FILE.test(basename(file.path)));
  const isApp = files.some((file) => file.path === 'package.json');
  if (isApp && !agentFiles.some((file) => /^(AGENTS|CLAUDE)\.md$/.test(file.path)))
    findings.push({
      rule: 'agents/missing',
      severity: 'low',
      title: 'No AGENTS.md or CLAUDE.md at the root',
      file: '.',
      why: 'Coding agents guess your stack, commands and no-go areas, and repeat the same mistakes each session.',
      fix: 'Add a short AGENTS.md: how to run, test and deploy, folder map, and rules such as "never use the service-role key in the client".',
    });
  for (const file of agentFiles) {
    const lines = file.text.split('\n').length;
    if (lines > MAX_LINES)
      findings.push({
        rule: 'agents/too-long',
        severity: 'low',
        title: `${basename(file.path)} is ${lines} lines`,
        file: file.path,
        why: 'Long instruction files fill the context window on every request and agents follow them less reliably.',
        fix: `Keep it under ${MAX_LINES} lines; move detail into linked docs the agent reads when needed.`,
      });
    const seen = new Set<string>();
    for (const m of [...file.text.matchAll(MD_LINK), ...file.text.matchAll(AT_IMPORT)]) {
      const target = linkTarget(file.path, m[1] ?? '');
      if (!target || seen.has(target) || target.startsWith('..') || exists(target)) continue;
      seen.add(target);
      findings.push({
        rule: 'agents/broken-link',
        severity: 'low',
        title: `${basename(file.path)} points to ${target}, which does not exist`,
        file: file.path,
        line: lineAt(file.text, (m.index ?? 0) + Math.max(0, m[0].search(/\S/))),
        why: 'The agent looks for the file, finds nothing, and works without the rules you meant it to read.',
        fix: 'Fix the path or remove the reference.',
      });
    }
  }
  return findings;
};
