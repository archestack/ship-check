import type { Finding, Project } from './types.js';

export const IGNORE_FILE = '.shipcheckignore';
const INLINE = 'ship-check-ignore';
// The line above counts only when it is a comment by itself, so a trailing marker covers one line.
const COMMENT_ABOVE = /^\s*(\/\/|#|--|\/?\*|<!--)\s*ship-check-ignore/;

interface Entry {
  path: RegExp;
  rule?: string;
}

// A gitignore-style path pattern: `*` stays inside one folder, `**` crosses folders, a pattern with
// no slash matches at any depth, and a match on a folder covers everything under it.
const toRegExp = (pattern: string): RegExp => {
  const anchored = pattern.startsWith('/') || pattern.replace(/\/$/, '').includes('/');
  const body = pattern
    .replace(/^\/|\/$/g, '')
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*\/|\*\*|\*|\?/g, (glob) =>
      glob === '**/' ? '(?:.*/)?' : glob === '**' ? '.*' : glob === '*' ? '[^/]*' : '[^/]',
    );
  return new RegExp(`^${anchored ? '' : '(?:.*/)?'}${body}(?:/.*)?$`);
};

// One entry per line: a path pattern, optionally followed by a rule id (`secret/stripe`) to silence
// only that rule there. `#` starts a comment.
const parse = (text: string): Entry[] =>
  text.split('\n').flatMap((raw) => {
    const [path, rule] = raw.replace(/#.*/, '').trim().split(/\s+/);
    return path ? [{ path: toRegExp(path), rule }] : [];
  });

/** Drops findings silenced by `.shipcheckignore` or a `ship-check-ignore` comment on the line or the line above. */
export const applyIgnores = (
  project: Project,
  findings: Finding[],
): { kept: Finding[]; ignored: number } => {
  const lines = new Map(project.files.map((f) => [f.path, f.text.split('\n')]));
  const entries = parse(lines.get(IGNORE_FILE)?.join('\n') ?? '');
  const silenced = (f: Finding): boolean => {
    if (entries.some((e) => e.path.test(f.file) && (!e.rule || e.rule === f.rule))) return true;
    const text = f.line ? lines.get(f.file) : undefined;
    if (!text) return false;
    return !!text[f.line! - 1]?.includes(INLINE) || COMMENT_ABOVE.test(text[f.line! - 2] ?? '');
  };
  const kept = findings.filter((f) => !silenced(f));
  return { kept, ignored: findings.length - kept.length };
};
