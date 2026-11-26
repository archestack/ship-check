import { type Check, type Finding, lineAt } from '../types.js';

const CODE = /\.(?:[cm]?[jt]sx?)$/;
const TEST_FILE = /\.(?:test|spec)\.|(^|\/)(?:__tests__|tests?)\//;
// Express `res.cookie(name, value, options)` and Next.js `cookies().set(name, value, options)`.
const SETTER =
  /\b(?:res|response|reply)\.cookie\(|\b(?:cookies\(\)|cookieStore|cookiesStore)\.set\(/g;
// A cookie that proves who the visitor is. Other cookies (theme, language) are fine to read from a script.
const SESSION_NAME = /sess|token|auth|jwt|\bsid\b|login|access|refresh/i;
const MAX_ARGS = 800;

/** The text between the call's parentheses, or undefined when it does not close within the limit. */
const argsAt = (text: string, open: number): string | undefined => {
  let depth = 0;
  let quote = '';
  for (let i = open; i < Math.min(text.length, open + MAX_ARGS); i++) {
    const ch = text[i] ?? '';
    if (quote) {
      if (ch === '\\') i++;
      else if (ch === quote) quote = '';
    } else if (ch === '"' || ch === "'" || ch === '`') quote = ch;
    else if ('([{'.includes(ch)) depth++;
    else if (')]}'.includes(ch) && --depth === 0) return text.slice(open + 1, i);
  }
  return undefined;
};

/** Top-level arguments, split on commas outside brackets and quotes. */
const splitArgs = (args: string): string[] => {
  const out: string[] = [];
  let depth = 0;
  let quote = '';
  let start = 0;
  for (let i = 0; i < args.length; i++) {
    const ch = args[i] ?? '';
    if (quote) {
      if (ch === '\\') i++;
      else if (ch === quote) quote = '';
    } else if (ch === '"' || ch === "'" || ch === '`') quote = ch;
    else if ('([{'.includes(ch)) depth++;
    else if (')]}'.includes(ch)) depth--;
    else if (ch === ',' && depth === 0) {
      out.push(args.slice(start, i).trim());
      start = i + 1;
    }
  }
  out.push(args.slice(start).trim());
  return out.filter(Boolean);
};

const literalName = (arg: string): string | undefined =>
  /^(['"`])([^'"`$]+)\1$/.exec(arg)?.[2] ?? /\bname\s*:\s*(['"`])([^'"`$]+)\1/.exec(arg)?.[2];

// Only literal options are judged: a variable or a spread may well set httpOnly, so it is left alone.
export const cookies: Check = ({ files }) => {
  const findings: Finding[] = [];
  for (const file of files) {
    if (!CODE.test(file.path) || TEST_FILE.test(file.path)) continue;
    for (const call of file.text.matchAll(SETTER)) {
      const args = argsAt(file.text, (call.index ?? 0) + call[0].length - 1);
      if (args === undefined || args.includes('...')) continue;
      const parts = splitArgs(args);
      const name = literalName(parts[0] ?? '');
      if (!name || !SESSION_NAME.test(name)) continue;
      const objectForm = (parts[0] ?? '').startsWith('{');
      const options = objectForm ? parts[0] : parts[2];
      if (!objectForm && parts.length > 2 && !options?.startsWith('{')) continue;
      if (/\bhttpOnly\s*:\s*true\b/.test(options ?? '')) continue;
      if (/\bhttpOnly\b(?!\s*:)/.test(options ?? '')) continue; // shorthand: a variable
      if (/\bhttpOnly\s*:\s*[^f\s]/.test(options ?? '')) continue; // an expression
      findings.push({
        rule: 'cookie/not-http-only',
        severity: 'medium',
        title: `Cookie "${name}" can be read by page scripts (no httpOnly)`,
        file: file.path,
        line: lineAt(file.text, call.index ?? 0),
        why: 'One injected script or a compromised npm package can read the session cookie and send it away, and whoever holds it is logged in as that user.',
        fix: 'Set httpOnly: true, secure: true and sameSite: "lax" on the cookie, and read the session on the server instead of from document.cookie.',
      });
    }
  }
  return findings;
};
