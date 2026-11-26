import { type Check, type Finding, lineAt } from '../types.js';
import { argsAt, splitArgs } from './cookies.js';

const CODE = /\.(?:[cm]?[jt]sx?)$/;
const TEST_FILE = /\.(?:test|spec)\.|(^|\/)(?:__tests__|tests?)\//;
// jsonwebtoken: `jwt.sign(payload, secret, options)` and `jwt.verify(token, secret, options)`.
const JWT_CALL = /\b(?:jwt|jsonwebtoken)\.(?:sign|verify)\(/g;
// A secret that signs logins or sessions, read from the environment with a typed-in default after it.
const ENV_FALLBACK =
  /\b(?:process\.env\.|import\.meta\.env\.)([A-Z0-9_]*(?:JWT|SESSION|AUTH|COOKIE|SIGNING)[A-Z0-9_]*(?:SECRET|KEY)[A-Z0-9_]*)\s*(?:\|\||\?\?)\s*(['"`])([^'"`$\n]{1,200})\2/g;
const LITERAL = /^(['"`])([^'"`$]+)\1$/;

const finding = (path: string, text: string, at: number, title: string): Finding => ({
  rule: 'auth/hardcoded-jwt-secret',
  severity: 'high',
  title,
  file: path,
  line: lineAt(text, at),
  why: 'The secret is in the repo (and in every build), so anyone who reads the code or the bundle can sign their own tokens and log in as any user, admin included.',
  fix: 'Read the secret from an environment variable only, throw at startup when it is missing, and rotate it: the committed value counts as leaked.',
});

export const jwtSecrets: Check = ({ files }) => {
  const findings: Finding[] = [];
  for (const file of files) {
    if (!CODE.test(file.path) || TEST_FILE.test(file.path)) continue;
    for (const call of file.text.matchAll(JWT_CALL)) {
      const args = argsAt(file.text, (call.index ?? 0) + call[0].length - 1);
      if (args === undefined) continue;
      if (!LITERAL.test(splitArgs(args)[1] ?? '')) continue;
      findings.push(
        finding(
          file.path,
          file.text,
          call.index ?? 0,
          'A JWT is signed or checked with a secret typed into the code',
        ),
      );
    }
    for (const match of file.text.matchAll(ENV_FALLBACK))
      findings.push(
        finding(
          file.path,
          file.text,
          match.index ?? 0,
          `${match[1]} falls back to a secret typed into the code`,
        ),
      );
  }
  return findings;
};
