import { type Check, type Finding, type SourceFile, lineAt } from '../types.js';

const CODE = /\.(?:[cm]?[jt]sx?)$/;
const APP_ROUTE = /(^|\/)app\/(?:.*\/)?route\.[cm]?[jt]sx?$/;
const PAGES_API = /(^|\/)pages\/api\/.+\.[cm]?[jt]sx?$/;
const NEXT_MIDDLEWARE = /^(?:src\/)?(?:middleware|proxy)\.[cm]?[jt]s$/;
const APP_HANDLER = /export\s+(?:async\s+)?(?:function\s+|const\s+)(POST|PUT|PATCH|DELETE)\b/g;
const EXPRESS_ROUTE =
  /\b(?:app|router|server|api|routes)\.(post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/g;
// Anything that looks like an auth, session or signature check. Broad on purpose: a missed route is
// better than a wall of false alarms.
const AUTH_SIGNAL =
  /auth|session|currentUser|getUser|verify|jwt|bearer|token|clerk|signature|webhook|api[-_]?key|passport|guard|protect|permission|isAdmin|requireUser|kinde|lucia|better-auth/i;

const finding = (file: SourceFile, index: number, what: string): Finding => ({
  rule: 'api/no-auth-check',
  severity: 'medium',
  title: `${what} changes data with no visible auth check`,
  file: file.path,
  line: lineAt(file.text, index),
  why: 'Anyone can call an API route directly, without your UI; hiding the button does not protect it.',
  fix: 'Check the session at the top of the handler (or in middleware) and return 401 when there is none.',
});

export const apiAuth: Check = ({ files }) => {
  const nextMiddlewareGuards = files.some(
    (file) => NEXT_MIDDLEWARE.test(file.path) && AUTH_SIGNAL.test(file.text),
  );
  const findings: Finding[] = [];
  for (const file of files) {
    if (!CODE.test(file.path) || AUTH_SIGNAL.test(file.text)) continue;
    if (APP_ROUTE.test(file.path) && !nextMiddlewareGuards) {
      const handlers = [...file.text.matchAll(APP_HANDLER)];
      const first = handlers[0];
      if (first)
        findings.push(
          finding(file, first.index ?? 0, `Route ${handlers.map((m) => m[1]).join(', ')}`),
        );
      continue;
    }
    if (PAGES_API.test(file.path) && !nextMiddlewareGuards) {
      if (/req\.method|POST|PUT|PATCH|DELETE|\.insert\(|\.update\(|\.delete\(/.test(file.text))
        findings.push(finding(file, 0, 'API route'));
      continue;
    }
    const routes = [...file.text.matchAll(EXPRESS_ROUTE)];
    const first = routes[0];
    if (first)
      findings.push(
        finding(
          file,
          first.index ?? 0,
          routes.map((m) => `${m[1]?.toUpperCase()} ${m[2]}`).join(', '),
        ),
      );
  }
  return findings;
};
