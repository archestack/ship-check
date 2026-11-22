import { type Check, type Finding, type SourceFile, lineAt } from '../types.js';

const CODE = /\.(?:[cm]?[jt]sx?)$/;
const TEST_FILE = /\.(?:test|spec)\.|(^|\/)(?:__tests__|tests?)\//;
const APP_ROUTE = /(^|\/)app\/(?:.*\/)?route\.[cm]?[jt]sx?$/;
const PAGES_API = /(^|\/)pages\/api\/.+\.[cm]?[jt]sx?$/;
const APP_HANDLER = /export\s+(?:async\s+)?(?:function\s+|const\s+)POST\b/;
const PAGES_HANDLER = /export\s+default\b/;
const EXPRESS_POST =
  /\b(?:app|router|server|api|routes)\.post\s*\(\s*['"`]([^'"`]*(?:log-?in|sign-?in|sign-?up|register|forgot|reset|otp|verify-?(?:code|email|phone)|magic)[^'"`]*)['"`]/i;
// Routes whose job is to let someone in or to prove who they are.
const AUTH_PATH =
  /(?:log-?in|sign-?in|sign-?up|register|forgot|reset-?password|password-?reset|otp|verify-?(?:code|email|phone)|magic-?link|two-?factor|2fa|mfa)/i;
// The route checks a secret or sends a code itself. A route that only calls a hosted provider
// (Supabase, Clerk, Auth0) is rate limited by that provider, so it is not flagged.
const OWN_CREDENTIAL_CHECK =
  /bcrypt|argon2|scrypt|pbkdf2|compare(?:Sync)?\s*\(|comparePassword|checkPassword|verifyPassword|timingSafeEqual|\botp\b|totp|sendMail|nodemailer|sendEmail|resend\.emails|sgMail|twilio|\.messages\.create|passwordHash|password_hash/i;
// Any sign that requests are counted or throttled, in the route, in middleware or as a dependency.
const RATE_LIMIT =
  /rate[-_ ]?limit|ratelimit|rate-limiter|limiter|throttl|slow-?down|too many (?:requests|attempts)|\b429\b|lockout|failedAttempts|failed_attempts|login_attempts|loginAttempts|arcjet|unkey|upstash/i;

const isAuthRoute = (file: SourceFile): boolean => {
  if (!CODE.test(file.path) || TEST_FILE.test(file.path)) return false;
  if (APP_ROUTE.test(file.path)) return AUTH_PATH.test(file.path) && APP_HANDLER.test(file.text);
  if (PAGES_API.test(file.path)) return AUTH_PATH.test(file.path) && PAGES_HANDLER.test(file.text);
  return EXPRESS_POST.test(file.text);
};

export const rateLimit: Check = ({ files }) => {
  const code = files.filter((file) => CODE.test(file.path) && !TEST_FILE.test(file.path));
  const packages = files.filter((file) => /(^|\/)package\.json$/.test(file.path));
  // A limiter anywhere in middleware, a shared helper or the dependency list counts for the project:
  // a missed route is better than a wall of false alarms.
  const limiterNamed = (file: SourceFile) =>
    /(^|\/)(?:middleware|proxy)\.[cm]?[jt]s$/.test(file.path);
  if (
    packages.some((file) => RATE_LIMIT.test(file.text)) ||
    code.some((file) => limiterNamed(file) && RATE_LIMIT.test(file.text))
  )
    return [];
  const findings: Finding[] = [];
  for (const file of code) {
    if (!isAuthRoute(file) || !OWN_CREDENTIAL_CHECK.test(file.text) || RATE_LIMIT.test(file.text))
      continue;
    const express = EXPRESS_POST.exec(file.text);
    findings.push({
      rule: 'auth/no-rate-limit',
      severity: 'medium',
      title: 'Login or code-check route has no rate limit',
      file: file.path,
      line: lineAt(file.text, express?.index ?? 0),
      why: 'Nothing slows repeated tries, so a script can guess passwords or a 6-digit code (1,000,000 combinations) in hours, or flood one inbox with reset mails.',
      fix: 'Count tries per IP and per account (Upstash Ratelimit, express-rate-limit or your host firewall), return 429 after about 5 failures a minute, and lock the account for a while after repeated misses.',
    });
  }
  return findings;
};
