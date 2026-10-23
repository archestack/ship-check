# ship-check

Run one command in your project folder before you launch and get a plain list of the things that
get vibe-coded apps hacked: keys in the code, Supabase tables anyone can read or write, open
Firebase rules, API routes with no auth check.

```sh
npx @archestack/ship-check
```

It reads your files and nothing else. No account, no upload, no network calls.

## What it checks

| Check | What it flags |
| --- | --- |
| Secrets | Live keys with a known format: Stripe, OpenAI, Anthropic, AWS, GitHub, Slack, SendGrid, Supabase secret and service-role keys, private key blocks, database URLs with a password. The Supabase anon key is public by design and is not flagged. |
| .env files | `.env`, `.env.local`, `.env.production` and friends that git would commit (tracked, or not covered by `.gitignore`). `.env.example` is fine. |
| Supabase | Tables in the `public` schema without row level security, RLS turned off, policies with `using (true)` on writes, and the service-role key used in a `"use client"` file. |
| Public env names | `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_` variables that hold a secret or service-role key. Those end up in the browser. |
| Firebase | `allow read, write: if true`, rules with no condition, test-mode date rules, and `".write": true` in Realtime Database rules. |
| API routes | Next.js route handlers and `pages/api` files, and Express-style `app.post(...)` routes, that change data and contain no sign of an auth or session check. This one is a heuristic, so it is reported as medium. |
| AGENTS.md / CLAUDE.md | Missing at the root, over 200 lines, or pointing to files that do not exist. |

Severities are critical, high, medium and low. The secret formats are adapted from
[gitleaks](https://github.com/gitleaks/gitleaks) (MIT).

## Example

```text
ship-check 0.1.0 · 4 files scanned

CRITICAL  VITE_SUPABASE_SERVICE_ROLE_KEY is shipped to the browser
          .env.production.example:2
          Why: Variables with a public prefix are copied into the JavaScript every visitor downloads.
          Fix: Drop the public prefix, use the value only in server code or an edge function, and rotate the key.

HIGH      Table public.sales has no row level security
          supabase/migrations/20250101_sales.sql:2
          Why: Every table in the public schema is reachable through the API with the anon key from your site; without RLS anyone can read and change all rows.
          Fix: Add `alter table public.sales enable row level security;` and policies that check auth.uid() in a new migration.

2 findings: 1 critical, 1 high
Want a developer to fix these? https://archestack.com/services/?ref=ship-check#audit-h
```

## Options

```text
ship-check [folder] [--json] [--fail-on critical|high|medium|low|never]
```

- `folder` defaults to the current folder.
- `--json` prints the findings as JSON.
- `--fail-on` sets when the exit code is 1. The default is `high`, so medium and low findings do
  not fail a build. Exit code 2 means bad arguments.

In a git repository it scans the files git would commit and skips what `.gitignore` covers. Outside
git it scans everything except `node_modules`, build output and lock files.

## Ignoring a finding

Once you have checked a finding and it is fine (a fake key in a test, a table that is public on
purpose), silence it so CI can stay on:

- Add `ship-check-ignore` in a comment on the same line, or on its own comment line just above it.
- Or list paths in a `.shipcheckignore` file at the project root, one per line, gitignore style
  (`test/`, `**/fixtures/**`, `*.sql`). Add a rule id after the path to silence only that rule
  there: `supabase/seed.sql supabase/rls-off`. Rule ids are in the `--json` output.

The report header says how many findings were ignored, so nothing disappears silently.

## In CI

```yaml
- run: npx -y @archestack/ship-check --fail-on high
```

## Limits

This is a pattern scan of your code, not a penetration test. It does not look at your live
database, so a table fixed in the Supabase dashboard but not in a migration still shows up, and a
policy written only in the dashboard is invisible to it. A clean run is a good sign, not proof.

## Want it fixed for you?

If you would rather have a developer fix what it finds, send a brief at
[archestack.com/services](https://archestack.com/services/?ref=ship-check#audit-h).

## License

MIT
