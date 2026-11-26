// Every check runs through the CLI entry point (dist/cli.js) against a project written to a temp
// folder. Key-shaped strings are built by concatenation so this file holds no real-looking secret.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, it } from 'node:test';

const CLI = new URL('../dist/cli.js', import.meta.url).pathname;
const dirs: string[] = [];
after(() => dirs.forEach((dir) => rmSync(dir, { recursive: true, force: true })));

const project = (files: Record<string, string>, { git = false } = {}): string => {
  const root = mkdtempSync(join(tmpdir(), 'ship-check-'));
  dirs.push(root);
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), text);
  }
  if (git) execFileSync('git', ['init', '-q'], { cwd: root });
  return root;
};

interface Run {
  status: number | null;
  stdout: string;
  rules: string[];
  findings: { rule: string; severity: string; file: string; line?: number; title: string }[];
}

const run = (root: string, ...args: string[]): Run => {
  const res = spawnSync('node', [CLI, root, '--json', ...args], { encoding: 'utf8' });
  const { findings } = JSON.parse(res.stdout);
  return {
    status: res.status,
    stdout: res.stdout,
    findings,
    rules: findings.map((f: { rule: string }) => f.rule),
  };
};

const jwt = (payload: object): string =>
  [
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
    Buffer.from(JSON.stringify(payload)).toString('base64url'),
    'c2lnbmF0dXJlLXBhcnQtaGVyZQ',
  ].join('.');

describe('clean project', () => {
  it('exits 0 with no findings and prints the text report', () => {
    const root = project({
      'package.json': '{"name":"x"}',
      'AGENTS.md': '# Rules\n',
      'src/a.ts': 'export const a = 1;\n',
    });
    const res = spawnSync('node', [CLI, root], { encoding: 'utf8' });
    assert.equal(res.status, 0);
    assert.match(res.stdout, /No ship blockers found/);
  });
});

describe('secrets', () => {
  it('finds a Stripe live key and a GitHub token, masked, exit 1', () => {
    const stripe = 'sk_' + 'live_' + 'a1B2c3D4e5F6g7H8i9J0k1L2';
    const gh = 'ghp' + '_' + 'A'.repeat(36);
    const root = project({ 'src/pay.ts': `const s = "${stripe}";\n\nconst g = '${gh}';\n` });
    const res = run(root);
    assert.equal(res.status, 1);
    assert.deepEqual(res.rules.sort(), ['secret/github-token', 'secret/stripe-secret-key']);
    assert.equal(res.findings.find((f) => f.rule === 'secret/github-token')?.line, 3);
    assert.ok(!res.stdout.includes(stripe), 'full key never printed');
  });

  it('flags a service-role JWT but not the anon key', () => {
    const root = project({
      'src/a.ts': `const anon = "${jwt({ role: 'anon', iss: 'supabase' })}";\nconst admin = "${jwt({ role: 'service_role', iss: 'supabase' })}";\n`,
    });
    const res = run(root);
    assert.deepEqual(res.rules, ['secret/supabase-service-role-jwt']);
    assert.equal(res.findings[0]?.line, 2);
  });

  it('flags a remote database URL with a password, not localhost or placeholders', () => {
    const root = project({
      'a.ts': [
        'const a = "postgres://app:' + 'Xk9mQ2vLp' + '@db.abcd.supabase.co:5432/postgres";',
        'const b = "postgres://app:Xk9mQ2vLp@localhost:5432/app";',
        'const c = "postgres://app:${PASSWORD}@db.example.com/app";',
      ].join('\n'),
    });
    const res = run(root);
    assert.deepEqual(res.rules, ['secret/database-url-password']);
    assert.equal(res.findings[0]?.severity, 'high');
  });

  it('flags a private key block, not code that strips the header', () => {
    const header = '-----BEGIN ' + 'PRIVATE KEY-----';
    const root = project({
      'key.json': `{"private_key": "${header}\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\\n"}`,
      'pem.ts': `const b64 = pem.replace(/${header}|-----END PRIVATE KEY-----|\\s/g, "");\n`,
    });
    assert.deepEqual(
      run(root).findings.map((f) => `${f.rule} ${f.file}`),
      ['secret/private-key key.json'],
    );
  });
});

describe('.env files', () => {
  it('flags a .env git would commit, not one .gitignore covers, not .env.example', () => {
    const committed = project({ '.env': 'A=1\n', '.env.example': 'A=\n' }, { git: true });
    assert.deepEqual(run(committed).rules, ['env/committed']);
    const ignored = project({ '.env': 'A=1\n', '.gitignore': '.env\n' }, { git: true });
    assert.deepEqual(run(ignored).rules, []);
  });
});

describe('supabase', () => {
  const pkg = { 'package.json': '{"dependencies":{"@supabase/supabase-js":"2"}}', 'AGENTS.md': '' };

  it('flags a public table without RLS and passes one with it', () => {
    const root = project({
      ...pkg,
      'supabase/migrations/1_init.sql':
        'create table public.notes (id int);\ncreate table if not exists "profiles" (id int);\ncreate table private.audit (id int);\n',
      'supabase/migrations/2_rls.sql': 'alter table public.profiles enable row level security;\n',
    });
    const res = run(root);
    assert.deepEqual(res.rules, ['supabase/rls-off']);
    assert.match(res.findings[0]?.title ?? '', /public\.notes/);
    assert.equal(res.findings[0]?.line, 1);
  });

  it('flags disabled RLS and an open write policy, not an open read policy', () => {
    const root = project({
      ...pkg,
      'supabase/migrations/1.sql': [
        'create table todos (id int);',
        'alter table todos enable row level security;',
        'create policy "read" on todos for select using (true);',
        'create policy "write" on todos for update using (true);',
        'create policy "form" on todos for insert with check (true);',
        'alter table todos disable row level security;',
      ].join('\n'),
    });
    assert.deepEqual(
      run(root).findings.map((f) => `${f.rule} ${f.severity} ${f.line}`),
      ['supabase/rls-disabled critical 6', 'supabase/open-write-policy high 4'],
    );
  });

  it('groups open write policies per table, worst severity first, one line per table', () => {
    const root = project({
      ...pkg,
      'supabase/migrations/1.sql': [
        'create policy "a" on public.todos for update using (true);',
        'create policy "b" on "todos" for delete using (true);',
        'create policy "c" on todos for update using (true);',
        'create policy "d" on notes for insert with check (true);',
        'create policy "e" on notes for insert with check (true);',
        'create policy "f" on tags for all using (true);',
      ].join('\n'),
    });
    assert.deepEqual(
      run(root).findings.map((f) => `${f.severity} ${f.line} ${f.title}`),
      [
        'high 1 Policies let anyone update, delete every row of todos',
        'high 6 Policy lets anyone write every row',
        'medium 4 Policy lets anyone insert every row',
      ],
    );
  });

  it('flags public storage buckets in migrations and config.toml, not private ones', () => {
    const root = project({
      ...pkg,
      'supabase/migrations/1.sql': [
        'insert into storage.buckets (id, name, public, allowed_mime_types)',
        "values ('avatars', 'avatars', true, array['image/png']), ('invoices', 'invoices', false, null);",
        "insert into storage.buckets (id, name) values ('docs', 'docs');",
        "update storage.buckets set public = true where id = 'uploads';",
      ].join('\n'),
      'supabase/config.toml':
        '[storage.buckets.images]\npublic = true\n\n[storage.buckets.private]\npublic = false\n',
    });
    assert.deepEqual(
      run(root).findings.map((f) => `${f.file} ${f.line} ${f.title}`),
      [
        'supabase/config.toml 1 Storage bucket images is public',
        'supabase/migrations/1.sql 1 Storage bucket avatars is public',
        'supabase/migrations/1.sql 4 Storage bucket uploads is public',
      ],
    );
  });

  it('counts the bare PUBLIC_ prefix only as an env name, and skips docs', () => {
    const root = project({
      '.env': 'PUBLIC_STRIPE_SECRET=x\n',
      'src/a.ts':
        'const PUBLIC_SECRET_PATTERN = /x/;\nconst k = import.meta.env.PUBLIC_API_SECRET;\n',
      'docs/setup.md': 'Never set VITE_SUPABASE_SERVICE_ROLE_KEY.\n',
    });
    assert.deepEqual(
      run(root)
        .findings.filter((f) => f.rule === 'client/public-secret-env')
        .map((f) => `${f.file}:${f.line}`),
      ['.env:1', 'src/a.ts:2'],
    );
  });

  it('groups 4+ rls-off findings in one file into a single finding, keeps individual for fewer', () => {
    const tables = (names: string[]): string =>
      names.map((n) => `create table public.${n} (id int);\n`).join('');
    // Three tables → three individual findings.
    const three = project({
      ...pkg,
      'supabase/migrations/1.sql': tables(['a', 'b', 'c']),
    });
    const resThree = run(three);
    assert.equal(resThree.rules.filter((r) => r === 'supabase/rls-off').length, 3);
    // Four tables → one grouped finding.
    const four = project({
      ...pkg,
      'supabase/migrations/1.sql': tables(['orders', 'products', 'users', 'sessions']),
    });
    const resFour = run(four);
    assert.equal(resFour.rules.filter((r) => r === 'supabase/rls-off').length, 1);
    const f = resFour.findings[0] as { title: string; fix?: string };
    assert.match(f?.title ?? '', /4 tables/);
    assert.match(f?.title ?? '', /orders/);
    assert.match(f?.fix ?? '', /alter table public\.orders/);
  });

  it('ignores SQL in a project that does not use Supabase', () => {
    assert.deepEqual(run(project({ 'db/schema.sql': 'create table notes (id int);\n' })).rules, []);
  });

  it('flags a public-prefixed secret env and a service-role key in a client component', () => {
    const root = project({
      '.env.example': 'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\n',
      'app/admin/page.tsx': `'use client';\nimport { createClient } from '@supabase/supabase-js';\nconst s = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);\n`,
    });
    const res = run(root);
    assert.deepEqual(res.rules.sort(), [
      'client/public-secret-env',
      'supabase/service-role-in-client',
    ]);
    assert.equal(res.findings.find((f) => f.rule === 'supabase/service-role-in-client')?.line, 3);
  });
});

describe('firebase', () => {
  it('flags open writes, open reads and test mode; passes auth rules', () => {
    const root = project({
      'firestore.rules': [
        "rules_version = '2';",
        'service cloud.firestore {',
        '  match /databases/{db}/documents {',
        '    match /posts/{id} { allow read: if true; }',
        '    match /{document=**} { allow read, write: if request.time < timestamp.date(2026, 1, 5); }',
        '    match /users/{uid} { allow read, write: if request.auth != null && request.auth.uid == uid; }',
        '    match /logs/{id} { allow write; }',
        '  }',
        '}',
      ].join('\n'),
      'database.rules.json': '{ "rules": { ".read": "auth != null", ".write": true } }',
    });
    const res = run(root);
    assert.equal(res.status, 1);
    assert.deepEqual(res.rules.sort(), [
      'firebase/open-read',
      'firebase/open-write',
      'firebase/open-write',
      'firebase/test-mode',
    ]);
    assert.match(
      res.findings.find((f) => f.rule === 'firebase/test-mode')?.title ?? '',
      /2026-01-05/,
    );
  });
});

describe('API routes', () => {
  it('flags Next.js and Express write routes with no auth check, passes guarded ones', () => {
    const root = project({
      'app/api/posts/route.ts':
        'export async function GET() {}\nexport async function POST(req: Request) { await db.insert(); }\n',
      'app/api/me/route.ts':
        "import { auth } from '@clerk/nextjs/server';\nexport async function DELETE() { await auth(); }\n",
      'pages/api/delete.ts':
        'export default async function handler(req, res) { if (req.method === "DELETE") await db.delete(); }\n',
      'server/index.js':
        "app.get('/x', h);\napp.post('/orders', create);\napp.delete('/orders/:id', remove);\n",
    });
    const res = run(root, '--fail-on', 'medium');
    assert.equal(res.status, 1);
    assert.deepEqual(res.findings.map((f) => f.file).sort(), [
      'app/api/posts/route.ts',
      'pages/api/delete.ts',
      'server/index.js',
    ]);
    assert.match(
      res.findings.find((f) => f.file === 'server/index.js')?.title ?? '',
      /POST \/orders, DELETE \/orders\/:id/,
    );
    assert.equal(res.findings.find((f) => f.file === 'app/api/posts/route.ts')?.line, 2);
  });

  it('skips Next.js routes when middleware checks auth', () => {
    const root = project({
      'middleware.ts': "export { auth as middleware } from './auth';\n",
      'app/api/posts/route.ts': 'export async function POST() {}\n',
    });
    assert.deepEqual(run(root).rules, []);
  });

  it('medium findings do not fail the default --fail-on high', () => {
    const root = project({ 'app/api/posts/route.ts': 'export async function POST() {}\n' });
    assert.equal(run(root).status, 0);
  });
});

describe('webhooks', () => {
  it('flags a Stripe webhook that never verifies the signature, passes a verified one', () => {
    const root = project({
      'app/api/stripe/webhook/route.ts':
        "export async function POST(req: Request) {\n  const event = await req.json();\n  if (event.type === 'checkout.session.completed') await grant(event);\n}\n",
      'app/api/billing/route.ts':
        "export async function POST(req: Request) {\n  const event = stripe.webhooks.constructEvent(await req.text(), req.headers.get('stripe-signature'), secret);\n  if (event.type === 'invoice.paid') await grant(event);\n}\n",
      'pages/api/clerk-webhook.ts':
        'export default async function handler(req, res) { await sync(req.body); res.end(); }\n',
      'pages/api/svix-webhook.ts':
        "import { Webhook } from 'svix';\nexport default async function handler(req, res) { new Webhook(s).verify(req.body, req.headers); }\n",
      'app/pricing/page.tsx':
        "export default function Page() { return 'checkout.session.completed'; }\n",
    });
    const res = run(root);
    const hits = res.findings.filter((f) => f.rule === 'webhook/unverified');
    assert.deepEqual(hits.map((f) => [f.file, f.severity]).sort(), [
      ['app/api/stripe/webhook/route.ts', 'high'],
      ['pages/api/clerk-webhook.ts', 'medium'],
    ]);
    assert.equal(hits[0]?.line, 1);
    assert.equal(res.status, 1);
  });

  it('reports a webhook once, and the word "webhook" no longer passes a plain route', () => {
    const root = project({
      // unverified webhook: only webhook/unverified, not also api/no-auth-check
      'app/api/stripe/webhook/route.ts':
        "export async function POST(req: Request) {\n  const event = await req.json();\n  if (event.type === 'checkout.session.completed') await grant(event);\n}\n",
      // verified webhook through the SDK: neither rule
      'app/api/billing/route.ts':
        "export async function POST(req: Request) {\n  const event = stripe.webhooks.constructEvent(await req.text(), req.headers.get('x'), secret);\n  if (event.type === 'invoice.paid') await grant(event);\n}\n",
      // not a webhook handler, only posts to one: still an open data-changing route
      'app/api/notify/route.ts':
        "export async function POST(req: Request) {\n  await fetch(process.env.SLACK_WEBHOOK_URL, { method: 'POST', body: await req.text() });\n}\n",
    });
    const byFile = (file: string) =>
      run(root)
        .findings.filter((f) => f.file === file)
        .map((f) => f.rule);
    assert.deepEqual(byFile('app/api/stripe/webhook/route.ts'), ['webhook/unverified']);
    assert.deepEqual(byFile('app/api/billing/route.ts'), []);
    assert.deepEqual(byFile('app/api/notify/route.ts'), ['api/no-auth-check']);
  });
});

describe('login rate limits', () => {
  const login =
    "import bcrypt from 'bcrypt';\nexport async function POST(req: Request) {\n  const { email, password } = await req.json();\n  const user = await db.user.find(email);\n  if (!(await bcrypt.compare(password, user.passwordHash))) return new Response('no', { status: 401 });\n  return new Response('ok');\n}\n";
  const files = {
    'app/api/login/route.ts': login,
    'app/api/auth/reset-password/route.ts':
      'export async function POST(req: Request) {\n  await resend.emails.send({ to: (await req.json()).email });\n}\n',
    'pages/api/verify-code.ts':
      'export default async function handler(req, res) { if (req.body.code !== (await getOtp(req.body.id))) return res.status(401).end(); res.end(); }\n',
    'server.js':
      "app.post('/signin', async (req, res) => { if (!await argon2.verify(u.hash, req.body.password)) return res.sendStatus(401); res.end(); });\n",
    // hosted provider does the limiting: not flagged
    'app/api/signin/route.ts':
      'export async function POST(req: Request) {\n  return supabase.auth.signInWithPassword(await req.json());\n}\n',
    // not an auth route
    'app/api/posts/route.ts': "export async function POST() { return bcrypt.compare('a', 'b'); }\n",
  };

  it('flags own credential checks and code sends with no limiter, not hosted providers', () => {
    const hits = run(project(files)).findings.filter((f) => f.rule === 'auth/no-rate-limit');
    assert.deepEqual(hits.map((f) => f.file).sort(), [
      'app/api/auth/reset-password/route.ts',
      'app/api/login/route.ts',
      'pages/api/verify-code.ts',
      'server.js',
    ]);
    assert.ok(hits.every((f) => f.severity === 'medium'));
  });

  it('passes when the route, middleware or a dependency shows a limiter', () => {
    const inRoute = {
      'app/api/login/route.ts': `const { success } = await ratelimit.limit(ip);\n${login}`,
    };
    const inMiddleware = {
      'app/api/login/route.ts': login,
      'middleware.ts':
        "import { Ratelimit } from '@upstash/ratelimit';\nexport function middleware() {}\n",
    };
    const inDeps = {
      'app/api/login/route.ts': login,
      'package.json': '{"dependencies":{"express-rate-limit":"^7.0.0"}}',
    };
    for (const set of [inRoute, inMiddleware, inDeps])
      assert.deepEqual(
        run(project(set)).findings.filter((f) => f.rule === 'auth/no-rate-limit'),
        [],
      );
  });
});

describe('session cookies', () => {
  const ruleFor = (code: string) => run(project({ 'src/auth.ts': code })).rules;

  it('flags a session or token cookie set without httpOnly, with or without options', () => {
    assert.deepEqual(ruleFor("res.cookie('session', token);\n"), ['cookie/not-http-only']);
    assert.deepEqual(ruleFor("res.cookie('access_token', t, { secure: true, maxAge: 9 });\n"), [
      'cookie/not-http-only',
    ]);
    assert.deepEqual(ruleFor("cookies().set('sb-auth', jwt, { httpOnly: false });\n"), [
      'cookie/not-http-only',
    ]);
    assert.deepEqual(ruleFor("cookieStore.set({ name: 'session', value: id, path: '/' });\n"), [
      'cookie/not-http-only',
    ]);
  });

  it('leaves httpOnly cookies, other cookies and options it cannot read alone', () => {
    assert.deepEqual(ruleFor("res.cookie('session', t, { httpOnly: true, secure: true });\n"), []);
    assert.deepEqual(ruleFor("res.cookie('theme', 'dark');\n"), []);
    assert.deepEqual(ruleFor("cookies().set('session', t, options);\n"), []);
    assert.deepEqual(ruleFor("res.cookie('session', t, { ...base, maxAge: 9 });\n"), []);
    assert.deepEqual(ruleFor("res.cookie('session', t, { httpOnly: !isDev });\n"), []);
    assert.deepEqual(
      ruleFor("cookieStore.set({ name: 'session', value: id, httpOnly: true });\n"),
      [],
    );
    const tests = run(project({ 'src/auth.test.ts': "res.cookie('session', t);\n" }));
    assert.deepEqual(tests.rules, []);
  });
});

describe('JWT secrets', () => {
  const ruleFor = (code: string, path = 'src/auth.ts') => run(project({ [path]: code })).rules;

  it('flags a secret typed into jwt.sign or jwt.verify, and an env secret with a typed default', () => {
    assert.deepEqual(ruleFor("const t = jwt.sign({ id }, 'changeme', { expiresIn: '1d' });\n"), [
      'auth/hardcoded-jwt-secret',
    ]);
    assert.deepEqual(ruleFor('const p = jwt.verify(token, "my-secret");\n'), [
      'auth/hardcoded-jwt-secret',
    ]);
    assert.deepEqual(ruleFor("const s = process.env.JWT_SECRET || 'secret';\n"), [
      'auth/hardcoded-jwt-secret',
    ]);
    assert.deepEqual(ruleFor('const s = process.env.NEXTAUTH_SECRET ?? "dev-secret";\n'), [
      'auth/hardcoded-jwt-secret',
    ]);
  });

  it('leaves env secrets, other variables and test files alone', () => {
    assert.deepEqual(ruleFor('const t = jwt.sign({ id }, process.env.JWT_SECRET);\n'), []);
    assert.deepEqual(ruleFor('const t = jwt.sign({ id }, secret, { expiresIn: "1d" });\n'), []);
    assert.deepEqual(ruleFor('const p = jwt.verify(token, `${prefix}-x`);\n'), []);
    assert.deepEqual(ruleFor("const u = process.env.API_URL || 'http://localhost';\n"), []);
    assert.deepEqual(ruleFor("const k = process.env.JWT_ISSUER || 'app';\n"), []);
    assert.deepEqual(ruleFor("const s = process.env.JWT_SECRET || '';\n"), []);
    assert.deepEqual(ruleFor("jwt.sign({}, 'secret');\n", 'src/auth.test.ts'), []);
  });
});

describe('agent files', () => {
  it('flags a missing AGENTS.md in an app', () => {
    assert.deepEqual(run(project({ 'package.json': '{}' })).rules, ['agents/missing']);
  });

  it('flags a long file and links to files that do not exist', () => {
    const root = project({
      'package.json': '{}',
      'docs/rules.md': 'x',
      'CLAUDE.md': [
        'See [rules](docs/rules.md) and [old](docs/old.md#x).',
        '@docs/gone.md',
        '[web](https://example.com)',
        ...Array(210).fill('-'),
      ].join('\n'),
    });
    const res = run(root);
    assert.deepEqual(res.rules.sort(), [
      'agents/broken-link',
      'agents/broken-link',
      'agents/too-long',
    ]);
    assert.deepEqual(
      res.findings.filter((f) => f.rule === 'agents/broken-link').map((f) => f.line),
      [1, 2],
    );
  });
});

describe('cli', () => {
  it('exits 2 on a bad --fail-on or a missing folder', () => {
    assert.equal(spawnSync('node', [CLI, '.', '--fail-on', 'nope']).status, 2);
    assert.equal(spawnSync('node', [CLI, '/no/such/folder']).status, 2);
  });

  it('--fail-on never always exits 0', () => {
    const root = project({ '.env': 'A=1\n' }, { git: true });
    assert.equal(run(root, '--fail-on', 'never').status, 0);
  });

  it('--sarif writes SARIF 2.1.0 that GitHub code scanning reads', () => {
    const root = project({
      'package.json': '{"dependencies":{"@supabase/supabase-js":"2"}}',
      'AGENTS.md': '',
      'supabase/migrations/1_init.sql':
        'create table notes (id int);\ncreate table tags (id int);\n',
    });
    const res = spawnSync('node', [CLI, root, '--sarif'], { encoding: 'utf8' });
    assert.equal(res.status, 1);
    const sarif = JSON.parse(res.stdout);
    assert.equal(sarif.version, '2.1.0');
    const [runLog] = sarif.runs;
    assert.equal(runLog.tool.driver.name, 'ship-check');
    assert.deepEqual(
      runLog.tool.driver.rules.map((r: { id: string }) => r.id),
      ['supabase/rls-off'],
    );
    assert.equal(runLog.results.length, 2);
    const [first] = runLog.results;
    assert.equal(first.ruleIndex, 0);
    assert.equal(first.level, 'error');
    assert.equal(first.properties['security-severity'], '8.0');
    assert.deepEqual(first.locations[0].physicalLocation, {
      artifactLocation: { uri: 'supabase/migrations/1_init.sql', uriBaseId: '%SRCROOT%' },
      region: { startLine: 1 },
    });
  });

  it('--sarif on a clean project has no results and exits 0', () => {
    const root = project({ 'package.json': '{"name":"x"}', 'AGENTS.md': '# Rules\n' });
    const res = spawnSync('node', [CLI, root, '--sarif'], { encoding: 'utf8' });
    assert.equal(res.status, 0);
    assert.deepEqual(JSON.parse(res.stdout).runs[0].results, []);
  });

  it('exits 2 when both --json and --sarif are given', () => {
    assert.equal(spawnSync('node', [CLI, '.', '--json', '--sarif']).status, 2);
  });
});

describe('ignores', () => {
  const stripe = 'sk_' + 'live_' + 'a1B2c3D4e5F6g7H8i9J0k1L2';
  const gh = 'ghp' + '_' + 'A'.repeat(36);

  it('a ship-check-ignore comment on the line or the line above silences it', () => {
    const root = project({
      'src/a.ts': `// ship-check-ignore\nconst s = "${stripe}";\nconst g = '${gh}'; // ship-check-ignore\nconst t = '${gh}';\n`,
    });
    const res = run(root);
    assert.deepEqual(
      res.findings.map((f) => f.line),
      [4],
    );
    assert.equal(JSON.parse(res.stdout).ignored, 2);
  });

  it('.shipcheckignore silences paths, globs and one rule per path', () => {
    const root = project({
      '.shipcheckignore': `# reviewed\ntest/\n**/fixtures/**/*.ts\nsrc/b.ts secret/github-token\n`,
      'test/a.ts': `const s = "${stripe}";\n`,
      'pkg/fixtures/deep/a.ts': `const s = "${stripe}";\n`,
      'src/b.ts': `const s = "${stripe}";\nconst g = '${gh}';\n`,
      'src/test.ts': `const s = "${stripe}";\n`,
    });
    const res = run(root);
    assert.deepEqual(
      res.findings.map((f) => `${f.file} ${f.rule}`),
      ['src/b.ts secret/stripe-secret-key', 'src/test.ts secret/stripe-secret-key'],
    );
    const text = spawnSync('node', [CLI, root], { encoding: 'utf8' }).stdout;
    assert.match(text, /3 ignored/);
  });
});

describe('built bundle', () => {
  const stripe = 'sk_' + 'live_' + 'a1B2c3D4e5F6g7H8i9J0k1L2';
  const openai = 'sk-' + 'proj-' + 'Ab3'.repeat(10);

  it('finds a key Next.js inlined into .next/static even when .next is gitignored', () => {
    const root = project(
      {
        '.gitignore': '.next\n',
        'src/a.ts': 'export const k = process.env.NEXT_PUBLIC_OPENAI_KEY;\n',
        '.next/static/chunks/app/page-1a2b.js': `(()=>{const k="${openai}";fetch(u,{headers:{a:k}})})();`,
        '.next/server/app/page.js': `const s="${stripe}";`,
      },
      { git: true },
    );
    const res = run(root);
    assert.equal(res.status, 1);
    assert.deepEqual(
      res.findings.map((f) => `${f.file} ${f.rule} ${f.severity}`),
      ['.next/static/chunks/app/page-1a2b.js bundle/openai-key critical'],
    );
    assert.ok(!res.stdout.includes(openai), 'full key never printed');
  });

  it('reads dist only when it is a web build with index.html', () => {
    const files = { 'dist/assets/index-9f.js': `var k="${stripe}";` };
    const web = run(project({ ...files, 'dist/index.html': '<script src="/assets/index-9f.js">' }));
    assert.deepEqual(web.rules, ['bundle/stripe-secret-key']);
    const server = run(project({ ...files, 'dist/server.js': 'listen()' }));
    assert.deepEqual(server.rules, []);
  });

  it('reports source maps in the client build, once per build', () => {
    const files = {
      'build/index.html': '<script src="/static/js/main.js">',
      'build/static/js/main.js': 'var a=1;',
      'build/static/js/main.js.map':
        '{"version":3,"sources":["a.js"],"sourcesContent":["var a=1;"],"mappings":""}',
      'build/static/js/2.chunk.js.map': '{"version":3,"sources":[],"mappings":""}',
    };
    const res = run(project(files));
    assert.deepEqual(
      res.findings.map((f) => `${f.file} ${f.rule} ${f.severity}`),
      ['build/static/js/main.js.map bundle/source-map medium'],
    );
    assert.match(res.findings[0]?.title ?? '', /2 source map files .* 1 with your original source/);
    const bare = run(
      project({ ...files, 'build/static/js/main.js.map': '{"version":3,"mappings":""}' }),
    );
    assert.deepEqual(
      bare.findings.map((f) => f.severity),
      ['low'],
    );
    const server = run(project({ 'dist/server.js.map': '{}', 'dist/server.js': 'listen()' }));
    assert.deepEqual(server.rules, []);
  });

  it('skips the public Supabase anon key and honours .shipcheckignore', () => {
    const anon = jwt({ role: 'anon', iss: 'supabase' });
    const root = project({
      'build/index.html': `<script>window.k="${anon}"</script>`,
      'build/static/js/main.js': `var k="${stripe}";`,
      '.shipcheckignore': 'build/static/js/main.js bundle/stripe-secret-key\n',
    });
    const res = run(root);
    assert.deepEqual(res.rules, []);
    assert.match(spawnSync('node', [CLI, root], { encoding: 'utf8' }).stdout, /1 ignored/);
  });
});

describe('offline', () => {
  it('no source file imports a network module or calls fetch', () => {
    const src = new URL('../src/', import.meta.url).pathname;
    const files = readdirSync(src, { recursive: true })
      .map(String)
      .filter((f) => f.endsWith('.ts'));
    assert.ok(files.length > 5);
    for (const file of files) {
      const text = readFileSync(join(src, file), 'utf8');
      assert.doesNotMatch(
        text,
        /from 'node:(https?|http2|net|tls|dgram|dns)'|\bfetch\(|XMLHttpRequest|WebSocket/,
        file,
      );
    }
  });
});
