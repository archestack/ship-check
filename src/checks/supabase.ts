import { type Check, type Finding, type SourceFile, lineAt } from '../types.js';

const NAME = String.raw`((?:"?\w+"?\.)?"?\w+"?)`;
const CREATE_TABLE = new RegExp(
  String.raw`create\s+table\s+(?:if\s+not\s+exists\s+)?${NAME}`,
  'gi',
);
const ENABLE_RLS = new RegExp(
  String.raw`alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${NAME}\s+enable\s+row\s+level\s+security`,
  'gi',
);
const DISABLE_RLS = new RegExp(
  String.raw`alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${NAME}\s+disable\s+row\s+level\s+security`,
  'gi',
);
const CREATE_POLICY = /create\s+policy[^;]*;/gi;
const OPEN_POLICY = /(?:using|with\s+check)\s*\(\s*true\s*\)/i;

// Env names a bundler ships to the browser that look like a server secret. The bare PUBLIC_ prefix
// (SvelteKit, Astro) counts only at a line start or after `env.`, so constants named PUBLIC_* do not.
const PUBLIC_SECRET_ENV =
  /(?:\b(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_)|(?<=^|env\.)PUBLIC_)[A-Z0-9_]*(?:SERVICE_ROLE|SERVICE_KEY|SECRET)[A-Z0-9_]*\b/gm;
// Docs that only name the variable are not shipped anywhere.
const DOCS = /\.(?:md|mdx|txt)$/;
const USE_CLIENT = /^\s*(?:\/\/[^\n]*\n\s*)*['"]use client['"]/;

const tableName = (raw: string): { schema: string; table: string } => {
  const parts = raw.replaceAll('"', '').toLowerCase().split('.');
  return parts.length === 2
    ? { schema: parts[0] ?? 'public', table: parts[1] ?? '' }
    : { schema: 'public', table: parts[0] ?? '' };
};

const usesSupabase = (files: SourceFile[]): boolean =>
  files.some(
    (file) =>
      file.path.startsWith('supabase/') ||
      file.path.includes('/supabase/') ||
      (file.path.endsWith('package.json') && file.text.includes('@supabase/')),
  );

const rls = (files: SourceFile[]): Finding[] => {
  const sql = files.filter((file) => file.path.endsWith('.sql'));
  const enabled = new Set<string>();
  const disabled = new Set<string>();
  for (const file of sql) {
    for (const m of file.text.matchAll(ENABLE_RLS)) {
      const { schema, table } = tableName(m[1] ?? '');
      enabled.add(`${schema}.${table}`);
      disabled.delete(`${schema}.${table}`);
    }
  }
  const findings: Finding[] = [];
  for (const file of sql) {
    for (const m of file.text.matchAll(CREATE_TABLE)) {
      const { schema, table } = tableName(m[1] ?? '');
      if (schema !== 'public' || enabled.has(`${schema}.${table}`)) continue;
      findings.push({
        rule: 'supabase/rls-off',
        severity: 'high',
        title: `Table public.${table} has no row level security`,
        file: file.path,
        line: lineAt(file.text, m.index ?? 0),
        why: 'Every table in the public schema is reachable through the API with the anon key from your site; without RLS anyone can read and change all rows.',
        fix: `Add \`alter table public.${table} enable row level security;\` and policies that check auth.uid() in a new migration.`,
      });
    }
    for (const m of file.text.matchAll(DISABLE_RLS)) {
      const { schema, table } = tableName(m[1] ?? '');
      if (schema !== 'public') continue;
      findings.push({
        rule: 'supabase/rls-disabled',
        severity: 'critical',
        title: `Row level security turned off on public.${table}`,
        file: file.path,
        line: lineAt(file.text, m.index ?? 0),
        why: 'With RLS disabled the table is open to anyone holding the anon key, which ships in your site.',
        fix: 'Remove the disable statement, enable RLS in a new migration, and write policies per action.',
      });
    }
    for (const m of file.text.matchAll(CREATE_POLICY)) {
      const statement = m[0];
      const action = /\bfor\s+(all|select|insert|update|delete)\b/i.exec(statement)?.[1] ?? 'all';
      if (action.toLowerCase() === 'select' || !OPEN_POLICY.test(statement)) continue;
      // An open insert is sometimes meant (a contact form); update, delete and all never are.
      const insertOnly = action.toLowerCase() === 'insert';
      findings.push({
        rule: 'supabase/open-write-policy',
        severity: insertOnly ? 'medium' : 'high',
        title: `Policy lets anyone ${action.toLowerCase() === 'all' ? 'write' : action.toLowerCase()} every row`,
        file: file.path,
        line: lineAt(file.text, m.index ?? 0),
        why: insertOnly
          ? '`with check (true)` lets every caller add rows; fine for a public form, a spam and storage hole anywhere else.'
          : '`using (true)` or `with check (true)` passes for every caller, so RLS is on but protects nothing.',
        fix: 'Compare the row owner with auth.uid(), e.g. `using (auth.uid() = user_id)`.',
      });
    }
  }
  return findings;
};

const BUCKETS = String.raw`"?storage"?\s*\.\s*"?buckets"?`;
const INSERT_BUCKET = new RegExp(
  String.raw`insert\s+into\s+${BUCKETS}\s*\(([^)]*)\)\s*values\s*([^;]*)`,
  'gi',
);
const UPDATE_BUCKET = new RegExp(
  String.raw`update\s+${BUCKETS}\s+set\s+[^;]*?\bpublic\s*=\s*true\b[^;]*`,
  'gi',
);
// Supabase CLI config: a [storage.buckets.<name>] section with `public = true`.
const CONFIG_BUCKET = /^\[storage\.buckets\.([\w-]+)\]([^[]*)/gm;

/** Splits `(a, 'b, c', f(d)), (e)` into tuples of top-level values. */
const tuples = (values: string): string[][] => {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let depth = 0;
  let quoted = false;
  for (const ch of values) {
    if (ch === "'") quoted = !quoted;
    if (!quoted && ch === '(') {
      if (depth++ === 0) continue;
    } else if (!quoted && ch === ')') {
      if (--depth === 0) {
        rows.push([...row, cell.trim()]);
        row = [];
        cell = '';
        continue;
      }
    } else if (!quoted && ch === ',' && depth === 1) {
      row.push(cell.trim());
      cell = '';
      continue;
    }
    if (depth > 0) cell += ch;
  }
  return rows;
};

const publicBucket = (file: string, line: number, name: string): Finding => ({
  rule: 'supabase/public-bucket',
  severity: 'medium',
  title: `Storage bucket ${name} is public`,
  file,
  line,
  why: 'Every file in a public bucket can be downloaded by anyone who has its URL, with no policy check; fine for avatars and site images, a leak for uploads, invoices or IDs.',
  fix: 'Keep the bucket private, add storage.objects policies that check auth.uid(), and hand out signed URLs.',
});

const buckets = (files: SourceFile[]): Finding[] =>
  files.flatMap((file) => {
    const found: Finding[] = [];
    if (file.path.endsWith('.sql')) {
      for (const m of file.text.matchAll(INSERT_BUCKET)) {
        const columns = (m[1] ?? '')
          .split(',')
          .map((c) => c.trim().replaceAll('"', '').toLowerCase());
        const at = columns.indexOf('public');
        if (at < 0) continue;
        for (const row of tuples(m[2] ?? '')) {
          if (row[at]?.toLowerCase() !== 'true') continue;
          const id = row[columns.indexOf('id')] ?? row[columns.indexOf('name')] ?? '';
          found.push(
            publicBucket(
              file.path,
              lineAt(file.text, m.index ?? 0),
              id.replaceAll("'", '') || '(unnamed)',
            ),
          );
        }
      }
      for (const m of file.text.matchAll(UPDATE_BUCKET)) {
        const id = /\b(?:id|name)\s*=\s*'([^']*)'/i.exec(m[0])?.[1] ?? '(all matching)';
        found.push(publicBucket(file.path, lineAt(file.text, m.index ?? 0), id));
      }
    } else if (file.path.endsWith('supabase/config.toml')) {
      for (const m of file.text.matchAll(CONFIG_BUCKET)) {
        if (/^\s*public\s*=\s*true\b/m.test(m[2] ?? ''))
          found.push(publicBucket(file.path, lineAt(file.text, m.index ?? 0), m[1] ?? ''));
      }
    }
    return found;
  });

const clientKeys = (files: SourceFile[]): Finding[] =>
  files.flatMap((file) => {
    const found: Finding[] = [];
    for (const m of DOCS.test(file.path) ? [] : file.text.matchAll(PUBLIC_SECRET_ENV)) {
      found.push({
        rule: 'client/public-secret-env',
        severity: 'critical',
        title: `${m[0]} is shipped to the browser`,
        file: file.path,
        line: lineAt(file.text, m.index ?? 0),
        why: 'Variables with a public prefix are copied into the JavaScript every visitor downloads.',
        fix: 'Drop the public prefix, use the value only in server code or an edge function, and rotate the key.',
      });
    }
    if (USE_CLIENT.test(file.text)) {
      const m = /SERVICE_ROLE|service_role/.exec(file.text);
      if (m)
        found.push({
          rule: 'supabase/service-role-in-client',
          severity: 'critical',
          title: 'Supabase service-role key used in a client component',
          file: file.path,
          line: lineAt(file.text, m.index),
          why: 'The service-role key skips every RLS policy; in a "use client" file it ends up in the browser.',
          fix: 'Use the anon key in the browser and move admin calls to a server route or edge function.',
        });
    }
    return found;
  });

export const supabase: Check = ({ files }) => [
  ...(usesSupabase(files) ? [...rls(files), ...buckets(files)] : []),
  ...clientKeys(files),
];
