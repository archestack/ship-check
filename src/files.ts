import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { Project, SourceFile } from './types.js';

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  '.next',
  '.nuxt',
  '.svelte-kit',
  '.output',
  '.vercel',
  '.netlify',
  '.turbo',
  '.cache',
  'out',
  'coverage',
  'vendor',
]);
const SKIP_FILES =
  /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?)$|\.min\.js$|\.map$/;
const MAX_BYTES = 1_000_000;

// Files git would commit: tracked ones plus untracked ones .gitignore does not cover. Runs the local
// git binary only, with fsmonitor off so a hostile .git/config cannot run a command; undefined when the
// folder is not in a git work tree or git is missing.
const gitFiles = (root: string): string[] | undefined => {
  try {
    const out = execFileSync(
      'git',
      [
        '-c',
        'core.fsmonitor=false',
        'ls-files',
        '-z',
        '--cached',
        '--others',
        '--exclude-standard',
      ],
      {
        cwd: root,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
        maxBuffer: 256 * 1024 * 1024,
      },
    );
    return [...new Set(out.split('\0').filter(Boolean))];
  } catch {
    return undefined;
  }
};

const walk = (root: string, dir = ''): string[] =>
  readdirSync(join(root, dir), { withFileTypes: true }).flatMap((entry) => {
    const path = dir ? `${dir}/${entry.name}` : entry.name;
    if (entry.isDirectory()) return SKIP_DIRS.has(entry.name) ? [] : walk(root, path);
    return entry.isFile() ? [path] : [];
  });

const readText = (root: string, path: string, maxBytes = MAX_BYTES): string | undefined => {
  try {
    const full = join(root, path);
    if (statSync(full).size > maxBytes) return undefined;
    const buffer = readFileSync(full);
    if (buffer.subarray(0, 8000).includes(0)) return undefined; // binary
    return buffer.toString('utf8');
  } catch {
    return undefined; // deleted but still in the index, or unreadable
  }
};

// Build output the browser downloads. These folders are always client-side; `dist`, `build` and `out`
// count only with an index.html at their top, so a Node server build is not read as a web bundle.
const CLIENT_DIRS = [
  '.next/static',
  '.output/public',
  '.svelte-kit/output/client',
  '.vercel/output/static',
];
const SPA_DIRS = ['dist', 'build', 'out'];
const BUNDLE_FILE = /\.(m?js|cjs|html)$/;
const BUNDLE_MAX_BYTES = 10_000_000; // minified bundles run past the 1 MB source cap
const BUNDLE_MAX_FILES = 5_000;
const BUNDLE_BUDGET = 100_000_000; // a large static site can hold hundreds of MB of HTML

const dirExists = (root: string, dir: string): boolean =>
  statSync(join(root, dir), { throwIfNoEntry: false })?.isDirectory() ?? false;

/** Text files of the client build folders present on disk (they are usually gitignored). */
export const loadBundle = (root: string): SourceFile[] => {
  const dirs = [
    ...CLIENT_DIRS.filter((dir) => dirExists(root, dir)),
    ...SPA_DIRS.filter((dir) => dirExists(root, dir) && existsSync(join(root, dir, 'index.html'))),
  ];
  const paths = dirs
    .flatMap((dir) => walkAll(root, dir))
    .filter((path) => BUNDLE_FILE.test(path))
    // Script files first: inlined keys land there, and pages only repeat them.
    .sort((a, b) => Number(a.endsWith('.html')) - Number(b.endsWith('.html')))
    .slice(0, BUNDLE_MAX_FILES);
  const files: SourceFile[] = [];
  let bytes = 0;
  for (const path of paths) {
    const text = readText(root, path, BUNDLE_MAX_BYTES);
    if (text === undefined) continue;
    bytes += text.length;
    if (bytes > BUNDLE_BUDGET) break;
    files.push({ path, text });
  }
  return files;
};

// Like walk, but inside a build folder, where names such as `out` or `build` are real subfolders.
const walkAll = (root: string, dir: string): string[] =>
  readdirSync(join(root, dir), { withFileTypes: true }).flatMap((entry) => {
    const path = `${dir}/${entry.name}`;
    if (entry.isDirectory()) return entry.name === 'node_modules' ? [] : walkAll(root, path);
    return entry.isFile() ? [path] : [];
  });

export const loadProject = (root: string): Project => {
  const fromGit = gitFiles(root);
  const paths = (fromGit ?? walk(root)).filter(
    (path) => !path.split('/').some((part) => SKIP_DIRS.has(part)) && !SKIP_FILES.test(path),
  );
  const files: SourceFile[] = [];
  for (const path of paths) {
    const text = readText(root, path);
    if (text !== undefined) files.push({ path, text });
  }
  return {
    root,
    files,
    bundle: loadBundle(root),
    git: fromGit !== undefined,
    exists: (path) => existsSync(join(root, path)),
  };
};
