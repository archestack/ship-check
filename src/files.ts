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

const readText = (root: string, path: string): string | undefined => {
  try {
    const full = join(root, path);
    if (statSync(full).size > MAX_BYTES) return undefined;
    const buffer = readFileSync(full);
    if (buffer.subarray(0, 8000).includes(0)) return undefined; // binary
    return buffer.toString('utf8');
  } catch {
    return undefined; // deleted but still in the index, or unreadable
  }
};

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
    git: fromGit !== undefined,
    exists: (path) => existsSync(join(root, path)),
  };
};
