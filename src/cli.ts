#!/usr/bin/env node
import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { textReport } from './report.js';
import { scan } from './scan.js';
import { SEVERITIES, type Severity } from './types.js';

const HELP = `Usage: ship-check [folder] [options]

Scans a project folder for ship blockers: committed secrets and .env files, Supabase tables without
row level security, open Firebase rules, API routes with no auth check, and AGENTS.md / CLAUDE.md
problems. Runs offline; nothing leaves your machine.

Options:
  --json             print findings as JSON
  --fail-on <level>  exit 1 when a finding is at this level or worse:
                     critical, high (default), medium, low, never
  -v, --version      print the version
  -h, --help         print this help`;

const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

const main = (): number => {
  let args;
  try {
    args = parseArgs({
      allowPositionals: true,
      options: {
        json: { type: 'boolean' },
        'fail-on': { type: 'string', default: 'high' },
        version: { type: 'boolean', short: 'v' },
        help: { type: 'boolean', short: 'h' },
      },
    });
  } catch (error) {
    console.error(`${(error as Error).message}\n\n${HELP}`);
    return 2;
  }
  const { values, positionals } = args;
  if (values.help) return (console.log(HELP), 0);
  if (values.version) return (console.log(version), 0);

  const failOn = values['fail-on'];
  if (failOn !== 'never' && !SEVERITIES.includes(failOn as Severity)) {
    console.error(`--fail-on must be one of ${SEVERITIES.join(', ')}, never`);
    return 2;
  }
  const root = resolve(positionals[0] ?? '.');
  if (!statSync(root, { throwIfNoEntry: false })?.isDirectory()) {
    console.error(`Not a folder: ${root}`);
    return 2;
  }

  const result = scan(root);
  console.log(
    values.json ? JSON.stringify({ version, ...result }, null, 2) : textReport(result, version),
  );
  if (failOn === 'never') return 0;
  const limit = SEVERITIES.indexOf(failOn as Severity);
  return result.findings.some((f) => SEVERITIES.indexOf(f.severity) <= limit) ? 1 : 0;
};

process.exitCode = main();
