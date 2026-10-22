import { type Check, basename } from '../types.js';

const ENV_FILE = /^\.env(\..+)?$/;
const TEMPLATE = /\.(example|sample|template|dist|defaults?|schema)$/i;

export const envFiles: Check = ({ files, git }) =>
  files
    .filter((file) => ENV_FILE.test(basename(file.path)) && !TEMPLATE.test(file.path))
    .filter((file) => file.text.trim() !== '')
    .map((file) => ({
      rule: 'env/committed',
      severity: git ? 'high' : 'medium',
      title: git
        ? `${basename(file.path)} is committed or not covered by .gitignore`
        : `${basename(file.path)} found; make sure .gitignore covers it`,
      file: file.path,
      why: 'Env files hold the keys to your database, payments and AI accounts; once pushed, anyone with repo access has them.',
      fix: 'Add .env* to .gitignore, run `git rm --cached` on the file, rotate every key in it, and commit a .env.example with empty values.',
    }));
