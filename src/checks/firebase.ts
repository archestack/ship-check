import { type Check, type Finding, lineAt } from '../types.js';

const ALLOW_IF_TRUE = /allow\s+([a-z, ]+?)\s*:\s*if\s+true\s*;/g;
const ALLOW_NO_CONDITION = /allow\s+([a-z, ]+?)\s*;/g;
const TEST_MODE =
  /request\.time\s*<\s*timestamp\.date\(\s*(\d{4})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})/g;
const RTDB_OPEN = /"\.(read|write)"\s*:\s*(?:true|"true")/g;

const writes = (actions: string): boolean => /write|create|update|delete/.test(actions);

const open = (file: string, line: number, actions: string): Finding => ({
  rule: writes(actions) ? 'firebase/open-write' : 'firebase/open-read',
  severity: writes(actions) ? 'critical' : 'high',
  title: `Firebase rules let anyone ${writes(actions) ? 'write' : 'read'} (${actions.trim()})`,
  file,
  line,
  why: 'Your Firebase config is public in the app, so anyone can call the database directly with it.',
  fix: 'Require sign-in and ownership, e.g. `allow read, write: if request.auth != null && request.auth.uid == userId;`, then deploy the rules.',
});

export const firebase: Check = ({ files }) =>
  files.flatMap((file) => {
    const found: Finding[] = [];
    if (file.path.endsWith('.rules')) {
      for (const m of file.text.matchAll(ALLOW_IF_TRUE))
        found.push(open(file.path, lineAt(file.text, m.index ?? 0), m[1] ?? ''));
      for (const m of file.text.matchAll(ALLOW_NO_CONDITION))
        found.push(open(file.path, lineAt(file.text, m.index ?? 0), m[1] ?? ''));
      for (const m of file.text.matchAll(TEST_MODE))
        found.push({
          rule: 'firebase/test-mode',
          severity: 'high',
          title: `Test-mode rules: open to anyone until ${m[1]}-${m[2]?.padStart(2, '0')}-${m[3]?.padStart(2, '0')}`,
          file: file.path,
          line: lineAt(file.text, m.index ?? 0),
          why: 'Until that date anyone can read and write everything; after it every request fails and the app breaks.',
          fix: 'Replace the date check with rules per collection that check request.auth.',
        });
    }
    if (/(^|\/)database\.rules\.json$/.test(file.path)) {
      for (const m of file.text.matchAll(RTDB_OPEN))
        found.push(open(file.path, lineAt(file.text, m.index ?? 0), m[1] ?? ''));
    }
    return found;
  });
