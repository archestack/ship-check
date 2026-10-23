import { agentFiles } from './checks/agent-files.js';
import { apiAuth } from './checks/api-auth.js';
import { envFiles } from './checks/env-files.js';
import { firebase } from './checks/firebase.js';
import { secrets } from './checks/secrets.js';
import { supabase } from './checks/supabase.js';
import { loadProject } from './files.js';
import { applyIgnores } from './ignore.js';
import { type Finding, SEVERITIES } from './types.js';

export const CHECKS = [secrets, envFiles, supabase, firebase, apiAuth, agentFiles];

export interface ScanResult {
  root: string;
  filesScanned: number;
  findings: Finding[];
  /** Findings silenced by .shipcheckignore or a ship-check-ignore comment. */
  ignored: number;
}

export const scan = (root: string): ScanResult => {
  const project = loadProject(root);
  const { kept, ignored } = applyIgnores(
    project,
    CHECKS.flatMap((check) => check(project)),
  );
  const findings = kept.sort(
    (a, b) =>
      SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) ||
      a.file.localeCompare(b.file) ||
      (a.line ?? 0) - (b.line ?? 0),
  );
  return { root, filesScanned: project.files.length, findings, ignored };
};
