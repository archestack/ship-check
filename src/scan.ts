import { agentFiles } from './checks/agent-files.js';
import { apiAuth } from './checks/api-auth.js';
import { bundleSecrets, bundleSourceMaps } from './checks/bundle.js';
import { cookies } from './checks/cookies.js';
import { envFiles } from './checks/env-files.js';
import { firebase } from './checks/firebase.js';
import { secrets } from './checks/secrets.js';
import { supabase } from './checks/supabase.js';
import { rateLimit } from './checks/rate-limit.js';
import { webhooks } from './checks/webhook.js';
import { loadProject } from './files.js';
import { applyIgnores } from './ignore.js';
import { type Finding, SEVERITIES } from './types.js';

export const CHECKS = [
  secrets,
  bundleSecrets,
  bundleSourceMaps,
  envFiles,
  supabase,
  firebase,
  apiAuth,
  webhooks,
  rateLimit,
  cookies,
  agentFiles,
];

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
  return { root, filesScanned: project.files.length + project.bundle.length, findings, ignored };
};
