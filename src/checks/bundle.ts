import type { Check, Finding } from '../types.js';
import { findKeys } from './secrets.js';

// Keys the build put into files the browser downloads. The source can be clean while the bundle is not:
// Vite inlines every VITE_* variable and Next.js every NEXT_PUBLIC_* one at build time.
export const bundleSecrets: Check = ({ bundle }) =>
  bundle.flatMap((file): Finding[] =>
    findKeys(file.text).map((key) => ({
      rule: `bundle/${key.id}`,
      severity: 'critical',
      title: `${key.name} in the built app the browser downloads (${key.masked})`,
      file: file.path,
      line: key.line,
      why: 'Every visitor gets this file, so anyone can copy the key from the browser dev tools. A build often inlines it from an env variable with a VITE_ or NEXT_PUBLIC_ prefix.',
      fix: `Revoke it in ${key.where} and issue a new one. Drop the public prefix from the variable and call the service from a server route or edge function that reads the key there.`,
    })),
  );
