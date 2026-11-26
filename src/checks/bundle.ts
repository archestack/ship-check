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

// One finding per build: a source map next to the bundle hands every visitor the original code, comments
// and file names included. Create React App writes them by default; Vite and Next.js only when asked to.
export const bundleSourceMaps: Check = ({ bundleMaps }) => {
  if (bundleMaps.length === 0) return [];
  const first = bundleMaps.find((map) => map.withSources) ?? bundleMaps[0];
  if (!first) return [];
  const withSources = bundleMaps.filter((map) => map.withSources).length;
  return [
    {
      rule: 'bundle/source-map',
      severity: withSources > 0 ? 'medium' : 'low',
      title: `${bundleMaps.length} source map file${bundleMaps.length === 1 ? '' : 's'} in the built app the browser downloads${withSources > 0 ? `, ${withSources} with your original source inside` : ''}`,
      file: first.path,
      why: 'Anyone can open the map in the browser dev tools and read your code as you wrote it: route names, hidden admin pages, comments, and any key or URL left in a source file.',
      fix: 'Turn production source maps off (CRA: GENERATE_SOURCEMAPS=false; Vite: build.sourcemap false; Next.js: productionBrowserSourceMaps false), or upload them to your error tracker and delete them from the deployed folder.',
    },
  ];
};
