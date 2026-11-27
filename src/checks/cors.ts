import { type Check, type Finding, lineAt } from '../types.js';

const CODE = /\.(?:[cm]?[jt]sx?)$/;
const TEST_FILE = /\.(?:test|spec)\.|(^|\/)(?:__tests__|tests?)\//;
const WINDOW = 240;
// `origin: true` makes the cors middleware echo whatever Origin the request sent;
// `origin: (o, cb) => cb(null, true)` does the same through a callback.
const REFLECT_OPTION =
  /\borigin\s*:\s*(?:true\b|(?:\(\s*\w*\s*,\s*(\w+)\s*\)|\w+\s*,\s*(\w+))\s*=>\s*\w+\(\s*null\s*,\s*true\s*\))/g;
const CREDENTIALS_ON = /\bcredentials\s*:\s*true\b/;
// A hand-written header that copies the request's Origin back.
const ECHO_HEADER =
  /Access-Control-Allow-Origin['"`]?\s*[,:]\s*(?:req(?:uest)?\.headers(?:\.origin|\[\s*['"]origin['"]\s*\])|req(?:uest)?\.headers?\.get\(\s*['"]origin['"]\s*\)|(?:req|request|c\.req)\.header\(\s*['"]origin['"]\s*\))/i;
const CREDENTIALS_HEADER = /Access-Control-Allow-Credentials['"`]?\s*[,:]\s*['"`]?true\b/i;

const finding = (path: string, text: string, at: number, title: string): Finding => ({
  rule: 'cors/reflect-origin-credentials',
  severity: 'medium',
  title,
  file: path,
  line: lineAt(text, at),
  why: 'Any website a logged-in user visits can call this API with their cookies and read the answers, because the server agrees to every origin and also allows credentials.',
  fix: 'List the exact origins you serve (an array or a function that checks an allow-list) instead of reflecting the request, or drop credentials: true if the API does not need cookies.',
});

export const cors: Check = ({ files }) => {
  const findings: Finding[] = [];
  for (const file of files) {
    if (!CODE.test(file.path) || TEST_FILE.test(file.path)) continue;
    const { text } = file;
    if (!/cors|Access-Control-Allow/i.test(text)) continue;
    let reported = false;
    for (const match of text.matchAll(REFLECT_OPTION)) {
      const at = match.index ?? 0;
      const near = text.slice(Math.max(0, at - WINDOW), at + match[0].length + WINDOW);
      if (!CREDENTIALS_ON.test(near)) continue;
      findings.push(
        finding(file.path, text, at, 'CORS accepts every origin and allows credentials'),
      );
      reported = true;
    }
    if (reported || !CREDENTIALS_HEADER.test(text)) continue;
    const echo = ECHO_HEADER.exec(text);
    if (echo)
      findings.push(
        finding(
          file.path,
          text,
          echo.index,
          'The Origin header is copied into Access-Control-Allow-Origin with credentials allowed',
        ),
      );
  }
  return findings;
};
