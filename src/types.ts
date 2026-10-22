export const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
export type Severity = (typeof SEVERITIES)[number];

export interface Finding {
  rule: string;
  severity: Severity;
  title: string;
  file: string;
  line?: number;
  why: string;
  fix: string;
}

export interface SourceFile {
  /** Path relative to the scanned folder, with forward slashes. */
  path: string;
  text: string;
}

export interface Project {
  root: string;
  files: SourceFile[];
  /** True when the file list came from git, so ignored files are already left out. */
  git: boolean;
  exists: (relativePath: string) => boolean;
}

export type Check = (project: Project) => Finding[];

/** 1-based line number of a character offset. */
export const lineAt = (text: string, index: number): number => {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
};

export const basename = (path: string): string => path.slice(path.lastIndexOf('/') + 1);
