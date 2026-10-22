# AGENTS.md

- Node 22+, TypeScript, no runtime dependencies. Source in `src/`, one file per check in `src/checks/`.
- `npm run lint && npm run typecheck && npm test` must pass. Tests run the built CLI (`dist/cli.js`)
  against temp folders; build key-shaped test strings by concatenation so no file holds a real-looking key.
- The tool never makes a network call (a test enforces it). It only reads files and runs `git ls-files`.
- A new check returns findings with what, where, why and fix, each one sentence. Prefer missing a
  case over a noisy false positive; run it on a few real repos before merging.
- Releases: bump `package.json`, push tag `vX.Y.Z`; `release.yml` publishes with provenance.
