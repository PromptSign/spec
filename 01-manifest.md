# PromptSign Spec 01 — Bundle Manifest (`promptsign/manifest/v1`)

The unit of signing is a **manifest** covering every file in an artifact, never
an individual file. Skills bundle scripts the host executes; signing only the
.md leaves the executable payload unprotected (threat T5).

```json
{
  "schema": "promptsign/manifest/v1",
  "name": "trailofbits/semgrep-triage",
  "version": "1.4.2",
  "kind": "skill",
  "scope": "dir",
  "created": "2026-07-07T18:00:00Z",
  "files": [
    { "path": "SKILL.md",          "sha256": "9f8a…", "role": "entrypoint" },
    { "path": "scripts/triage.py", "sha256": "1c2d…", "role": "executable" },
    { "path": "references/x.md",   "sha256": "77ab…", "role": "reference" }
  ]
}
```

## Fields

- **name** — namespaced artifact name; the subject of trust-policy pattern
  matching and TOFU pinning. Defaults to the directory/file basename.
- **version** — semver string; reserved for rollback detection (threat T4).
- **kind** — `skill | agent | command | instructions | plugin | file`. Inferred:
  `SKILL.md` present → `skill`; any file under a top-level `commands/` directory →
  `command`; single context-injected file (`CLAUDE.md`, `AGENTS.md`, or an
  OpenClaw workspace bootstrap file — see the entrypoint list below) →
  `instructions`; single other .md → `agent`. First match wins, in that order.
- **scope** — `dir` (manifest covers a whole directory; **files on disk that are
  not listed are a verification failure**) or `file` (standalone file with
  sidecar signature; no extras check).
- **files[].path** — POSIX-style relative path. Paths containing `..` or
  absolute paths MUST be rejected by verifiers.
- **files[].sha256** — hex digest of the file's canonical form
  (see [Spec 02](02-canonicalization.md)).
- **files[].role**:
  - `entrypoint` — the instruction file the harness loads (`SKILL.md`,
    `CLAUDE.md`, `AGENTS.md`, or an OpenClaw workspace bootstrap file —
    `SOUL.md`, `TOOLS.md`, `IDENTITY.md`, `USER.md`, `HEARTBEAT.md`,
    `BOOTSTRAP.md`, `MEMORY.md` — at bundle root, or the single file itself).
  - `executable` — anything the host may run: files under `scripts/` or with an
    executable extension (`.py .sh .js .mjs .cjs .ts .ps1 .cmd .bat .exe .rb .pl .php` …).
    Hashed as **raw bytes**, never canonicalized. Policy may apply stricter rules.
  - `reference` — everything else.

## Excluded from manifests

`.promptsign/`, `.git/`, `node_modules/`, `__pycache__/`, `.venv/`, and
`*.psig.json` sidecars. File paths are sorted lexicographically for determinism.

## Verification requirements

A verifier MUST, in order: (1) verify the envelope signature
([Spec 03](03-bundle.md)); (2) recompute every listed digest from disk and fail
on any mismatch or missing file; (3) for `scope: dir`, fail on any unlisted
file present; (4) evaluate trust policy ([Spec 04](04-policy.md)). Integrity
failures (step 2–3) are unconditional — policy cannot waive them for a signed
artifact.
