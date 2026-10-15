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

### Host-owned bookkeeping

A closed-tree `scope: dir` manifest fails on any unlisted file, but a host
harness can write its own bookkeeping into a directory after it is signed. A
plugin cache directory managed by Claude Code is one such case: the runtime
writes `.in_use/<pid>` while a session holds the plugin, and `.orphaned_at`
once a newer version supersedes it. Neither file is part of the signed
artifact, and a genuine, correctly-signed release MUST still verify clean with
them present.

A verifier MUST therefore also treat the following as excluded, on the exact
same terms as the list above:

- `.in_use/` — a directory of host-written, per-session marker files.
- `.orphaned_at` — a host-written file holding a superseded-version timestamp.

This list is closed and host-owned, not signer-configurable. A publisher MUST
NOT be able to grow it: an `--exclude` flag or similar signer-supplied
exclusion would let a signer carve an unverified hole into their own bundle,
which defeats the purpose of a closed tree. Implementations MUST hardcode this
set and change it only when this spec changes.

## Verification requirements

A verifier MUST perform the following steps in order:

1. Verify the envelope signature ([Spec 03](03-bundle.md)).
2. Recompute every listed digest from disk. Fail if any digest mismatches or any referenced file is missing.
3. If `scope: dir`, fail if any unlisted file is present.
4. If `scope: dir`, fail if the tree contains a symbolic link or a Windows directory junction, whether or not the manifest lists its path. The walk MUST NOT follow it.
5. Evaluate the trust policy ([Spec 04](04-policy.md)).

Integrity failures (steps 2–4) are unconditional. Policy MUST NOT waive them for a signed artifact.

A signer MUST refuse to sign a tree that contains a symbolic link or a directory junction. With a link inside, the bundle carries content the publisher does not control: anyone who can write to the link's target adds files that no digest covers, and anyone who retargets the link changes what the host loads.
