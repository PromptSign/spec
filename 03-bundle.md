# PromptSign Spec 03 — Signature Bundle (`promptsign/bundle/v1`)

The manifest is signed inside a [DSSE](https://github.com/secure-systems-lab/dsse)
envelope. DSSE's pre-authentication encoding (PAE) binds the payload type, so a
signed manifest cannot be replayed as some other document type:

```
PAE = "DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload
signature = Ed25519-sign(PAE)
```

## Carriage

- Directory bundle → `<dir>/.promptsign/bundle.json`
- Standalone file → `<file>.psig.json` sidecar
- Embedded → an `x-promptsign:` line in a single Markdown file's YAML frontmatter
  (see below), excluded from the canonical form per Spec 02.

Detached carriage takes precedence on verify: an embedded block is read only when
no sidecar / `bundle.json` is found.

### Embedded carriage (`x-promptsign:`)

The bundle is carried as a **single frontmatter line**:

```
x-promptsign: <base64 of the bundle JSON>
```

so the signature travels inside the file it signs. Because the block is excised
from the canonical form before hashing (Spec 02 §5), it does not sign itself —
but that same excision is what would let unsigned bytes ride in, so verifiers
apply **strict validation** and **role gating**:

- **Strict validation (#1).** The excised region MUST be exactly one line whose
  value is *canonical* base64 (re-encoding the decoded bytes yields the identical
  token) that decodes to a well-formed bundle. More than one `x-promptsign:` line,
  any indented continuation line under it, non-canonical base64, or non-JSON is a
  **verification failure** — never silently ignored, never treated as unsigned.
- **Requires pre-existing frontmatter.** Signing inserts the line into an existing
  `---…---` block and never synthesizes one: canonicalization excises the marker
  line but not the `---` fences, so a synthesized block would change the canonical
  digest. Files without frontmatter cannot be embedded (use a sidecar).
- **Role gating (#2).** Embedding is refused for context-injected files — those
  agents load into context verbatim: `CLAUDE.md` and `AGENTS.md` (Claude
  Code/Codex) plus the OpenClaw workspace bootstrap set (`SOUL.md`, `TOOLS.md`,
  `IDENTITY.md`, `USER.md`, `HEARTBEAT.md`, `BOOTSTRAP.md`, `MEMORY.md`). On
  verify, an `x-promptsign:` marker in such a file is **never** a signature and
  its mere presence is an unconditional failure (with a warning), whether the
  file is checked standalone or as a member of a signed directory. Some of these
  basenames are generic (`USER.md`, `MEMORY.md`); the refusal is deliberately
  broad — a sidecar signature always remains available for such files.
  Structured-frontmatter files (`SKILL.md`, agent definitions) are eligible.

Embedded carriage is file-scope only; integrity checks the target file itself, so
a signed file that is renamed still verifies.

## Format

```json
{
  "schema": "promptsign/bundle/v1",
  "envelope": {
    "payloadType": "application/vnd.promptsign.manifest+json",
    "payload": "<base64 manifest JSON>",
    "signatures": [ { "keyid": "<sha256 of signer SPKI DER>", "sig": "<base64>" } ]
  },
  "signer": {
    "identity": "github:execv",
    "scheme": "ed25519",
    "publicKey": "<base64 SPKI DER>"
  }
}
```

- **keyid** = SHA-256 of the signer's SPKI DER; verifiers MUST recompute it from
  `signer.publicKey` and require a matching signature entry.
- **scheme**: `ed25519` (v1), or `keyless` when the signer is a certificate
  chain ([Spec 05](05-keyless.md)), whose leaf key may be Ed25519 or ECDSA
  P-256. No other algorithms; no negotiation.
- **identity**: free-form string in v1 local-key mode (defaults to
  `key:<keyid-prefix>`). In keyless mode ([Spec 05](05-keyless.md)) the `signer`
  block instead carries a short-lived X.509 certificate chain binding an OpenID
  Connect (OIDC) identity (issuer + subject) to the key, plus a
  transparency-log inclusion proof and timestamp — the bundle stays
  self-contained so **verification remains fully offline**.

## Trust semantics (important)

The embedded public key makes verification self-contained but proves only
*continuity*, not *identity*: anyone can generate a key and claim any identity
string. Meaningful trust comes from [Spec 04](04-policy.md) — policy rules
binding names to identities/keys, and TOFU pinning that hard-fails when a
name's signer changes. Keyless certificates ([Spec 05](05-keyless.md)) upgrade
identity claims to OIDC identities attested by a certificate authority, without
changing this bundle schema's shape.
