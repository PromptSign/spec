# PromptSign spec 09: Approvals (`https://promptsign.dev/approval/v1`)

Status: Draft v0.1 · 2026-10-16 · extends spec/01-manifest.md, spec/04-policy.md, spec/06-revocation.md, spec/07-trust-roots.md

A signature says who published an artifact. An **approval** says that someone
else, such as an organization's reviewer, looked at these bytes and accepted
them. A policy can then require approvals: "load a skill only when
two of our AppSec reviewers approved this version", whoever wrote it and
whether or not its author signed it.

An approval is an in-toto Statement, signed keyless or in certificate mode
like any other PromptSign signature, whose subject is the artifact's content
digest (§1). It binds content: the same bytes stay approved when the author
re-signs them, signs them in another format, or never signs them at all.

## 1. Content listing and content digest

The **content listing** of an artifact is the list of files a signer would put
in its manifest ([01](01-manifest.md)), one line per file:

```
<sha256 hex of the file, per spec/02><space><space><path><LF>
```

- The files and their paths are those of a manifest built from the artifact on
  disk: every file of a directory except those spec/01 excludes, or a single
  file under its base name.
- Each digest is the one spec/02 assigns to the file, so an embedded
  `x-promptsign:` block (spec/03) is not part of it.
- Sort the lines by path, comparing UTF-8 bytes. The listing is UTF-8 with
  LF line endings and ends with an LF.

The **content digest** is the SHA-256 of the listing's bytes, in lower-case
hex. For an artifact with a valid PromptSign signature, whose integrity check
(spec/01) passed, the signed manifest's `files` produce the same listing.

A verifier MUST refuse to compute a listing for a tree that contains a
symbolic link or a directory junction, as a signer refuses to sign one.

## 2. Approval document

The approval is the DSSE payload of a signed bundle, with payloadType
`application/vnd.in-toto+json`:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "acme/semgrep-triage", "digest": { "sha256": "<content digest>" } }
  ],
  "predicateType": "https://promptsign.dev/approval/v1",
  "predicate": { "approvedAt": "2026-10-16T09:30:00Z", "note": "reviewed in PR 412" }
}
```

| Field | Rule |
|---|---|
| `_type` | Exactly `https://in-toto.io/Statement/v1`. |
| `subject` | One or more entries. The approval covers an artifact when any entry's `digest.sha256` equals its content digest. `name` is informative. |
| `predicateType` | Exactly `https://promptsign.dev/approval/v1`. |
| `predicate` | An object. Verifiers ignore its contents. `approvedAt` is the approver's RFC 3339 time and `note` a free-text comment. |

Because the subject is a digest over a byte string, any tool that signs an
in-toto attestation over a file can produce an approval: write the listing to
a file and attest that file with the predicate type above.

## 3. Carriage

A verifier accepts the same two carriages as for a revocation feed
([06 §2](06-revocation.md)): a PromptSign keyless bundle (spec/05), and a
Sigstore bundle (v0.1 to v0.3) with a DSSE envelope, signed keyless or in
certificate mode ([07 §3](07-trust-roots.md)). The signature may chain to
any root in the verifier's registry (spec/07 §2).

A verifier looks for approval files, each holding one bundle as JSON, in:

1. `<dir>/.promptsign/approvals/` for a directory artifact, or the
   `.promptsign/approvals/` directory beside a single-file artifact;
2. `<managed>/approvals/<content digest>/` ([04](04-policy.md), managed
   directory);
3. `$PROMPTSIGN_HOME/approvals/<content digest>/` (`~/.promptsign` by
   default).

The first location travels with the artifact, so a reviewer can commit an
approval next to the skill it approves; spec/01 excludes `.promptsign/` from
manifests. The others let an administrator, or a fleet agent, distribute
approvals for artifacts they do not control. A verifier reads every `*.json`
file in these directories, skips any that does not parse, verify or cover the
artifact, and counts the rest.

## 4. Policy

A rule ([04](04-policy.md)) may set `approval`:

```json
{
  "pattern": "*",
  "action": "enforce",
  "approval": {
    "approvers": [
      { "identity": "*@acme.example",
        "issuer": "https://login.microsoftonline.com/<tenant>/v2.0",
        "trust_root": "acme/*" }
    ],
    "threshold": 2
  }
}
```

| Field | Rule |
|---|---|
| `approvers` | One or more accepted approvers: `identity`, a glob over the approval signer's identity (the SAN of a keyless certificate, the subject DN in certificate mode), and optional `issuer` and `trust_root` globs, matched as in a rule (spec/04). |
| `threshold` | Integer ≥ 1, default 1. The number of distinct approvers required, counting each identity and issuer pair once. |

An approval **counts** for an artifact when it verifies (§3) offline, covers
the artifact's content digest, its signer matches one of `approvers`, and the
revocation feed, when policy configures one, does not revoke it (§5). Fewer
counting approvals than `threshold` is a violation, which the rule's `action`
weighs like any other.

`approval` adds to a rule's other requirements. A rule that also
sets `identity`, `issuer`, `keyid` or `trust_root` still needs an author
signature that matches them. A rule that sets none of those accepts an
unsigned artifact once it has enough approvals, because the approvals then
vouch for the exact bytes in place of a signature. An invalid author
signature still counts as one (spec/04, unconditional rules), and integrity
failures stay unconditional.

The layering rules of spec/04 hold unchanged: a project or user policy over a
managed one may add an approval requirement, which only tightens. An
unsigned artifact passes on approvals only when the base layer's rule
accepts it.

A verifier that does not implement this spec MUST treat a rule that sets
`approval` as unmet.

## 5. Revocation

The revocation feed (spec/06) applies to approvals as it does to signatures:
an `identity` entry withdraws the approvals its identity made at or after
`from`, a `digest` entry matches the sha256 of an approval's DSSE payload, and
a `logIndex` entry its transparency log index. A revoked approval does not
count. A verifier weighs the feed's freshness once, on the artifact's own
verification (spec/06 §4).

Two approvers who sign byte-identical statements share one payload digest,
and a `digest` entry then withdraws both. `promptsign approve` sets
`approvedAt`, so each approval it signs has a digest of its own; to withdraw
one approver's share of an identical statement, use an `identity` or
`logIndex` entry.

## 6. Producing an approval (informative)

`promptsign approve <path>` computes the content listing, signs an approval
keyless with the approver's identity, and writes it to the artifact's
`.promptsign/approvals/` directory, or with `--store` to the approver's own
store (§3). `--note` sets the predicate's `note`, and `--listing` prints the
listing instead of signing, for use with other signing tools.
