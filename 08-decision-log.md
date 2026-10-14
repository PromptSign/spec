# PromptSign spec 08: Decision log (`promptsign/decision-log/v1`)

Status: Draft v0.1 · 2026-10-13 · extends spec/04-policy.md

A verifier that blocks a skill keeps no record of it once the session ends.
The **decision log** keeps one: a JSON line per verification, appended to a
local file, with what was verified, who signed it, which policy rule decided,
and what the hook did. A security team can collect it from each
machine with no PromptSign server, and a log shipper (Filebeat, Fluent Bit, a
SIEM agent) can tail the file like any other.

The verifier only writes the file. Shipping it anywhere is outside this spec,
and writing it MUST NOT need network access.

## 1. Turning it on

Three sources turn the log on, each adding a file to write to:

| Source | File |
|---|---|
| `decision_log: true` in the managed policy ([Spec 04](04-policy.md) "Managed policy") | `<managed>/log/decisions-<user>.jsonl` |
| `decision_log: true` in the user's policy | `<PROMPTSIGN_HOME>/log/decisions-<user>.jsonl` |
| `--decision-log <file>` on `verify`, `verify-tree` or `hook` | `<file>` |

A verifier writes each record to every file that applies; the same path
appearing twice gets the record once. A project policy cannot turn the log
on: verifiers ignore its `decision_log` keys. A user policy cannot turn off the
managed one.

A managed policy that does not parse fails verification ([Spec 04](04-policy.md)),
and its verifier logs to the managed default so that failure leaves a record.

Two more keys shape a policy's file:

| Key | Default | Effect |
|---|---|---|
| `decision_log_dir` | `<managed>/log` or `<PROMPTSIGN_HOME>/log` | Directory of the log. A relative path resolves against the directory holding the policy file. |
| `decision_log_max_bytes` | `10485760` | Size at which the file rotates (§4). |

`<user>` is the operating system user the verifier runs as (`USER`, else
`USERNAME`, else `unknown`), with every character outside `A–Z a–z 0–9 . _ -`
replaced by `_`. One file per user means users of a shared machine never need
write access to each other's files. An administrator who wants the managed log
to survive its user creates `<managed>/log` so users can append to their
files but not delete them.

## 2. Records

Each line is one JSON object followed by `\n`. A writer emits the keys in
this order and leaves out a key that has no value instead of writing `null`:

| Key | Type | Meaning |
|---|---|---|
| `schema` | string | `promptsign/decision-log/v1` |
| `time` | string | When the record was written, RFC 3339 UTC with milliseconds |
| `verifier` | string | `<implementation>/<version>`, e.g. `promptsign-cli/0.7.0` |
| `user` | string | The operating system user, unsanitized |
| `harness` | string | `claude`, `codex` or `openclaw` for a hook; absent for a command |
| `event` | string | The hook event (`SessionStart`, `PreToolUse`, `UserPromptSubmit`, `install-policy`) or the command (`verify`, `verify-tree`) |
| `target` | string | Absolute path of what was verified; absent when nothing was found |
| `name` | string | The artifact name from the manifest, the file name when unsigned, or the skill name the harness asked for |
| `format` | string | `promptsign` or `oms` |
| `signed` | boolean | A signature was present, valid or not |
| `payload_digest` | string | `sha256:<hex>` of the signed payload, the digest a revocation entry matches ([Spec 06](06-revocation.md) §1.1) |
| `identity` | string | Signer identity |
| `issuer` | string | OIDC issuer (keyless) or `x509:sha256:<fingerprint>` (certificate mode) |
| `root` | string | Registry root the signature chained to ([Spec 07](07-trust-roots.md)) |
| `integrated_time` | integer | Unix seconds the signature was witnessed ([Spec 05](05-keyless.md)) |
| `result` | string | `pass`, `warn` or `fail` as verification decided; `unresolved` when the harness named a target the hook could not find; `error` when the verifier could not run |
| `decision` | string | `allow` or `block`: what the hook did with the event. Absent for a command. |
| `rule` | object | The policy rule that set the policy outcome (§3) |
| `revocation` | string | `clear`, `revoked`, `stale` or `unavailable` ([Spec 06](06-revocation.md) §4); `unchecked` when no feed applies |
| `policy_source` | string | The policy files consulted, as `verify` prints them |
| `findings` | array | `{ "level", "message" }` objects, as in `verify --json` |

An example, wrapped here for reading:

```json
{"schema":"promptsign/decision-log/v1","time":"2026-10-13T09:14:02.511Z",
 "verifier":"promptsign-cli/0.7.0","user":"dana","harness":"claude",
 "event":"PreToolUse","target":"/home/dana/.claude/skills/deploy",
 "name":"deploy","format":"promptsign","signed":true,
 "payload_digest":"sha256:9f2c…","identity":"https://github.com/acme/skills/.github/workflows/release.yml@refs/tags/v1.4.0",
 "issuer":"https://token.actions.githubusercontent.com","root":"sigstore-public",
 "integrated_time":1791364441,"result":"fail","decision":"block",
 "rule":{"layer":"managed","pattern":"acme/*","action":"enforce"},
 "revocation":"revoked","policy_source":"/etc/promptsign/managed-policy.json (managed)",
 "findings":[{"level":"error","message":"revoked — compromised release"}]}
```

A reader MUST ignore keys it does not know. Adding a key is a compatible
change within `v1`; removing one or changing its meaning is not.

## 3. The deciding rule

`rule` names the layer and rule behind the policy's part of the verdict:

| Key | Meaning |
|---|---|
| `layer` | `managed`, `user` (the user's file or the built-in default) or `project` |
| `pattern` | The matching rule's pattern, `*` for a layer's default |
| `action` | That rule's action, else the layer's `default`: `enforce`, `warn` or `off` |

The verifier evaluates every layer ([Spec 04](04-policy.md) "Layers"). The base layer's
rule decides unless a later layer makes the outcome worse; then the first
layer that did so decides. A record has no `rule` when the verifier never
consulted policy: an invalid signature, or a target the hook could not find.

Integrity failures and revocation can fail an artifact whatever `rule` says;
`findings` records why.

## 4. Writing

A verifier appends whole lines and writes each batch with a single write.
Before writing, when the file is not empty and the batch would take it past
`decision_log_max_bytes`, it rotates: `<file>.3` becomes `<file>.4`, and so
on down to `<file>` becoming `<file>.1`. The verifier drops the oldest copy
and keeps at most four. Writers of one file SHOULD hold a lock while they
rotate and append; the reference CLI locks `<file>.lock`.

A failed write MUST NOT change a verdict or a hook decision. The verifier
reports the failure on stderr and goes on.

## 5. What each hook logs

| Event | Records |
|---|---|
| `SessionStart` | One per verified file. `decision` is `block` on every record when strict mode stopped the session. |
| `PreToolUse` (Claude Code `Skill`) | One for the skill; `unresolved` when it was not found on disk, blocked only in strict mode |
| `PreToolUse` (Codex `Bash`), `UserPromptSubmit` | One per skill the command or the prompt reaches, up to the first that blocks |
| `install-policy` (OpenClaw) | One for the staged source |

A hook writes nothing for a tool call that reaches no instruction file.
