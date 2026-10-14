# PromptSign Spec 04 — Trust Policy (`promptsign/policy/v1`)

A valid signature only proves *someone* signed it. Policy decides **which
identities may sign which names**, and what happens when they didn't.

## Layers

A verifier evaluates up to three policies on each artifact: the machine's
managed policy, the user's, and the project's.

The **user policy** is the first of:

1. `--policy <path>` CLI flag
2. `PROMPTSIGN_POLICY` env var, unless the managed policy sets `lock_env`
3. `~/.promptsign/policy.json` (or `$PROMPTSIGN_HOME/policy.json`)
4. Built-in default: `{ "default": "warn", "rules": [{ "pattern": "*", "action": "warn", "tofu": true }] }`,
   on a machine without a managed policy

The **base** layer is the managed policy (next section) when the machine has
one, else the user policy. Over a managed base, the user policy applies only
when the user has a policy file, and it tightens the base the way a project
policy does.

Verifiers evaluate a **project policy**, `<project>/.promptsign/policy.json`,
*in addition* to the others, never instead of them. Untrusted instruction files
come from the project directory, so its policy may only tighten.

Tightening layers follow these rules:

- Verifiers evaluate the base, then the user policy over a managed base, then
  the project policy, all on the same input. They report every finding, the
  user layer's prefixed `user policy: ` and the project's `project policy: `,
  and the worst action wins.
- A tightening layer therefore cannot lower an action, switch checks `off`, or
  trust an identity, key or root the base does not accept.
- A broken signature, or a marker in a context-injected file (spec/03), only
  warns when the matching action of every layer is `off`.
- TOFU pins belong to the user. The base checks them, or the user layer when
  the base's matching rule sets no `tofu`. A project policy never checks or
  writes them.
- A project policy never sets revocation settings (`revocation_feed` and
  related keys), `on_trust_bundle_stale` or `strict`.
- A policy at any layer that does not parse is an error.

## Managed policy

An administrator sets a managed policy for every user on a machine, as
managed settings do for Claude Code. It lives in the managed directory, which
users cannot write:

| Platform | Managed directory |
|---|---|
| Windows | `C:\ProgramData\PromptSign` |
| macOS | `/Library/Application Support/PromptSign` |
| Linux and other Unix | `/etc/promptsign` |

The directory holds:

- `managed-policy.json`: a `promptsign/policy/v1` document, the base layer.
- `trust/`: managed roots and trust bundles ([Spec 07](07-trust-roots.md) §2.4).
- `revocation.json`: a cached revocation feed ([Spec 06](06-revocation.md) §4).

Verifiers take the location from this table and not from an environment
variable, because a project can set variables for the hooks it runs.
`$PROMPTSIGN_MANAGED_DIR` replaces the directory only where the platform
directory does not exist, for tests and trials.

The managed policy accepts three more keys:

| Key | Effect |
|---|---|
| `strict` | `true`: hooks fail closed, as with `PROMPTSIGN_STRICT=1`. A user policy may set it too. The environment cannot turn it off. |
| `lock_env` | `true`: verifiers ignore `PROMPTSIGN_POLICY`, `PROMPTSIGN_HOME`, `PROMPTSIGN_TRUST_DIR` and `PROMPTSIGN_REVOCATION_FILE` and use the defaults under the user's home. A managed policy that does not parse counts as `true`. |
| `user_roots` | `false`: the registry leaves out the roots and trust bundles the user added ([Spec 07](07-trust-roots.md) §2.4). |

Verifiers ignore `lock_env` and `user_roots` in a user or project policy.
`promptsign policy show` prints each layer with the file it came from, then
the `strict`, `lock_env` and `user_roots` settings in effect.

## Format

```json
{
  "schema": "promptsign/policy/v1",
  "default": "warn",
  "rules": [
    { "pattern": "anthropic/*",
      "identity": "https://github.com/anthropic/*",
      "action": "enforce" },
    { "pattern": "corp/*",
      "keyid": "ab12…full sha256…",
      "action": "enforce" },
    { "pattern": "*", "action": "warn", "tofu": true }
  ]
}
```

- **First matching rule wins** (patterns are globs; `*` matches any run of
  characters). No match → implicit `{ pattern: "*", action: default }`.
- **action** — `enforce` (violations fail, exit 2), `warn` (violations warn,
  exit 0), `off` (no policy checks; crypto/integrity still apply).
- **identity** — glob the verified signer identity must match.
- **keyid** — exact keyid pin for the rule.
- **trust_root** — glob the name of the trust root (spec/07) the signature
  chained to must match, e.g. `sigstore-public`, a root added with
  `promptsign trust add`, or `acme/*` for every root of the bundle `acme`.
- **tofu** — trust-on-first-use: on first successful verification the
  `(name → identity, keyid)` pair is pinned in `~/.promptsign/pins.json`.
  A later artifact with the same name but a **different identity or key hard-fails
  regardless of `action`** — this is the account-compromise / repo-transfer
  tripwire (threat T3), and it requires zero publisher onboarding. For keyless
  CI signers, a new release tag of the same workflow is the same identity
  (spec/05 §5).

## Unconditional rules (policy cannot waive)

- Integrity mismatches on a signed artifact (modified/missing/unlisted files).
- TOFU pin mismatches.
- An artifact with an *invalid* signature is never treated better than an
  unsigned one (an existing-but-broken signature warns even under `off`).

## Additional keys

[Spec 06](06-revocation.md) specifies `revocation_feed`,
`revocation_feed_identity`, `revocation_feed_issuer`,
`revocation_feed_trust_root`, `max_feed_staleness` and `on_feed_stale`. Verifiers read them from the managed policy when
it sets `revocation_feed`, else from the user policy. [Spec 07](07-trust-roots.md)
§5.6 specifies `on_trust_bundle_stale`; `fail` in the managed or the user
policy wins.

[Spec 08](08-decision-log.md) specifies `decision_log`, `decision_log_dir`
and `decision_log_max_bytes`. Verifiers read them from the managed and the
user policy, and each of the two that sets `decision_log: true` gets a log.

`require_attestations` (e.g. `promptsign/scan/v1`, `promptsign/review/v1`) is
reserved; no spec in this series defines it yet. Enterprise roots are
`trust_root` (spec/07).
