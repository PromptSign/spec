# PromptSign Spec 04 — Trust Policy (`promptsign/policy/v1`)

A valid signature only proves *someone* signed it. Policy decides **which
identities may sign which names**, and what happens when they didn't.

## Resolution order

The **user policy** is the first of:

1. `--policy <path>` CLI flag
2. `PROMPTSIGN_POLICY` env var
3. `~/.promptsign/policy.json` (or `$PROMPTSIGN_HOME/policy.json`)
4. Built-in default: `{ "default": "warn", "rules": [{ "pattern": "*", "action": "warn", "tofu": true }] }`

A **project policy**, `<project>/.promptsign/policy.json`, is evaluated *in
addition* to the user policy, never instead of it. The project directory is
where untrusted instruction files come from, so its policy may only tighten:

- Verifiers evaluate the user policy, then the project policy on the same
  input. Findings from both are reported (project findings prefixed
  `project policy: `) and the worse action wins.
- A project policy therefore cannot lower an action, switch checks `off`, or
  trust an identity, key or root the user policy does not accept.
- A project policy never checks or writes TOFU pins; pins belong to the user.
- Revocation settings (`revocation_feed` and related keys) are read from the
  user policy only.
- A project policy that does not parse is an error, like a user policy.

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

`revocation_feed`, `revocation_feed_identity`, `revocation_feed_issuer`,
`max_feed_staleness`, and `on_feed_stale` are specified in
[Spec 06](06-revocation.md). `on_trust_bundle_stale` is specified in
[Spec 07](07-trust-roots.md) §5.6. All of them are read from the user policy
only.

`require_attestations` (e.g. `promptsign/scan/v1`, `promptsign/review/v1`) is
reserved; no spec in this series defines it yet. Enterprise roots are
`trust_root` (spec/07).
