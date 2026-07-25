# PromptSign Spec 04 — Trust Policy (`promptsign/policy/v1`)

A valid signature only proves *someone* signed it. Policy decides **which
identities may sign which names**, and what happens when they didn't.

## Resolution order

1. `--policy <path>` CLI flag
2. `PROMPTSIGN_POLICY` env var
3. `<project>/.promptsign/policy.json`
4. `~/.promptsign/policy.json` (or `$PROMPTSIGN_HOME/policy.json`)
5. Built-in default: `{ "default": "warn", "rules": [{ "pattern": "*", "action": "warn", "tofu": true }] }`

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
- **tofu** — trust-on-first-use: on first successful verification the
  `(name → identity, keyid)` pair is pinned in `~/.promptsign/pins.json`.
  A later artifact with the same name but a **different identity or key hard-fails
  regardless of `action`** — this is the account-compromise / repo-transfer
  tripwire (threat T3), and it requires zero publisher onboarding.

## Unconditional rules (policy cannot waive)

- Integrity mismatches on a signed artifact (modified/missing/unlisted files).
- TOFU pin mismatches.
- An artifact with an *invalid* signature is never treated better than an
  unsigned one (an existing-but-broken signature warns even under `off`).

## Additional keys

`revocation_feed`, `revocation_feed_identity`, `revocation_feed_issuer`,
`max_feed_staleness`, and `on_feed_stale` are specified in
[Spec 06](06-revocation.md).

`require_attestations` (e.g. `promptsign/scan/v1`, `promptsign/review/v1`) and
`x509_root` (enterprise root pin) are reserved; no spec in this series defines
them yet.
