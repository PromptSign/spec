# PromptSign spec 06 — Revocation feed

Status: Draft v0.1 · 2026-07-13 · extends spec/04-policy.md, spec/05-keyless.md

A valid signature stays valid forever — cryptography cannot retract it (D6,
threat T6). The **revocation feed** is how "it was fine yesterday, kill it
today" reaches every verifier: a compact, **keyless-signed**, append-only list of
revoked identities, artifact digests, and transparency-log indices. It is fetched
opportunistically, cached locally, and consulted **fully offline** during verify.
Neither a certificate revocation list (CRL) nor the Online Certificate Status
Protocol (OCSP) is used — both put an online certificate authority in the verify
hot path, the wrong tradeoff for a CLI that must work on a plane (D6).

## 1. Feed document

The feed is the Dead Simple Signing Envelope (DSSE) **payload** of a keyless
bundle (spec/05). The payload bytes are a single JSON object:

```json
{
  "schema": "promptsign/revocation/v1",
  "generatedAt": "2026-07-13T00:00:00.000Z",
  "entries": [
    { "type": "identity", "identity": "repo:github.com/acme/*",
      "issuer": "https://token.actions.githubusercontent.com",
      "from": "2026-07-01T00:00:00.000Z", "reason": "session-compromise" },
    { "type": "digest", "payloadDigest": "sha256:1a2b…", "reason": "malware" },
    { "type": "logIndex", "logIndex": 12345678, "reason": "mis-issued" }
  ]
}
```

- `generatedAt` is ISO-8601 UTC (same shape as a manifest `created`). It drives
  freshness (§4).
- `entries` is append-only by convention; verifiers do not require ordering.

### 1.1 Entry kinds

Each entry has a `type` and an optional human-readable `reason`. The match keys map
onto values a verifier already extracts from the bundle under test (spec/05 §4):

| `type`     | Fields                          | Matches                                                                 |
|------------|---------------------------------|-------------------------------------------------------------------------|
| `identity` | `identity` (glob), `issuer?` (glob), `from?` | leaf-certificate SAN identity + Fulcio issuer of a **keyless** bundle |
| `digest`   | `payloadDigest` = `sha256:<hex>`| `sha256` of the DSSE **payload** (the value in `spec.payloadHash`, spec/05 §4.4) |
| `logIndex` | `logIndex` (integer)            | `transparency.logIndex`                                                  |

- `identity.identity` / `identity.issuer` are globs with the same `*` semantics as
  policy rules (spec/04). An `identity` entry **only applies to keyless bundles** —
  a keyful (ed25519) bundle has no issuer and is subject to `digest`/`logIndex`
  entries only.
- `digest` and `logIndex` entries are **unconditional**: they name one specific
  signed artifact, so they revoke it regardless of when it was signed.

### 1.2 Timestamping (why `from` exists)

Revoking an *identity* must not retroactively invalidate every good artifact that
identity ever signed (D6). An `identity` entry with `from` revokes only
signatures whose Rekor `integratedTime` is **at or after** `from`:

> revoked ⇔ `identity` glob matches ∧ `issuer` glob matches (if present) ∧
> (`from` absent ∨ `integratedTime ≥ from`)

So "the release key custodian left on 2026-07-01, revoke everything signed as that
identity since" is `{ "type":"identity", "identity":"…", "from":"2026-07-01T…" }`,
and artifacts signed before that timestamp still verify. To kill a *specific* bad
artifact regardless of time, use a `digest` or `logIndex` entry.

## 2. Carriage and trust

The feed document is signed exactly like any keyless bundle (spec/05 §1), with one
difference: the DSSE `payloadType` is

```
application/vnd.promptsign.revocation+json
```

so a manifest bundle can never be replayed as a feed (and vice versa). The bundle is
served as JSON at the policy's `revocation_feed` URL.

**Who may sign the feed** is pinned by policy, not implied by a valid signature
(anyone can validly sign as themselves — spec/04 §1). A verifier accepts a feed only
if its authenticated signer matches the policy-configured feed identity:

- `revocation_feed_identity` — glob matched against the feed signer's SAN identity.
- `revocation_feed_issuer` — glob matched against the feed signer's Fulcio issuer.

A feed signed by anyone else is treated as *unavailable* (§4), never trusted.

## 3. Policy configuration

Added to the policy document (spec/04). All optional; absent `revocation_feed`
means revocation is not consulted (no behavior change):

```json
{
  "schema": "promptsign/policy/v1",
  "rules": [ … ],
  "revocation_feed": "https://feed.promptsign.dev/v1",
  "revocation_feed_identity": "feed@promptsign.dev",
  "revocation_feed_issuer": "https://accounts.google.com",
  "max_feed_staleness": "72h",
  "on_feed_stale": "warn"
}
```

- `max_feed_staleness` — a duration (`s`/`m`/`h`/`d` suffix, e.g. `"72h"`, `"7d"`).
  A cached feed older than this is *stale*.
- `on_feed_stale` — `"warn"` (default) or `"fail"`: how verification degrades when
  the feed is stale or missing (§4).

## 4. Verification algorithm (offline)

Runs after signature + integrity + policy (spec/04 §4), only when
`policy.revocation_feed` is set and this is not a signer self-check:

1. Load the cached feed bundle (`$PROMPTSIGN_REVOCATION_FILE` or
   `~/.promptsign/revocation.json`). Missing ⇒ **unavailable**.
2. Verify it as a keyless bundle (spec/05 §4, offline) and confirm its
   `payloadType`, `schema`, and signer identity/issuer against policy (§2).
   Any failure ⇒ **unavailable** (an unverifiable feed is never trusted).
3. Evaluate the bundle under test against every entry (§1.1). A match ⇒
   **revoked**: verification fails (`error`) with the entry `reason`, regardless of
   feed freshness.
4. If not revoked and the feed is stale by `max_feed_staleness` ⇒ **unavailable**.
5. **unavailable** degrades per `on_feed_stale`: `warn` adds a warning (verification
   still passes on that axis); `fail` fails. This is deliberate — a verifier that
   cannot consult a fresh revocation list should say so, and fleets that require
   freshness set `fail`.

Revocation **never** changes canonical digests or the manifest, so it does not
affect wire compatibility across implementations (spec/02): a bundle signed by one
implementation revokes identically in all of them.

## 5. Publishing (informative)

`promptsign revoke sign <entries.json>` stamps `generatedAt`, wraps the entries as
a `promptsign/revocation/v1` document, and signs it keyless (spec/05 §6) with the
revocation `payloadType`. Serving the resulting bundle from a CDN at the
`revocation_feed` URL is an operations concern outside this spec. Consumers refresh
their cache with `promptsign revoke fetch` (opportunistic; the only online step).
