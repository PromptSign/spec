# PromptSign spec 05 — Keyless (Sigstore) signing and verification

Status: Draft v0.1 · 2026-07-07 · extends spec/03-bundle.md

Keyless mode replaces long-lived local Ed25519 keys with an **ephemeral key**
certified by a Fulcio-style certificate authority for ~10 minutes against an
**OpenID Connect (OIDC) identity**, and a **transparency-log entry** (Rekor)
stapled into the bundle. Identity — not key possession — is the unit of trust
(D4). Verification remains **fully offline**: everything needed is stapled;
trust roots are fetched once and cached.

## 1. Bundle extension

The DSSE (Dead Simple Signing Envelope) `envelope` is unchanged from spec/03. A
keyless bundle differs in the `signer` block and adds a `transparency` block:

```json
{
  "schema": "promptsign/bundle/v1",
  "envelope": { "payloadType": "…", "payload": "…", "signatures": [{ "keyid": "…", "sig": "…" }] },
  "signer": {
    "scheme": "keyless",
    "identity": "repo:github.com/acme/skills:ref:refs/tags/v1.4.2",
    "issuer": "https://token.actions.githubusercontent.com",
    "certChain": ["<b64 DER leaf>", "<b64 DER intermediate>", "…"]
  },
  "transparency": {
    "logId": "<hex sha256 of the log's public key (SPKI DER)>",
    "logIndex": 123456,
    "integratedTime": 1751900000,
    "signedEntryTimestamp": "<b64 ECDSA-P256/DER over the canonical entry>",
    "body": "<b64 canonicalized Rekor entry body (kind: dsse, apiVersion 0.0.1)>"
  }
}
```

- `certChain` is leaf-first DER, base64 (standard alphabet). The root MAY be
  omitted; it comes from the verifier's trust store.
- `signer.identity` / `signer.issuer` are **display hints only**. The
  authoritative values live in the leaf certificate; verifiers MUST fail if the
  hints do not match the certificate (prevents display spoofing).
- `scheme: "keyless"` is deliberate: v1 verifiers that only know `ed25519`
  fail closed with `unsupported signature scheme` rather than silently verifying
  against the embedded key without checking the certificate.
- The envelope `keyid` is the hex SHA-256 of the leaf SPKI DER — informational;
  it changes on every signing because the key is ephemeral.

## 2. Certificate profile (Fulcio)

- Leaf key algorithms: **Ed25519** (what `promptsign` generates) or
  **ECDSA P-256** (interop with cosign-produced material).
- Identity: first SubjectAltName (SAN) of type `rfc822Name` (email) or
  `uniformResourceIdentifier` (CI workflows). Exactly one MUST be present.
- Issuer: Fulcio extension `1.3.6.1.4.1.57264.1.8` (DER UTF8String), with
  legacy fallback `1.3.6.1.4.1.57264.1.1` (raw bytes).
- Chain signatures supported: ECDSA P-256/SHA-256, ECDSA P-384/SHA-384 (with
  cross combinations), Ed25519.

## 3. Transparency entry (Rekor `dsse` kind, apiVersion 0.0.1)

`transparency.body` is the base64 canonical entry as returned by the log:

```json
{ "apiVersion": "0.0.1", "kind": "dsse", "spec": {
    "envelopeHash":  { "algorithm": "sha256", "value": "…" },
    "payloadHash":   { "algorithm": "sha256", "value": "…" },
    "signatures": [ { "signature": "<b64, same as envelope sig>", "verifier": "<PEM leaf>" } ] } }
```

The **signed entry timestamp (SET)** is an ECDSA-P256/DER signature by the log
over the compact JSON `{"body":…,"integratedTime":…,"logID":…,"logIndex":…}`
(keys in that order — they are already lexicographic).

## 4. Verification algorithm (offline)

Given a bundle with `signer.scheme == "keyless"` and a trust store
(`$PROMPTSIGN_TRUST_DIR` or `~/.promptsign/trust/`: `fulcio.pem` — one or more
certificate authority certs; `rekor.pub` — the log's P-256 public key, SPKI
PEM):

1. **Envelope**: verify `signatures[i].sig` over `PAE(payloadType, payload)`
   with the leaf certificate's public key (Ed25519 raw / ECDSA-P256 DER).
2. **Chain**: `certChain[i]` must be signed by `certChain[i+1]`; the last chain
   cert must be signed by (or byte-equal to) a trust-store certificate
   authority.
3. **SET**: recompute the canonical entry JSON from `transparency.{body,
   integratedTime, logId, logIndex}` and verify `signedEntryTimestamp` with
   `rekor.pub`; `logId` MUST equal the hex SHA-256 of `rekor.pub`'s SPKI DER.
4. **Entry binding**: decode `body`; `kind` MUST be `dsse`;
   `spec.payloadHash` MUST equal SHA-256 of the decoded envelope payload;
   `spec.signatures[]` MUST contain the envelope's signature value.
   (`envelopeHash` is NOT recomputed — it would require JCS canonicalization of
   the whole envelope and adds nothing: SET→body→payloadHash+signature→PAE is
   already a complete chain of custody.)
5. **Time validity**: `integratedTime` MUST fall within the leaf certificate's
   `[notBefore, notAfter]` — i.e. the certificate was valid *when the log saw
   the signature*, which is what makes 10-minute certificates verifiable
   forever.
6. **Identity**: extract SAN identity + Fulcio issuer from the leaf; fail if
   the bundle's `signer.identity`/`signer.issuer` hints disagree.
7. Proceed to integrity + policy exactly as spec/04, with `identity` and
   `issuer` from step 6.

Steps 1–6 require **no network**. If the trust store is missing, keyless
verification fails with instructions to run `promptsign trust fetch` (one-time,
online). Neither a certificate revocation list (CRL) nor the Online Certificate
Status Protocol (OCSP) is consulted: revocation is the feed of spec/06 (D6).

## 5. Policy and trust-on-first-use (TOFU) for keyless identities

- Policy rules (spec/04) gain an optional `issuer` glob, matched against the
  certificate issuer: `{ "pattern": "acme/*", "identity":
  "repo:github.com/acme/*", "issuer": "https://token.actions.githubusercontent.com",
  "action": "enforce" }`. A rule with `issuer` never matches a keyful bundle
  (its issuer is absent).
- **TOFU pins for keyless bundles pin `identity` + `issuer` with an empty
  `keyid`** — the ephemeral key changes on every signing, so pinning a key
  fingerprint would be meaningless. Pin comparison: `identity`, `keyid`, and
  `issuer` must all match; a keyful↔keyless transition therefore hard-fails
  (keyid `"…"` vs `""`), which is the correct signal for a signer change.

## 6. Signing flow (informative)

1. Obtain an OIDC token: `--identity-token <jwt>`, `$SIGSTORE_ID_TOKEN`, or
   GitHub Actions ambient credentials (`ACTIONS_ID_TOKEN_REQUEST_URL` +
   `_TOKEN`, audience `sigstore`).
2. Generate an ephemeral Ed25519 keypair; proof-of-possession = signature over
   the token's `sub` claim.
3. `POST /api/v2/signingCert` (Fulcio) → short-lived certificate chain.
4. Sign `PAE(payloadType, payload)`; `POST /api/v1/log/entries` (Rekor, kind
   `dsse`) → `{body, integratedTime, logID, logIndex, signedEntryTimestamp}`.
5. Staple everything into the bundle; **discard the key**. Self-verify (full
   offline pipeline, policy skipped) before reporting success.

Default endpoints are public Sigstore (`fulcio.sigstore.dev`,
`rekor.sigstore.dev`), overridable via `$PROMPTSIGN_FULCIO_URL` /
`$PROMPTSIGN_REKOR_URL` (enterprise deployments, tests).
