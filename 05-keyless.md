# PromptSign spec 05 — Keyless (Sigstore) signing and verification

Status: Draft v0.2 · 2026-10-12 · extends spec/03-bundle.md

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

A signer that logs to a **Rekor v2** log staples an inclusion proof in place
of the signed entry timestamp, and RFC 3161 timestamps that date the signature:

```json
{
  "schema": "promptsign/bundle/v1",
  "envelope": { "payloadType": "…", "payload": "…", "signatures": [{ "keyid": "…", "sig": "…" }] },
  "signer": { "scheme": "keyless", "identity": "…", "issuer": "…", "certChain": ["…"] },
  "transparency": {
    "logId": "<hex log id (spec/07 §1)>",
    "logIndex": 4026478,
    "body": "<b64 canonicalized Rekor entry body (kind: hashedrekord, apiVersion 0.0.2)>",
    "inclusionProof": {
      "treeSize": 4026479,
      "rootHash": "<b64 RFC 6962 root hash>",
      "hashes": ["<b64 sibling hash>", "…"],
      "checkpoint": "<signed note: origin, tree size, root hash, then signatures>"
    }
  },
  "timestamps": ["<b64 DER RFC 3161 TimeStampResp over the envelope signature>"]
}
```

- `transparency` holds `signedEntryTimestamp` with `integratedTime` (Rekor v1)
  or `inclusionProof` (Rekor v2). A verifier given both uses the signed entry
  timestamp.
- `timestamps` is optional and holds at most 32 entries. A Rekor v2 log signs
  no time, so a v2 signature needs at least one timestamp that verifies, or it
  fails (§4 step 5).
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
  **ECDSA P-256** (interop with cosign-produced material). Rekor v2 rejects
  signatures that are not prehashed, so a signer logging there uses ECDSA.
- Identity: first SubjectAltName (SAN) of type `rfc822Name` (email) or
  `uniformResourceIdentifier` (CI workflows). Exactly one MUST be present.
- Issuer: Fulcio extension `1.3.6.1.4.1.57264.1.8` (DER UTF8String), with
  legacy fallback `1.3.6.1.4.1.57264.1.1` (raw bytes).
- Chain signatures supported: ECDSA P-256/SHA-256, ECDSA P-384/SHA-384 (with
  cross combinations), Ed25519.

## 3. Transparency entries

### 3.1 Rekor v1: `dsse` kind, apiVersion 0.0.1

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

### 3.2 Rekor v2: `hashedrekord` kind, apiVersion 0.0.2

A Rekor v2 log records the hash of the signed content, the signature and the
signing certificate:

```json
{ "apiVersion": "0.0.2", "kind": "hashedrekord", "spec": { "hashedRekordV002": {
    "data": { "algorithm": "SHA2_256", "digest": "<b64 SHA-256 of PAE(payloadType, payload)>" },
    "signature": {
      "content": "<b64, the same bytes as the envelope sig>",
      "verifier": { "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                    "x509Certificate": { "rawBytes": "<b64 DER leaf>" } } } } } }
```

The log keeps its entries in an RFC 6962 Merkle tree. An entry's leaf hash is
SHA-256 of a zero byte followed by the decoded `body`; `inclusionProof.hashes`
is its audit path, which verifiers check as RFC 9162 §2.1.3.2 describes.

The checkpoint is a C2SP signed note
([tlog-checkpoint](https://c2sp.org/tlog-checkpoint),
[signed-note](https://c2sp.org/signed-note)):

```
<origin>
<tree size, decimal>
<base64 root hash>
<optional extension lines>

— <origin> <base64 of key hint followed by signature>
```

- The origin is the host of the log's `baseUrl` (spec/07 §1).
- The key hint is the first four bytes of the log id.
- The log signs every line before the blank line, each with its newline. An
  Ed25519 log signs that text; an ECDSA P-256 log signs its SHA-256 and
  DER-encodes the signature.
- Verifiers ignore a signature line whose name or key hint is not the log's,
  such as a witness cosignature. A line from the log that does not verify fails
  the checkpoint, and so does a checkpoint with no line from the log.

### 3.3 RFC 3161 timestamps

Each entry of `timestamps` is a DER `TimeStampResp` (RFC 3161 §2.4.2), whose
token is CMS `SignedData` over a `TSTInfo`. A timestamp verifies against a
timestamp authority of the root (spec/07 §1) when:

1. Its status is granted (0) or granted with modifications (1).
2. `TSTInfo.messageImprint` is the hash, under its stated algorithm (SHA-256,
   SHA-384 or SHA-512), of the decoded envelope signature.
3. The token has exactly one signer. Its signed attributes name
   `id-ct-TSTInfo` as the content type and carry the digest of the
   encapsulated `TSTInfo`, and its signature over them verifies with the
   timestamping certificate's key (ECDSA, RSA PKCS#1 v1.5 or Ed25519).
4. The timestamping certificate, embedded in the token or listed by the
   authority, matches the signer identifier, has the `timeStamping` extended
   key usage, and chains through the authority's certificates to the
   authority's last certificate. Each issuing certificate on that path must be
   a CA, and every certificate must be valid at `genTime`.
5. `genTime` falls inside the authority's `validFor` (spec/07 §4).

The verified time is `genTime` in whole seconds. A timestamp that fails a check
gives no time, and does not by itself fail the signature.

## 4. Verification algorithm (offline)

Given a bundle with `signer.scheme == "keyless"` and the registry of trust
roots (spec/07). The built-in root is the trust store
(`$PROMPTSIGN_TRUST_DIR` or `~/.promptsign/trust/`: `fulcio.pem` — one or more
certificate authority certs; `rekor.pub` — the log's P-256 public keys, SPKI
PEM, oldest first). Steps 2 and 3 use the root the chain ends at, and
spec/07 §3.1 adds that root's validity windows:

1. **Envelope**: verify `signatures[i].sig` over `PAE(payloadType, payload)`
   with the leaf certificate's public key (Ed25519 raw / ECDSA-P256 DER).
2. **Chain**: `certChain[i]` must be signed by `certChain[i+1]`; the last chain
   cert must be signed by (or byte-equal to) a certificate authority of a
   keyless root.
3. **Log proof**: the log of that root whose id (spec/07 §1) equals the
   entry's `logId` must vouch for the entry.
   - Rekor v1: recompute the canonical entry JSON from `transparency.{body,
     integratedTime, logId, logIndex}` and verify `signedEntryTimestamp` with
     the log's P-256 key.
   - Rekor v2: verify `inclusionProof.checkpoint` with the log's key and
     origin (§3.2). Its tree size and root hash must equal `treeSize` and
     `rootHash`, and `hashes` must lead from the leaf hash of the decoded
     `body` at `logIndex` to that root.
4. **Entry binding**: decode `body`.
   - Rekor v1: `kind` MUST be `dsse`; `spec.payloadHash` MUST equal SHA-256
     of the decoded envelope payload; `spec.signatures[]` MUST contain the
     envelope's signature value. (`envelopeHash` is NOT recomputed — it would
     require JCS canonicalization of the whole envelope and adds nothing:
     SET→body→payloadHash+signature→PAE is already a complete chain of
     custody.)
   - Rekor v2: `kind` MUST be `hashedrekord` and `apiVersion` `0.0.2`;
     `data.digest` MUST equal the hash of PAE(payloadType, payload) under
     `data.algorithm`; `signature.content` MUST equal the envelope signature
     bytes; `signature.verifier.x509Certificate.rawBytes` MUST equal the leaf
     certificate.
5. **Time validity**: the signing times are the Rekor v1 `integratedTime`,
   which the SET signs, and the `genTime` of every timestamp that verifies
   against the root's timestamp authorities (§3.3). There MUST be at least
   one. Each MUST fall within the leaf certificate's `[notBefore, notAfter]`:
   the certificate was valid *when the signer used it*, and that check keeps
   10-minute certificates verifiable after they expire. A result's
   `integratedTime` is the Rekor v1 `integratedTime` when the entry has one,
   else the earliest verified timestamp.
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
  `keyid`.** The ephemeral key changes on every signing, so pinning a key
  fingerprint would be meaningless. Pin comparison: `identity`, `keyid`, and
  `issuer` must all match; a keyful↔keyless transition therefore hard-fails
  (keyid `"…"` vs `""`), which is the correct signal for a signer change.
- **The pinned identity of a CI workflow ignores its git ref.** A CI signer's
  identity is a workflow URI such as
  `https://github.com/acme/skills/.github/workflows/sign.yml@refs/tags/v1.4.2`,
  and every release tag changes the part after `@refs/`. When comparing a
  keyless pin, both identities are cut at the first `@refs/` if they start with
  `https://`; the rest must match exactly. Email identities and keyful
  identities are compared whole. The pin file keeps the full identity it first
  saw, so pins written before this rule need no migration. A policy rule's
  `identity` glob still sees the full URI, so a rule can require
  `*@refs/tags/*` to refuse signatures made from a branch.

## 6. Signing flow (informative)

1. Choose the services from a Sigstore SigningConfig v0.2 document:
   `$PROMPTSIGN_SIGNING_CONFIG`, else `signing_config.json` in the trust
   directory (spec/07 §2.3), else public Fulcio and Rekor v1 with no timestamp
   authority. From each list, keep the services whose `validFor` holds the
   current time and whose `majorApiVersion` the signer speaks (Fulcio 1, Rekor
   1 and 2, timestamp authority 1), then take the highest version and, among
   those, the latest start. A bundle staples one log entry, so the signer
   refuses a config whose selector asks for more than one log.
2. Obtain an OIDC token: `--identity-token <jwt>`, `$SIGSTORE_ID_TOKEN`, or
   GitHub Actions ambient credentials (`ACTIONS_ID_TOKEN_REQUEST_URL` +
   `_TOKEN`, audience `sigstore`).
3. Generate an ephemeral keypair: Ed25519 for a Rekor v1 log, ECDSA P-256 for
   a Rekor v2 log (§2). The proof of possession is a signature over the
   token's `email` claim, or its `sub` claim when it has no email.
4. `POST /api/v2/signingCert` (Fulcio) → short-lived certificate chain.
5. Sign `PAE(payloadType, payload)`. For each chosen timestamp authority,
   `POST` an RFC 3161 `TimeStampReq` over SHA-256 of the signature, with
   `certReq` set, and keep the `TimeStampResp` in `timestamps`.
6. Log the entry. Rekor v1: `POST /api/v1/log/entries` (kind `dsse`) →
   `{body, integratedTime, logID, logIndex, signedEntryTimestamp}`. Rekor v2:
   `POST /api/v2/log/entries` with a `hashedRekordRequestV002` → a
   `TransparencyLogEntry`; copy its `canonicalizedBody`, inclusion proof and
   checkpoint into `transparency` (§1).
7. Staple everything into the bundle; **discard the key**. Self-verify (full
   offline pipeline, policy skipped) before reporting success.

`$PROMPTSIGN_FULCIO_URL`, `$PROMPTSIGN_REKOR_URL` and `$PROMPTSIGN_TSA_URL`
replace the chosen URLs for enterprise deployments and tests. If you set either
of the first two, the signer ignores the trust directory's config, since that
file describes the public instance. Sigstore's default public config selects
Rekor v1 and a timestamp from `timestamp.sigstore.dev`. Sigstore publishes a
second config that selects its Rekor v2 log.
