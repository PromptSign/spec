# PromptSign spec 07: Trust roots and trust bundles

A verifier trusts a set of named **roots**. A signature verifies only when its
certificate chain ends at one of them. The public Sigstore root is built in, so
public keyless signatures verify with no configuration. An organization that
runs its own Sigstore, or signs with its own certificate authority, adds its
roots: one at a time from files (§2.2), or as a signed, versioned **trust
bundle** that the verifier keeps current (§5).

Verification stays offline. Only `trust fetch` and `trust add <url>` reach the
network, and only when the user runs them.

## 1. Root document

A root is a JSON document in the shape of Sigstore's `trusted_root.json`
(`mediaType` `application/vnd.dev.sigstore.trustedroot+json;version=0.1`).
Verifiers read these fields and ignore the rest:

| Field | Meaning |
|---|---|
| `certificateAuthorities[]` | One entry per CA. |
| `certificateAuthorities[].certChain.certificates[].rawBytes` | Base64 DER certificates, the CA itself and any intermediates. Any of them may terminate a signature's chain. |
| `certificateAuthorities[].validFor` | Optional `{ "start": RFC 3339, "end": RFC 3339 }`. Absent `end` means open-ended (§4). |
| `tlogs[]` | One entry per transparency log key. |
| `tlogs[].baseUrl` | The log's URL. Its host is the origin a Rekor v2 checkpoint names (spec/05 §3.2). |
| `tlogs[].publicKey.rawBytes` | Base64 SPKI DER of the log key. |
| `tlogs[].publicKey.keyDetails` | `PKIX_ECDSA_P256_SHA_256` or `PKIX_ED25519`. Verifiers skip entries with other key types. |
| `tlogs[].publicKey.validFor` | Optional window, as for CAs. |
| `tlogs[].logId.keyId` | Base64 log id. For a P-256 key it is SHA-256 of the SPKI DER. For an Ed25519 key it is the C2SP signed-note key hash: SHA-256 of the origin, a newline, the byte `0x01` and the 32-byte key. Verifiers recompute it and skip an entry whose stated id disagrees, and skip an Ed25519 entry without `baseUrl`. |
| `timestampAuthorities[]` | One entry per RFC 3161 timestamp authority (spec/05 §3.3). |
| `timestampAuthorities[].certChain.certificates[].rawBytes` | Base64 DER certificates: the timestamping certificate first, then any intermediates, the authority's anchor last. |
| `timestampAuthorities[].validFor` | Optional window for the timestamps' `genTime`, as for CAs. |

`ctlogs` is reserved. Verifiers ignore it.

A root with at least one usable log is a **keyless root**: signatures under it
carry a transparency entry (spec/05). A root with no usable log is a
**certificate root**: verifiers check signatures under it against the CA alone,
at the time a timestamp from the root's authorities gives, else at the current
time (§3.2). A certificate root never verifies a keyless
PromptSign signature, and a keyless root never verifies a certificate-mode one.

A root's **fingerprint** is the hex SHA-256 of its anchor certificate's DER.
The anchor is its self-signed certificate when it has one, else the last
certificate listed. A root's **subject** is the anchor's subject DN (RFC 4514,
no spaces after commas).

## 2. Registry

The registry is every root a verifier accepts, in this order:

1. **`sigstore-public`**, the built-in root: `fulcio.pem` and `rekor.pub` in the
   trust directory (`$PROMPTSIGN_TRUST_DIR`, else `$PROMPTSIGN_HOME/trust`).
   `rekor.pub` may hold several keys, oldest first, so a log key rotation keeps
   older signatures valid. The pair has no `validFor`. If the same directory
   holds `trusted_root.json`, the public Sigstore root document, the verifier
   joins the two into the built-in root: the document's CAs, logs and timestamp
   authorities first, then the pair's certificates and any log the document
   lacks. The Rekor v2 logs and the timestamp authority come from the document.
   Either source works on its own. `trust fetch` writes all three (§2.3).
2. **Named roots**: `$PROMPTSIGN_HOME/trust/roots/<name>.json`, by name.
3. **Bundle roots**: the roots of each installed trust bundle (§5.5), named
   `<bundle>/<root>`.

Named and bundle roots never follow `$PROMPTSIGN_TRUST_DIR`. A verifier never
reads a root from the directory being verified, and a project policy (spec/04)
cannot add one. A verifier reports a root file that does not parse as an
error and does not skip it.

### 2.1 Names

A root or bundle name is 1 to 64 characters from `a-z`, `0-9`, `-`, `_`, `.`,
not starting with `.`. `sigstore-public` is reserved. The `/` in a bundle
root's name cannot occur in a named root, so the two never collide.

### 2.2 Adding and removing roots

| Command | Effect |
|---|---|
| `trust add <name> --ca <pem>` | A certificate root from PEM CA certificates. |
| `trust add <name> --trusted-root <json>` | A root from a `trusted_root.json` file, such as one exported from a private Sigstore deployment. |
| `trust add <name> <url-or-file>` | A trust bundle (§5). |
| `trust list` | Every root in the registry: name, kind, fingerprint, subject, and for bundle roots the bundle's version and expiry. |
| `trust rm <name>` | Removes a named root, or a bundle and all its roots. |
| `trust fetch` | Refreshes the built-in root (§2.3) and every installed bundle (§5.4). |

Adding shows the root's subject and fingerprint (for a bundle, its signer,
version, expiry and every root) and asks the user to confirm. Non-interactive
use takes `--yes`. Adding refuses a name already in use and a root already
trusted under another name.

### 2.3 Fetching the built-in root

`trust fetch` writes the built-in root into the trust directory. It takes
`fulcio.pem` from Fulcio's `/api/v1/rootCert` and `rekor.pub` from Rekor's
`/api/v1/log/publicKey`. Those endpoints serve current material only, so
`trust fetch` keeps a cached file that holds an entry the response lacks,
unless you pass `--force`.

It takes `trusted_root.json` and `signing_config.json` (spec/05 §6) from the
targets `trusted_root.json` and `signing_config.v0.2.json` of Sigstore's TUF
repository (`$PROMPTSIGN_TUF_URL`, default `https://tuf-repo-cdn.sigstore.dev`).
The client follows the TUF 1.0 client workflow, starting from a root it ships
(`$PROMPTSIGN_TUF_ROOT` replaces it):

- Each newer root must carry a threshold of signatures from the previous
  root's keys and from its own.
- Timestamp, snapshot and targets metadata must carry their role's threshold,
  the version the metadata above them names, and an `expires` still ahead.
- Each target must match the length and hashes the targets metadata gives.
- The client keeps verified metadata under `<trust dir>/tuf/` and refuses a
  timestamp or snapshot older than the one it kept.

`trust fetch` writes the two documents over the cached copies without that
check, because Sigstore signs them and keeps retired entries with a closed
window. It fetches and checks all four files before it writes any. If you set
`$PROMPTSIGN_FULCIO_URL` or `$PROMPTSIGN_REKOR_URL`, it skips the TUF step
unless you also set `$PROMPTSIGN_TUF_URL`.

## 3. Choosing a root during verification

### 3.1 Keyless signatures

For a signature with a transparency entry (spec/05 §4):

1. The chain must end at a CA of a **keyless** root. That root is the
   signature's **anchor root**.
2. The entry's `logId` must name a log of the anchor root. The verifier does
   not consult the logs of other roots.
3. Every signing time (spec/05 §4 step 5) must fall inside the CA entry's
   `validFor` and the log entry's `validFor` (§4), in addition to the leaf
   certificate's own validity. The anchor root's timestamp authorities date
   the signature; no other root's do.

### 3.2 Certificate mode

For a signature that carries a certificate chain but no transparency entry,
such as an OpenSSF Model Signing bundle signed with a CA:

1. The chain must end at a CA of a **certificate** root.
2. The signing times are the `genTime` of each RFC 3161 timestamp in the
   bundle that verifies against that root's timestamp authorities (spec/05
   §3.3); a Sigstore bundle carries them in
   `verificationMaterial.timestampVerificationData.rfc3161Timestamps`. With
   none, the verifier uses the current time. It checks every certificate at
   each signing time, and each time must fall inside the CA entry's
   `validFor`. A timestamp lets a signature keep verifying after its
   certificate expires.
3. Each issuing certificate must be a CA (`basicConstraints` CA:TRUE), its
   `pathLenConstraint` must hold, and if it states key usages they must include
   `keyCertSign`. If the leaf states key usages they must include
   `digitalSignature`, and if it states extended key usages they must include
   `codeSigning` or `anyExtendedKeyUsage`.
4. The signer identity is the leaf's subject DN (RFC 4514, no spaces). The
   issuer is `x509:sha256:<anchor root fingerprint>`. TOFU (spec/04) pins
   that pair, so a later signature from the same subject under another CA
   fails.

### 3.3 Result

The verification result carries `root`: the anchor root's name, and for a
timestamped certificate-mode signature, `integratedTime`: the earliest
verified timestamp. A policy rule
may require it with `trust_root` (spec/04), a glob matched against that name,
so `acme/*` accepts every root of the bundle `acme`.

## 4. Validity windows

A `validFor` window is `[start, end]`, closed at both ends like Sigstore's
`TimeRange`. `start` is required, `end` is optional. A CA, log or timestamp
authority entry with no `validFor` is valid at every time.

The window bounds the time the signer made the signature. A publisher retires
a CA by ending its window, and signatures made before that end keep verifying.
For a keyless signature, the signing times are those of spec/05 §4 step 5:
the Rekor v1 `integratedTime` and the verified timestamps. The verifier checks
a certificate-mode signature at its verified timestamps, or at the current time
when it has none.

When the same certificate appears in several CA entries, a chain that ends at
it is accepted if any one of those entries' windows holds.

## 5. Trust bundles

An organization distributes and rotates its roots in a trust bundle: an
ordinary file with an ordinary PromptSign signature. The publisher signs it
with `promptsign sign` and needs no other tooling.

### 5.1 Document

```json
{
  "schema": "promptsign/trust-bundle/v1",
  "name": "acme",
  "version": 7,
  "issued": "2026-10-04T00:00:00Z",
  "expires": "2026-11-04T00:00:00Z",
  "roots": {
    "prod": { "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1", "certificateAuthorities": [ … ], "tlogs": [ … ] },
    "ca":   { "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1", "certificateAuthorities": [ … ], "tlogs": [] }
  },
  "signers": [
    {
      "identity": "https://github.com/acme/trust/.github/workflows/publish.yml@refs/heads/main",
      "issuer": "https://token.actions.githubusercontent.com",
      "root": "sigstore-public"
    }
  ]
}
```

| Field | Rule |
|---|---|
| `schema` | Exactly `promptsign/trust-bundle/v1`. |
| `name` | The publisher's suggested bundle name (§2.1). Informative: the user picks the installed name. |
| `version` | Integer ≥ 1. Strictly increases with every change. |
| `issued`, `expires` | RFC 3339. `expires` is later than `issued`. |
| `roots` | One or more root documents (§1), keyed by root name (§2.1). |
| `signers` | One or more accepted signers of the **next** version: `identity` (a glob, as in spec/04), `issuer` (exact), and `root`, the root the signer's certificate must chain to: `sigstore-public` or a key of this bundle's `roots`. |

The publisher places a keyless (spec/05) sidecar signature beside the bundle
file as `<file>.psig.json` (spec/03). For a bundle at `<url>`, verifiers fetch
the sidecar from `<url>.psig.json`.

### 5.2 Verifying a bundle

Given a candidate bundle `V` and, for an update, the installed version `C`:

1. **Signature.** Verify the sidecar over the bundle file's bytes as a keyless
   signature (spec/05 §4, offline), giving an identity, an issuer and an anchor
   root. Any failure rejects `V`.
2. **Signer.** The accepted signers are `C.signers` for an update and
   `V.signers` when installing. One of them must match: `identity` glob,
   `issuer` exact, and the anchor root must be that signer's `root`, resolved as
   the built-in root or a root of `C` (update) or of `V` (install).
3. **Document.** `V` satisfies §5.1. Every root parses (§1).
4. **Rollback.** For an update, `V.version` must be greater than `C.version`.
   An equal version with identical bytes is a no-op; a verifier rejects any
   other equal or lower version as a rollback.
5. **Freshness.** `V.expires` must be later than the current time, and
   `V.issued` no more than 5 minutes after it.

A rejected candidate leaves the installed version in place.

### 5.3 Installing (`trust add <name> <url-or-file>`)

An install has no installed version to check the signer against, so the user
decides, as for any new root. The verifier runs §5.2 against `V`'s own
signers and shows the signer that matched, the version, the expiry, and each
root's name, kind, subject and fingerprint. The user confirms, or passes
`--signer <identity>` (a glob the matching signer's identity must satisfy) with
`--yes` to install non-interactively. `<name>` defaults to `V.name`.

### 5.4 Updating and rotation (`trust fetch`)

`trust fetch` fetches each installed bundle from its source URL and installs it
if §5.2 accepts it. A verifier accepts an update only from a signer the
installed version names, so publishers rotate in steps:

- **New root or CA.** Add it to `roots` (with a `validFor` start) and publish
  the next version.
- **Retiring a CA.** Set its `validFor.end` rather than removing it, so its
  existing signatures keep verifying (§4). Removing a root stops trusting it
  for every signature, old and new.
- **New bundle signer.** Publish a version, signed by a current signer, whose
  `signers` lists the new one. The new signer may then sign later versions,
  which may drop the old signer.

A bundle installed from a file has no source URL. Re-running
`trust add <name> <file>` on the same name updates it under §5.2 rules (no
confirmation needed when an installed signer signed it).

### 5.5 Storage

An installed bundle lives in `$PROMPTSIGN_HOME/trust/bundles/<name>/`:
`trust-bundle.json` and `trust-bundle.json.psig.json` exactly as fetched, plus
`source.json` (`{ "url": … }`, absent for a file install). A verifier
re-verifies the stored bundle's signature (§5.2 steps 1 to 3, against its own
signers) every time it loads it, and treats a stored bundle that fails as an
error. Writes replace the directory atomically.

### 5.6 Staleness

A bundle past its `expires` is **stale**. Its roots still verify signatures, so
one missed fetch does not break signed artifacts. A signature anchored at
a stale bundle's root carries a finding, and the user policy (spec/04) decides
its weight:

```json
{ "on_trust_bundle_stale": "warn" }
```

`warn` (the default) adds a warning; `fail` fails. Only the user policy can set
it; a project policy cannot.

## 6. Conformance

An implementation that claims this spec MUST reach these verdicts on the shared
fixtures in [`test/fixtures/trust-roots`](test/fixtures/trust-roots):

- A public keyless signature verifies with the built-in root alone, with
  `root` `sigstore-public`.
- A signature made through an organization's own Fulcio and Rekor fails until
  you install the organization's bundle, then verifies offline with `root`
  `<bundle>/<root>`.
- A signature whose `integratedTime` falls outside its CA's or log's
  `validFor` window fails.
- The verifier rejects a bundle update from a signer the installed version does
  not list, and rejects an update with a lower version.
- A stale bundle's roots verify with a warning under the default policy, and
  fail under `on_trust_bundle_stale: "fail"`.

It MUST also reach these verdicts on the fixtures in
[`test/fixtures/rekor-v2`](test/fixtures/rekor-v2):

- A signature logged in a Rekor v2 log verifies with its timestamp, and fails
  without one, with a timestamp over another signature, and with a timestamp
  outside the certificate's validity.
- A checkpoint signed by another key fails; one with an unknown witness line
  first verifies. A tampered inclusion proof fails.
- A Rekor v1 signature with an added timestamp verifies with its own
  `integratedTime`.
