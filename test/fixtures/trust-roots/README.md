# Trust-root fixtures

Shared fixtures for the [07](../../../07-trust-roots.md) §6 conformance checks.
Every implementation runs the same checks on these files and must reach the
verdicts below.

An organization, `acme`, runs two keyless deployments of its own (a Fulcio-style
CA and a Rekor-style log each): `prod`, current, and `old`, retired on
2026-07-01 by ending its CA's `validFor`. Both are test deployments whose keys
derive from fixed seeds. They protect nothing.

`promptsign-core`'s `tests/conformance_fixtures.rs` wrote these files. Every
time in them is fixed and its signatures are deterministic, so regenerating
writes the same bytes:

```bash
PROMPTSIGN_FIXTURES_OUT=<this directory> \
  cargo test --test conformance_fixtures -- --ignored
```

The repository stores this tree with `-text`: a line-ending conversion would
break every signature in it.

## Public root

`public/public-signed.txt` carries a real keyless signature from the
public-good Sigstore instance. `public/fulcio.pem` and `public/rekor.pub` are a
copy of the pinned public root (`promptsign-core/trust/`), the files
`promptsign trust fetch` writes to `$PROMPTSIGN_HOME/trust/`. With them there and
nothing else configured, the file verifies with `root` `sigstore-public`.

## Bundles

Each directory holds `trust-bundle.json` and its keyless sidecar
`trust-bundle.json.psig.json`, signed through `acme/prod`. Every version lists
one signer: `https://github.com/acme/trust/.github/workflows/publish.yml@refs/heads/main`
(issuer `https://token.actions.githubusercontent.com`, root `prod`).

| Directory | Version | Expires | Signed by | Verdict |
|---|---|---|---|---|
| `bundles/acme-v1` | 1 | 2126-01-01 | the listed signer | installs |
| `bundles/acme-v2` | 2 | 2126-01-01 | the listed signer | updates v1 |
| `bundles/acme-v2-unlisted-signer` | 2 | 2126-01-01 | `https://github.com/mallory/…`, not listed | refused, as an install and as an update |
| `bundles/acme-stale` | 1 | 2026-09-30 | the listed signer | refused as an install (expired); see below |
| `bundles/acme-feed` | 1 | 2126-01-01 | the listed signer | installs; its `revocationFeed` root resolves to `acme/prod` |
| `bundles/acme-feed-bad-root` | 1 | 2126-01-01 | the listed signer | refused: its `revocationFeed` names root `staging`, which the bundle does not hold |

With v2 installed, `bundles/acme-v1` is refused as a rollback.

## Artifacts

Each file in `artifacts/` has a keyless sidecar, signed by `alice@acme.test`
(issuer `https://sso.acme.test`).

| File | Signed through | Witnessed | Without `acme` | With `acme` installed |
|---|---|---|---|---|
| `prod-signed.txt` | `acme/prod` | 2026-10-01 | fails | verifies, `root` `acme/prod` |
| `before-retirement.txt` | `acme/old` | 2026-06-01 | fails | verifies, `root` `acme/old` |
| `after-retirement.txt` | `acme/old` | 2026-08-01 | fails | fails: outside the CA's `validFor` |

## Rotated intermediate

`rotated/` holds a third deployment, `acme-rotated`, that issues leaves from an
intermediate under an offline root. Its `trusted_root.json` lists two CA
entries: generation 1, the intermediate and the root, valid 2026-01-01 to
2026-07-01; and generation 2, the same root alone, valid from 2026-07-01.
`alice@acme.test` signed both files through intermediate 1, and their sidecars
staple the leaf, the intermediate and the root.

| File | Witnessed | With `rotated/trusted_root.json` added as `acme-rotated` |
|---|---|---|
| `rotated/before-rotation.txt` | 2026-06-01 | verifies, `root` `acme-rotated` |
| `rotated/retired-intermediate.txt` | 2026-08-01 | fails: intermediate 1 is outside its entry's `validFor`, though generation 2's open entry lists the root |

## Staleness

An expired bundle cannot be installed, so a check of staleness writes
`bundles/acme-stale` straight into the store (07 §5.5) as
`$PROMPTSIGN_HOME/trust/bundles/acme/`. `prod-signed.txt` then verifies with a
warning that the bundle expired, and fails under a user policy with
`"on_trust_bundle_stale": "fail"`.
