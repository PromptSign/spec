# Rekor v2 fixtures

Shared fixtures for the [07](../../../07-trust-roots.md) §6 conformance checks
on Rekor v2 entries and RFC 3161 timestamps ([05](../../../05-keyless.md) §3.2,
§3.3). Every implementation runs the same checks on these files and must reach
the verdicts below.

An organization, `acme`, runs one test deployment with a Fulcio-style CA, a
Rekor v1 log (ECDSA P-256), a Rekor v2 log (Ed25519, origin
`rekor-eb2cf13b.test`) and a timestamp authority with its own root.
`trusted_root.json` describes all four. Its keys derive from fixed seeds and
protect nothing.

`promptsign-core`'s `tests/conformance_fixtures.rs` wrote these files. Every
time in them is fixed and its signatures are deterministic, so regenerating
writes the same bytes:

```bash
PROMPTSIGN_FIXTURES_OUT=<../trust-roots> \
PROMPTSIGN_REKOR_V2_FIXTURES_OUT=<this directory> \
  cargo test --test conformance_fixtures -- --ignored
```

The repository stores this tree with `-text`: a line-ending conversion would
break every signature in it.

## Artifacts

Install the root first: `promptsign trust add acme-v2 --trusted-root
trusted_root.json --yes`. Each file in `artifacts/` has a keyless sidecar,
signed by `alice@acme.test` (issuer `https://sso.acme.test`) at
2026-10-01T12:00:00Z.

| File | Entry | Verdict |
|---|---|---|
| `signed.txt` | Rekor v2, timestamped | verifies, `root` `acme-v2` |
| `no-timestamp.txt` | Rekor v2, no timestamp | fails: no verified signing time |
| `timestamp-other-signature.txt` | Rekor v2, timestamp over other bytes | fails: no verified signing time |
| `timestamp-after-certificate.txt` | Rekor v2, timestamp an hour later | fails: outside the certificate's validity |
| `checkpoint-other-key.txt` | Rekor v2, checkpoint signed by another key | fails: no signature from the log |
| `checkpoint-witness-first.txt` | Rekor v2, unknown witness line before the log's | verifies |
| `proof-tampered.txt` | Rekor v2, one proof hash changed | fails: proof does not reach the root hash |
| `v1-with-timestamp.txt` | Rekor v1 with a timestamp five seconds later | verifies, signing time is the log's `integratedTime` |

Without the root installed, every file fails.
