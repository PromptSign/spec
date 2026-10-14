#!/usr/bin/env bash
# PromptSign conformance suite — wire-format agreement between two independent
# implementations of spec/01–05 and 07.
#
# One implementation is a spec of one. This suite is how you check that a second
# one agrees: bundles signed by either verify in the other, canonical digests
# match byte for byte, and both reach the same verdict under the same policy.
#
# Usage:
#   IMPL_A="node ../promptsign-node/src/index.mjs" \
#   IMPL_B="../promptsign-cli/target/debug/promptsign" IMPL_B_SIGN_ARGS="--local-key" \
#   ./conformance.sh
#
# Environment:
#   IMPL_A, IMPL_B              command that runs each implementation
#   IMPL_A_SIGN_ARGS, IMPL_B_SIGN_ARGS
#                               extra args that implementation needs to sign
#                               with a *local key* (spec/03 `ed25519`). Empty
#                               when local-key signing is the default.
#
# Defaults assume the PromptSign repos are checked out as siblings. If IMPL_B is
# absent the interop checks are skipped rather than failed, so a single
# implementation can still be run against the one-sided checks.
#
# Requires: bash, coreutils, and python3 or node (two checks parse bundle JSON).
# Exit: 0 if every check passed.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
WS="$(cd "$HERE/../.." && pwd)"                  # parent holding the repos

IMPL_A="${IMPL_A:-node $WS/promptsign-node/src/index.mjs}"
IMPL_A_SIGN_ARGS="${IMPL_A_SIGN_ARGS:-}"
IMPL_B="${IMPL_B:-}"
IMPL_B_SIGN_ARGS="${IMPL_B_SIGN_ARGS:---local-key}"

if [ -z "$IMPL_B" ]; then
  for c in "$WS"/promptsign-cli/target/release/promptsign{,.exe} \
           "$WS"/promptsign-cli/target/debug/promptsign{,.exe}; do
    [ -x "$c" ] && IMPL_B="$c" && break
  done
fi

WORK="$(mktemp -d)"
PASS=0; FAIL=0; SKIP=0

check() { # check <desc> <expected_exit> <actual_exit>
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "ok   - $1";
  else FAIL=$((FAIL+1)); echo "FAIL - $1 (expected exit $2, got $3)"; fi
}

skip() { SKIP=$((SKIP+1)); echo "skip - $1"; }

have_b() { [ -n "$IMPL_B" ]; }
b_signs() { [ "$B_SIGNS" = 1 ]; }

# Two checks need to read inside a bundle. Any JSON-capable runtime will do.
jsonrun() { # jsonrun <python-expr> <node-expr> <args...>
  if command -v python3 >/dev/null 2>&1; then python3 -c "$1" "${@:3}" 2>/dev/null
  elif command -v node >/dev/null 2>&1; then node -e "$2" "${@:3}" 2>/dev/null
  else return 127; fi
}

mkskill() { # mkskill <dir>
  mkdir -p "$1/scripts" "$1/references"
  printf '# demo-skill\r\nDoes things.  \r\n' > "$1/SKILL.md"    # CRLF + trailing ws
  printf 'print("hello")\n' > "$1/scripts/run.py"
  printf 'rules here\n' > "$1/references/rules.md"
}

# Can B produce a local-key signature? A verify-only build, or a release binary
# compiled without local-key support, can still verify — so the checks that need
# B to *sign* are skipped rather than reported as failures.
B_SIGNS=0
if [ -n "$IMPL_B" ]; then
  PROMPTSIGN_HOME="$WORK/probe" $IMPL_B keygen --identity "probe:capability" >/dev/null 2>&1 \
    && B_SIGNS=1
fi

echo "IMPL_A: $IMPL_A"
echo "IMPL_B: ${IMPL_B:-<none — interop checks will be skipped>}"
have_b && ! b_signs && echo "         (cannot sign with a local key — B will only be verified against)"
echo

# $IMPL_A / $IMPL_B are intentionally unquoted: they may carry arguments.

# ---- 1. A signs, B verifies --------------------------------------------------
export PROMPTSIGN_HOME="$WORK/home-a"
mkskill "$WORK/skill-a"
$IMPL_A keygen --identity "github:alice" >/dev/null 2>&1
$IMPL_A sign "$WORK/skill-a" $IMPL_A_SIGN_ARGS --name demo/skill-a --version 1.0.0 >/dev/null 2>&1
check "A signs a directory bundle" 0 $?

if have_b; then
  export PROMPTSIGN_HOME="$WORK/home-consumer"
  $IMPL_B verify "$WORK/skill-a" >/dev/null 2>&1
  check "B verifies an A-signed bundle" 0 $?

  # A modified executable payload must fail (spec/01 threat T5)
  printf 'print("evil")\n' > "$WORK/skill-a/scripts/run.py"
  $IMPL_B verify "$WORK/skill-a" | grep -q "modified: scripts/run.py"
  check "B reports the modified script by path" 0 $?
  $IMPL_B verify "$WORK/skill-a" >/dev/null 2>&1
  check "B blocks a tampered A-signed bundle" 2 $?
  printf 'print("hello")\n' > "$WORK/skill-a/scripts/run.py"

  # scope: dir — an unlisted file present on disk is a failure (spec/01)
  printf 'x\n' > "$WORK/skill-a/extra.txt"
  $IMPL_B verify "$WORK/skill-a" | grep -q "unlisted file present: extra.txt"
  check "B reports an unlisted file" 0 $?
  rm "$WORK/skill-a/extra.txt"

  # CRLF churn on markdown must NOT break the signature (spec/02)
  printf '# demo-skill\nDoes things.\n' > "$WORK/skill-a/SKILL.md"
  $IMPL_B verify "$WORK/skill-a" >/dev/null 2>&1
  check "B tolerates CRLF->LF churn via the canonical form" 0 $?
else
  skip "section 1 interop (no IMPL_B)"
fi

# ---- 2. B signs, A verifies --------------------------------------------------
if have_b && b_signs; then
  export PROMPTSIGN_HOME="$WORK/home-b"
  mkskill "$WORK/skill-b"
  $IMPL_B keygen --identity "github:bob" >/dev/null 2>&1
  check "B generates a local key" 0 $?
  $IMPL_B sign "$WORK/skill-b" $IMPL_B_SIGN_ARGS --name demo/skill-b --version 2.0.0 >/dev/null 2>&1
  check "B signs (including its own self-check)" 0 $?

  export PROMPTSIGN_HOME="$WORK/home-consumer"
  $IMPL_A verify "$WORK/skill-b" >/dev/null 2>&1
  check "A verifies a B-signed bundle" 0 $?
  printf 'print("evil")\n' > "$WORK/skill-b/scripts/run.py"
  $IMPL_A verify "$WORK/skill-b" >/dev/null 2>&1
  check "A blocks a tampered B-signed bundle" 2 $?
  printf 'print("hello")\n' > "$WORK/skill-b/scripts/run.py"
else
  skip "section 2 interop (B cannot sign)"
fi

# ---- 3. Digest equivalence ---------------------------------------------------
# The canonical form (spec/02) must produce identical digests everywhere, or
# nothing else in the spec holds.
if have_b && b_signs; then
  jsonrun '
import base64, json, sys
def files(p):
    b = json.load(open(p))
    return json.dumps(json.loads(base64.b64decode(b["envelope"]["payload"]))["files"], sort_keys=True)
sys.exit(0 if files(sys.argv[1]) == files(sys.argv[2]) else 1)
' '
const fs = require("fs");
const files = p => { const b = JSON.parse(fs.readFileSync(p, "utf8"));
  return JSON.stringify(JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()).files); };
process.exit(files(process.argv[1]) === files(process.argv[2]) ? 0 : 1);
' "$WORK/skill-a/.promptsign/bundle.json" "$WORK/skill-b/.promptsign/bundle.json"
  rc=$?
  if [ "$rc" = 127 ]; then skip "digest equivalence (needs python3 or node)";
  else check "identical canonical digests across implementations" 0 "$rc"; fi
else
  skip "section 3 digest equivalence (B cannot sign)"
fi

# ---- 4. Single-file sidecar, both directions ---------------------------------
if have_b; then
  printf '# project rules\r\n' > "$WORK/CLAUDE.md"
  export PROMPTSIGN_HOME="$WORK/home-a"
  $IMPL_A sign "$WORK/CLAUDE.md" $IMPL_A_SIGN_ARGS >/dev/null 2>&1
  export PROMPTSIGN_HOME="$WORK/home-consumer"
  $IMPL_B verify "$WORK/CLAUDE.md" >/dev/null 2>&1
  check "B verifies an A-signed sidecar file" 0 $?
else
  skip "section 4 sidecar interop (no IMPL_B)"
fi

if have_b && b_signs; then
  printf '# agent def\n' > "$WORK/reviewer.md"
  export PROMPTSIGN_HOME="$WORK/home-b"
  $IMPL_B sign "$WORK/reviewer.md" $IMPL_B_SIGN_ARGS >/dev/null 2>&1
  export PROMPTSIGN_HOME="$WORK/home-consumer"
  $IMPL_A verify "$WORK/reviewer.md" >/dev/null 2>&1
  check "A verifies a B-signed sidecar file" 0 $?
else
  skip "section 4 reverse sidecar (B cannot sign)"
fi

# ---- 5. TOFU pin interop -----------------------------------------------------
# A pin written by one implementation must be honoured by the other (spec/04).
if have_b && b_signs; then
  export PROMPTSIGN_HOME="$WORK/home-tofu"
  $IMPL_B verify "$WORK/skill-a" >/dev/null 2>&1
  grep -q "github:alice" "$WORK/home-tofu/pins.json"
  check "B writes a TOFU pin for an A-signed bundle" 0 $?

  # re-sign the same name under a different identity: the pin must hard-fail
  cp -r "$WORK/home-b" "$WORK/home-attacker"
  PROMPTSIGN_HOME="$WORK/home-attacker" $IMPL_B sign "$WORK/skill-a" $IMPL_B_SIGN_ARGS \
    --name demo/skill-a --version 1.0.1 >/dev/null 2>&1
  $IMPL_A verify "$WORK/skill-a" 2>/dev/null | grep -q "TOFU pin mismatch"
  check "A detects a pin mismatch written by B" 0 $?
  $IMPL_A verify "$WORK/skill-a" >/dev/null 2>&1
  check "A hard-fails on the pin mismatch" 2 $?
  $IMPL_B verify "$WORK/skill-a" >/dev/null 2>&1
  check "B hard-fails on its own pin mismatch" 2 $?
  $IMPL_B pin rm demo/skill-a >/dev/null 2>&1
  check "B removes a pin" 0 $?
else
  skip "section 5 TOFU interop (B cannot sign)"
fi

# ---- 6. Policy agreement -----------------------------------------------------
if have_b && b_signs; then
  mkdir -p "$WORK/home-policy"
  cat > "$WORK/home-policy/policy.json" <<'EOF'
{
  "schema": "promptsign/policy/v1",
  "default": "warn",
  "rules": [
    { "pattern": "demo/*", "identity": "github:alice", "action": "enforce" },
    { "pattern": "*", "action": "warn", "tofu": true }
  ]
}
EOF
  export PROMPTSIGN_HOME="$WORK/home-policy"
  $IMPL_B verify "$WORK/skill-b" >/dev/null 2>&1     # signed as github:bob -> enforce fail
  check "B enforces the identity rule" 2 $?
  $IMPL_A verify "$WORK/skill-b" >/dev/null 2>&1
  check "A enforces the identity rule identically" 2 $?
else
  skip "section 6 policy agreement (B cannot sign)"
fi

# ---- 7. verify-tree output parity --------------------------------------------
if have_b && b_signs; then
  export PROMPTSIGN_HOME="$WORK/home-consumer"
  mkdir -p "$WORK/tree/.claude/skills"
  cp -r "$WORK/skill-b" "$WORK/tree/.claude/skills/skill-b"
  printf '# unsigned\n' > "$WORK/tree/CLAUDE.md"
  $IMPL_A verify-tree "$WORK/tree" --no-pin-updates > "$WORK/out-a.txt" 2>&1; A_EXIT=$?
  $IMPL_B verify-tree "$WORK/tree" --no-pin-updates > "$WORK/out-b.txt" 2>&1; B_EXIT=$?
  check "verify-tree exit codes match" "$A_EXIT" "$B_EXIT"
  if diff -u "$WORK/out-a.txt" "$WORK/out-b.txt" > "$WORK/tree-diff.txt"; then
    PASS=$((PASS+1)); echo "ok   - verify-tree output byte-identical"
  else
    FAIL=$((FAIL+1)); echo "FAIL - verify-tree output differs:"; cat "$WORK/tree-diff.txt"
  fi
else
  skip "section 7 verify-tree parity (B cannot sign)"
fi

# ---- 8. Unknown signature scheme must fail closed ----------------------------
# spec/05 §1: a verifier rejects a scheme it does not know outright, and a
# bundle relabelled `keyless` without a certificate chain fails rather than
# verifying against the embedded key.
relabel() { # relabel <dir> <scheme>
  mkdir -p "$1"
  cp -r "$WORK/skill-b/." "$1/"
  jsonrun '
import json, sys
p, scheme = sys.argv[1], sys.argv[2]
b = json.load(open(p))
b["signer"]["scheme"] = scheme
open(p, "w").write(json.dumps(b, indent=2) + "\n")
' '
const fs = require("fs"), [p, scheme] = process.argv.slice(1);
const b = JSON.parse(fs.readFileSync(p, "utf8"));
b.signer.scheme = scheme;
fs.writeFileSync(p, JSON.stringify(b, null, 2) + "\n");
' "$1/.promptsign/bundle.json" "$2"
}
if have_b && b_signs; then
  relabel "$WORK/skill-x" "x-unknown"
  if [ $? = 127 ]; then
    skip "unknown-scheme fail-closed (needs python3 or node)"
  else
    relabel "$WORK/skill-kl" "keyless"
    export PROMPTSIGN_HOME="$WORK/home-consumer"
    $IMPL_A verify "$WORK/skill-x" >/dev/null 2>&1
    check "A fails closed on an unknown signature scheme" 2 $?
    $IMPL_A verify "$WORK/skill-x" 2>/dev/null | grep -q "unsupported signature scheme"
    check "A says why (not a silent pass)" 0 $?
    $IMPL_B verify "$WORK/skill-x" >/dev/null 2>&1
    check "B rejects the same unknown scheme" 2 $?
    $IMPL_A verify "$WORK/skill-kl" >/dev/null 2>&1
    check "A fails a keyless label with no certificate chain" 2 $?
    $IMPL_B verify "$WORK/skill-kl" >/dev/null 2>&1
    check "B fails the same relabelled bundle" 2 $?
  fi
else
  skip "section 8 fail-closed (B cannot sign)"
fi

# ---- 9. Invisible-Unicode refusal at sign time -------------------------------
# spec/02: bidi overrides and friends cannot be signed at all.
mkdir -p "$WORK/evil-skill"
printf 'Click \xe2\x80\xae evil \xe2\x80\xac now\n' > "$WORK/evil-skill/SKILL.md"  # U+202E
export PROMPTSIGN_HOME="$WORK/home-a"
$IMPL_A sign "$WORK/evil-skill" $IMPL_A_SIGN_ARGS >/dev/null 2>&1
check "A refuses to sign bidi-override content" 1 $?
if have_b && b_signs; then
  export PROMPTSIGN_HOME="$WORK/home-b"
  $IMPL_B sign "$WORK/evil-skill" $IMPL_B_SIGN_ARGS >/dev/null 2>&1
  check "B refuses the same content" 1 $?
else
  skip "invisible-Unicode refusal on B (B cannot sign)"
fi

# ---- 10. Context-injected marker gating --------------------------------------
# spec/03: an x-promptsign marker in a context-injected file is never a
# signature; its presence alone is an unconditional failure.
mkdir -p "$WORK/marker"
printf -- '---\nx-promptsign: abc\n---\n# Project\n' > "$WORK/marker/CLAUDE.md"
printf -- '---\nx-promptsign: abc\n---\n# Soul\n' > "$WORK/marker/SOUL.md"
export PROMPTSIGN_HOME="$WORK/home-consumer"
$IMPL_A verify "$WORK/marker/CLAUDE.md" >/dev/null 2>&1
check "A fails a marker-bearing CLAUDE.md" 2 $?
$IMPL_A verify "$WORK/marker/SOUL.md" >/dev/null 2>&1
check "A fails a marker-bearing SOUL.md (bootstrap file)" 2 $?
if have_b; then
  $IMPL_B verify "$WORK/marker/CLAUDE.md" >/dev/null 2>&1
  check "B fails a marker-bearing CLAUDE.md" 2 $?
  $IMPL_B verify "$WORK/marker/SOUL.md" >/dev/null 2>&1
  check "B fails a marker-bearing SOUL.md (bootstrap file)" 2 $?
  $IMPL_A verify-tree "$WORK/marker" --no-pin-updates > "$WORK/out-a-marker.txt" 2>&1; A_EXIT=$?
  $IMPL_B verify-tree "$WORK/marker" --no-pin-updates > "$WORK/out-b-marker.txt" 2>&1; B_EXIT=$?
  check "marker verify-tree exit codes match" "$A_EXIT" "$B_EXIT"
  if diff -u "$WORK/out-a-marker.txt" "$WORK/out-b-marker.txt" > "$WORK/marker-diff.txt"; then
    PASS=$((PASS+1)); echo "ok   - marker verify-tree output byte-identical"
  else
    FAIL=$((FAIL+1)); echo "FAIL - marker verify-tree output differs:"; cat "$WORK/marker-diff.txt"
  fi
fi

# ---- 11. Host-owned bookkeeping paths are excluded from both sides ----------
# spec/01 "Host-owned bookkeeping": a harness (e.g. Claude Code's plugin cache)
# writes .in_use/<pid> and .orphaned_at into an already-signed directory. A
# genuine, correctly-signed release must still verify clean with them present,
# on both implementations. Uses skill-b (signed once by B in section 2, never
# re-signed since) under a fresh PROMPTSIGN_HOME, since skill-a is deliberately
# left mid-attack by the TOFU checks in section 5.
if have_b && b_signs; then
  export PROMPTSIGN_HOME="$WORK/home-hostowned"
  mkdir -p "$WORK/skill-b/.in_use"
  printf '{"pid":60356}' > "$WORK/skill-b/.in_use/60356"
  printf '1788889068596' > "$WORK/skill-b/.orphaned_at"
  $IMPL_B verify "$WORK/skill-b" >/dev/null 2>&1
  check "B tolerates .in_use/ and .orphaned_at left by the host" 0 $?
  export PROMPTSIGN_HOME="$WORK/home-hostowned-a"
  $IMPL_A verify "$WORK/skill-b" >/dev/null 2>&1
  check "A tolerates the same host-owned paths" 0 $?
  rm -rf "$WORK/skill-b/.in_use" "$WORK/skill-b/.orphaned_at"
else
  skip "section 11 host-owned bookkeeping (B cannot sign)"
fi

# ---- 12. Trust roots and trust bundles (spec/07 §6) -------------------------
# Shared fixtures in fixtures/trust-roots (its README states every verdict): an
# organization's own Fulcio/Rekor roots arrive in a signed trust bundle. Each
# side runs every check with its own PROMPTSIGN_HOME; then their output must
# match byte for byte.
TR="$HERE/fixtures/trust-roots"
TR_SIGNER='https://github.com/acme/trust/*'

trust_roots() { # trust_roots <A|B> <command...>
  local side="$1"; shift
  local home="$WORK/home-tr-$side" art="$TR/artifacts"
  export PROMPTSIGN_HOME="$home"
  mkdir -p "$home"

  "$@" verify "$art/prod-signed.txt" >/dev/null 2>&1
  check "$side fails an organization-signed file before its bundle is installed" 2 $?
  "$@" trust add acme "$TR/bundles/acme-v2-unlisted-signer/trust-bundle.json" --signer "$TR_SIGNER" --yes >/dev/null 2>&1
  check "$side refuses to install a bundle signed by a signer it does not list" 1 $?
  "$@" trust add acme "$TR/bundles/acme-v1/trust-bundle.json" --signer "$TR_SIGNER" --yes >/dev/null 2>&1
  check "$side installs acme v1" 0 $?
  "$@" verify "$art/prod-signed.txt" > "$WORK/tr-$side-prod.txt" 2>&1
  check "$side verifies through acme/prod" 0 $?
  "$@" verify "$art/before-retirement.txt" > "$WORK/tr-$side-before.txt" 2>&1
  check "$side verifies a signature made while acme/old's CA was valid" 0 $?
  "$@" verify "$art/after-retirement.txt" > "$WORK/tr-$side-after.txt" 2>&1
  check "$side fails a signature made after acme/old's CA validFor ended" 2 $?
  grep -q '(root acme/prod)' "$WORK/tr-$side-prod.txt"
  check "$side names the root a signature anchored at" 0 $?
  "$@" trust add acme "$TR/bundles/acme-v2-unlisted-signer/trust-bundle.json" >/dev/null 2>&1
  check "$side refuses an update from a signer v1 does not list" 1 $?
  "$@" trust add acme "$TR/bundles/acme-v2/trust-bundle.json" >/dev/null 2>&1
  check "$side updates acme to v2" 0 $?
  "$@" trust add acme "$TR/bundles/acme-v1/trust-bundle.json" >/dev/null 2>&1
  check "$side refuses a rollback to v1" 1 $?
  "$@" trust list > "$WORK/tr-$side-list.txt" 2>&1

  # An expired bundle cannot be installed, so it goes straight into the store.
  export PROMPTSIGN_HOME="$home-stale"
  mkdir -p "$home-stale/trust/bundles/acme"
  cp "$TR/bundles/acme-stale/"* "$home-stale/trust/bundles/acme/"
  "$@" verify "$art/prod-signed.txt" > "$WORK/tr-$side-stale.txt" 2>&1
  check "$side verifies under a stale bundle (default: warn)" 0 $?
  grep -q 'trust bundle "acme" expired at 2026-09-30T00:00:00Z' "$WORK/tr-$side-stale.txt"
  check "$side reports the stale bundle" 0 $?
  printf '{"schema":"promptsign/policy/v1","default":"warn","on_trust_bundle_stale":"fail","rules":[]}\n' \
    > "$home-stale/policy.json"
  "$@" verify "$art/prod-signed.txt" --no-pin-updates >/dev/null 2>&1
  check "$side fails under on_trust_bundle_stale: fail" 2 $?

  # The public root: the files `trust fetch` writes, nothing else configured.
  if [ -f "$TR/public/public-signed.txt.psig.json" ]; then
    export PROMPTSIGN_HOME="$home-public"
    mkdir -p "$home-public/trust"
    cp "$TR/public/fulcio.pem" "$TR/public/rekor.pub" "$home-public/trust/"
    "$@" verify "$TR/public/public-signed.txt" > "$WORK/tr-$side-public.txt" 2>&1
    check "$side verifies a public keyless signature with no configuration" 0 $?
  else
    skip "$side public keyless signature (fixture not signed yet)"
  fi
}

# $IMPL_A / $IMPL_B are intentionally unquoted: they may carry arguments.
trust_roots A $IMPL_A
if have_b; then
  trust_roots B $IMPL_B
  for f in prod before after list stale public; do
    [ -f "$WORK/tr-A-$f.txt" ] || continue
    if diff -u <(sed "s|$WORK/home-tr-A|HOME|g" "$WORK/tr-A-$f.txt") \
               <(sed "s|$WORK/home-tr-B|HOME|g" "$WORK/tr-B-$f.txt") > "$WORK/tr-diff.txt"; then
      PASS=$((PASS+1)); echo "ok   - trust-root output byte-identical ($f)"
    else
      FAIL=$((FAIL+1)); echo "FAIL - trust-root output differs ($f):"; cat "$WORK/tr-diff.txt"
    fi
  done
else
  skip "section 12 on B and output parity (no IMPL_B)"
fi

# ---- 13. Rekor v2 entries and RFC 3161 timestamps (spec/05 §3.2-3.3) -------
# Shared fixtures in fixtures/rekor-v2 (its README states every verdict): a
# deployment with a Rekor v2 log and a timestamp authority, installed as a
# named root. Verdicts first, then byte-identical output across sides.
RV="$HERE/fixtures/rekor-v2"

rekor_v2() { # rekor_v2 <A|B> <command...>
  local side="$1"; shift
  local home="$WORK/home-rv-$side" art="$RV/artifacts" f
  export PROMPTSIGN_HOME="$home"
  mkdir -p "$home"

  "$@" verify "$art/signed.txt" --no-pin-updates >/dev/null 2>&1
  check "$side fails a Rekor v2 signature before its root is installed" 2 $?
  "$@" trust add acme-v2 --trusted-root "$RV/trusted_root.json" --yes >/dev/null 2>&1
  check "$side installs a root with a Rekor v2 log and a timestamp authority" 0 $?
  for f in signed checkpoint-witness-first v1-with-timestamp; do
    "$@" verify "$art/$f.txt" --no-pin-updates > "$WORK/rv-$side-$f.txt" 2>&1
    check "$side verifies $f.txt" 0 $?
  done
  for f in no-timestamp timestamp-other-signature timestamp-after-certificate \
           checkpoint-other-key proof-tampered; do
    "$@" verify "$art/$f.txt" --no-pin-updates > "$WORK/rv-$side-$f.txt" 2>&1
    check "$side fails $f.txt" 2 $?
  done
  "$@" verify "$art/signed.txt" --json --no-pin-updates > "$WORK/rv-$side-json.txt" 2>&1
  grep -q '"integratedTime": 1790856000' "$WORK/rv-$side-json.txt"
  check "$side reports the timestamp as the signing time" 0 $?
  cp "$home/trust/roots/acme-v2.json" "$WORK/rv-$side-root.txt" 2>/dev/null
}

rekor_v2 A $IMPL_A
if have_b; then
  rekor_v2 B $IMPL_B
  for f in signed checkpoint-witness-first v1-with-timestamp no-timestamp \
           timestamp-other-signature timestamp-after-certificate checkpoint-other-key \
           proof-tampered json root; do
    if diff -u "$WORK/rv-A-$f.txt" "$WORK/rv-B-$f.txt" > "$WORK/rv-diff.txt"; then
      PASS=$((PASS+1)); echo "ok   - Rekor v2 output byte-identical ($f)"
    else
      FAIL=$((FAIL+1)); echo "FAIL - Rekor v2 output differs ($f):"; cat "$WORK/rv-diff.txt"
    fi
  done
else
  skip "section 13 on B and output parity (no IMPL_B)"
fi

# ---- 14. Managed policy and trust (spec/04, spec/07 §2.4) ------------------
# An administrator's directory, stood in for by PROMPTSIGN_MANAGED_DIR: its
# policy is the base the user's and the project's can only tighten, its bundle
# is trusted by every user, user_roots: false drops the user's own bundle, and
# lock_env stops PROMPTSIGN_HOME from applying. The variable only works where
# the platform directory is absent, so the section skips on a managed machine.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) MANAGED_PLATFORM_DIR="/c/ProgramData/PromptSign" ;;
  Darwin) MANAGED_PLATFORM_DIR="/Library/Application Support/PromptSign" ;;
  *) MANAGED_PLATFORM_DIR="/etc/promptsign" ;;
esac
POLICY_V1='"schema":"promptsign/policy/v1"'

managed_layer() { # managed_layer <A|B> <command...>
  local side="$1"; shift
  local base="$WORK/mg-$side" art="$TR/artifacts"
  local m="$base/managed" home="$base/home" proj="$base/project"
  mkdir -p "$m" "$home" "$proj" "$base/os-home"
  printf '# rules\n' > "$proj/CLAUDE.md"
  export PROMPTSIGN_HOME="$home" PROMPTSIGN_MANAGED_DIR="$m"

  "$@" trust add acme "$TR/bundles/acme-v1/trust-bundle.json" --signer "$TR_SIGNER" --yes --managed >/dev/null 2>&1
  check "$side installs acme v1 into the managed directory" 0 $?
  [ -f "$m/trust/bundles/acme/trust-bundle.json" ]
  check "$side stores the managed bundle under <managed>/trust/bundles" 0 $?
  "$@" verify "$art/prod-signed.txt" --no-pin-updates > "$WORK/mg-$side-prod.txt" 2>&1
  check "$side verifies through the managed bundle with nothing in the user's home" 0 $?
  "$@" trust list > "$WORK/mg-$side-list.txt" 2>&1
  "$@" trust add acme "$TR/bundles/acme-v1/trust-bundle.json" --signer "$TR_SIGNER" --yes >/dev/null 2>&1
  check "$side refuses a user bundle that takes a managed name" 1 $?

  printf '{%s,"default":"off","rules":[]}\n' "$POLICY_V1" > "$home/policy.json"
  printf '{%s,"default":"enforce","rules":[]}\n' "$POLICY_V1" > "$m/managed-policy.json"
  mkdir -p "$proj/.promptsign"
  printf '{%s,"default":"off","rules":[]}\n' "$POLICY_V1" > "$proj/.promptsign/policy.json"
  (cd "$proj" && "$@" verify CLAUDE.md --no-pin-updates) > "$WORK/mg-$side-unsigned.txt" 2>&1
  check "$side fails an unsigned file under a managed enforce, despite user and project off" 2 $?
  (cd "$proj" && "$@" policy show) > "$WORK/mg-$side-show.txt" 2>&1
  rm -r "$proj/.promptsign"

  printf '{%s,"default":"warn","rules":[]}\n' "$POLICY_V1" > "$m/managed-policy.json"
  printf '{%s,"default":"warn","rules":[{"pattern":"*","trust_root":"sigstore-public","action":"enforce"}]}\n' \
    "$POLICY_V1" > "$home/policy.json"
  "$@" verify "$art/prod-signed.txt" --no-pin-updates > "$WORK/mg-$side-tighten.txt" 2>&1
  check "$side lets the user's policy tighten the managed one" 2 $?
  grep -q 'user policy: trust root "acme/prod" not allowed' "$WORK/mg-$side-tighten.txt"
  check "$side prefixes the user layer's findings" 0 $?
  rm "$home/policy.json"

  "$@" trust rm acme --managed >/dev/null 2>&1
  check "$side removes the managed bundle" 0 $?
  "$@" trust add acme "$TR/bundles/acme-v1/trust-bundle.json" --signer "$TR_SIGNER" --yes >/dev/null 2>&1
  check "$side installs acme v1 for the user" 0 $?
  "$@" verify "$art/prod-signed.txt" --no-pin-updates >/dev/null 2>&1
  check "$side verifies through the user's bundle under a managed policy" 0 $?
  printf '{%s,"default":"warn","rules":[],"user_roots":false}\n' "$POLICY_V1" > "$m/managed-policy.json"
  "$@" verify "$art/prod-signed.txt" --no-pin-updates > "$WORK/mg-$side-user-roots.txt" 2>&1
  check "$side ignores the user's bundle under user_roots: false" 2 $?

  printf '{%s,"default":"warn","rules":[],"lock_env":true}\n' "$POLICY_V1" > "$m/managed-policy.json"
  HOME="$base/os-home" USERPROFILE="$base/os-home" \
    "$@" verify "$art/prod-signed.txt" --no-pin-updates >/dev/null 2>&1
  check "$side ignores PROMPTSIGN_HOME under lock_env" 2 $?
  unset PROMPTSIGN_MANAGED_DIR
}

if [ -e "$MANAGED_PLATFORM_DIR" ]; then
  skip "section 14 managed layer ($MANAGED_PLATFORM_DIR exists)"
else
  # $IMPL_A / $IMPL_B are intentionally unquoted: they may carry arguments.
  managed_layer A $IMPL_A
  if have_b; then
    managed_layer B $IMPL_B
    for f in prod list unsigned show tighten user-roots; do
      if diff -u <(sed "s|mg-A|mg-X|g" "$WORK/mg-A-$f.txt") \
                 <(sed "s|mg-B|mg-X|g" "$WORK/mg-B-$f.txt") > "$WORK/mg-diff.txt"; then
        PASS=$((PASS+1)); echo "ok   - managed-layer output byte-identical ($f)"
      else
        FAIL=$((FAIL+1)); echo "FAIL - managed-layer output differs ($f):"; cat "$WORK/mg-diff.txt"
      fi
    done
  else
    skip "section 14 on B and output parity (no IMPL_B)"
  fi
fi

echo
echo "conformance: $PASS passed, $FAIL failed, $SKIP skipped  (work dir: $WORK)"
[ "$FAIL" = 0 ]
