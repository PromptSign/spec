#!/usr/bin/env bash
# PromptSign conformance suite — wire-format agreement between two independent
# implementations of spec/01–04.
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
# spec/05 §1: a v1 verifier that only knows `ed25519` must reject `keyless`
# outright, never verify against the embedded key without checking the cert.
if have_b && b_signs; then
  mkdir -p "$WORK/skill-kl"
  cp -r "$WORK/skill-b/." "$WORK/skill-kl/"
  jsonrun '
import json, sys
p = sys.argv[1]
b = json.load(open(p))
b["signer"]["scheme"] = "keyless"
open(p, "w").write(json.dumps(b, indent=2) + "\n")
' '
const fs = require("fs"), p = process.argv[1];
const b = JSON.parse(fs.readFileSync(p, "utf8"));
b.signer.scheme = "keyless";
fs.writeFileSync(p, JSON.stringify(b, null, 2) + "\n");
' "$WORK/skill-kl/.promptsign/bundle.json"
  if [ $? = 127 ]; then
    skip "unknown-scheme fail-closed (needs python3 or node)"
  else
    export PROMPTSIGN_HOME="$WORK/home-consumer"
    $IMPL_A verify "$WORK/skill-kl" >/dev/null 2>&1
    check "A fails closed on an unknown signature scheme" 2 $?
    $IMPL_A verify "$WORK/skill-kl" 2>/dev/null | grep -q "unsupported signature scheme"
    check "A says why (not a silent pass)" 0 $?
    $IMPL_B verify "$WORK/skill-kl" >/dev/null 2>&1
    check "B rejects the same malformed bundle" 2 $?
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

echo
echo "conformance: $PASS passed, $FAIL failed, $SKIP skipped  (work dir: $WORK)"
[ "$FAIL" = 0 ]
