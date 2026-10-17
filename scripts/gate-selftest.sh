#!/usr/bin/env bash
# =============================================================================
# CloudShield — security-gate self-test (Acceptance criterion D8)
#
# Proves each CI gate actually FAILS on a known-bad input, using the same
# tools and flags as .github/workflows/ci.yml. Seeds are generated in a temp
# dir at runtime and deleted afterwards; nothing bad is ever committed (a
# committed seed secret would live in git history forever and trip gitleaks
# on every future full-history scan).
#
# Usage:  scripts/gate-selftest.sh [secrets|sast|sca|iac|dockerfile|image|dast|all]
# Needs:  gitleaks, semgrep, trivy, checkov (and docker for dast; hadolint or
#         docker for dockerfile) on PATH.
# Exit:   0 = every selected gate tripped as expected; 1 = a gate let a seed
#         through OR exited non-zero WITHOUT reporting the seeded finding
#         (tool crash, DB download failure, unknown subcommand…) — a bare
#         non-zero exit is not proof the gate works.
# =============================================================================
set -uo pipefail

SEL="${1:-all}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0; SKIP=0

expect_trip() {               # expect_trip <gate> <signature-regex> <command...>
  local gate="$1" sig="$2"; shift 2
  if "$@" >"$WORK/$gate.log" 2>&1; then
    echo "✗ $gate: seed was NOT caught (gate would let it through)"; FAIL=$((FAIL+1))
  else
    local rc=$?
    if [ "$rc" -eq 127 ]; then
      echo "- $gate: SKIPPED (tool not installed)"; SKIP=$((SKIP+1))
    elif grep -qiE "$sig" "$WORK/$gate.log"; then
      echo "✓ $gate: tripped on the seeded finding (exit $rc, matched /$sig/)"; PASS=$((PASS+1))
    else
      echo "✗ $gate: exit $rc but the seeded finding /$sig/ is absent — tool error, not a real trip:"
      tail -n 5 "$WORK/$gate.log" | sed 's/^/    /'
      FAIL=$((FAIL+1))
    fi
  fi
}

want() { [ "$SEL" = all ] || [ "$SEL" = "$1" ]; }

# --- Gate 1: secrets — a syntactically valid but fake GitHub PAT, built at
# runtime so this script itself contains no secret pattern. (AWS's documented
# example key AKIAIOSFODNN7EXAMPLE is allow-listed by gitleaks and would NOT trip.)
if want secrets; then
  mkdir -p "$WORK/secrets"
  tok="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 36)"
  printf 'const token = "%s%s";\n' "ghp" "_$tok" >"$WORK/secrets/config.js"
  expect_trip secrets 'github-pat' gitleaks dir "$WORK/secrets" --exit-code 1 --no-banner --verbose
fi

# --- Gate 2: SAST — Express route building SQL from user input (OWASP A03).
if want sast; then
  mkdir -p "$WORK/sast"
  cat >"$WORK/sast/app.js" <<'JS'
const express = require("express");
const mysql = require("mysql");
const app = express();
const db = mysql.createConnection({});
app.get("/docs", (req, res) => {
  db.query("SELECT * FROM docs WHERE id = " + req.query.id, (err, rows) => res.json(rows));
});
app.listen(3000);
JS
  expect_trip sast 'sql|CWE-89' semgrep scan --config p/owasp-top-ten --config p/nodejs \
    --severity ERROR --error --metrics off "$WORK/sast"
fi

# --- Gate 3: SCA — lodash 4.17.4 (CVE-2019-10744, CRITICAL, fixed in 4.17.12).
if want sca; then
  mkdir -p "$WORK/sca"
  cat >"$WORK/sca/package-lock.json" <<'JSON'
{
  "name": "seed", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
  "packages": {
    "": { "name": "seed", "version": "1.0.0", "dependencies": { "lodash": "4.17.4" } },
    "node_modules/lodash": { "version": "4.17.4", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.4.tgz" }
  }
}
JSON
  expect_trip sca 'CVE-2019-10744' trivy fs --scanners vuln --severity CRITICAL --ignore-unfixed --exit-code 1 "$WORK/sca"
fi

# --- Gate 4: IaC — SSH open to the world (CKV_AWS_24).
if want iac; then
  mkdir -p "$WORK/iac"
  cat >"$WORK/iac/main.tf" <<'HCL'
resource "aws_security_group" "bad" {
  name        = "seed-open-ssh"
  description = "seed"
  vpc_id      = "vpc-00000000"
  ingress {
    description = "seed"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
HCL
  expect_trip iac 'CKV_AWS_24' checkov -d "$WORK/iac" --framework terraform --quiet --compact --check CKV_AWS_24
fi

# --- Gate 4b: Dockerfiles (Phase E) — a floating tag and a root user:
# hadolint DL3007 (app job) and Checkov CKV_DOCKER_7 / CKV_DOCKER_8 (iac job).
if want dockerfile; then
  mkdir -p "$WORK/dockerfile"
  printf 'FROM node:latest\nUSER root\nCMD ["node"]\n' >"$WORK/dockerfile/Dockerfile"
  if command -v hadolint >/dev/null; then
    expect_trip dockerfile-hadolint 'DL3007' hadolint --failure-threshold warning "$WORK/dockerfile/Dockerfile"
  else
    expect_trip dockerfile-hadolint 'DL3007' docker run --rm -i -v "$WORK/dockerfile:/w:ro" \
      "${HADOLINT_IMAGE:-hadolint/hadolint:v2.14.0}" hadolint --failure-threshold warning /w/Dockerfile
  fi
  expect_trip dockerfile-checkov 'CKV_DOCKER_7|CKV_DOCKER_8' checkov -d "$WORK/dockerfile" --framework dockerfile \
    --quiet --compact --check CKV_DOCKER_7,CKV_DOCKER_8
fi

# --- Gate 5: image — end-of-life base image with fixable CRITICAL/HIGH CVEs.
if want image; then
  expect_trip image 'CRITICAL|HIGH' trivy image --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 node:14
fi

# --- Gate 6: DAST — local server that sends none of the FAIL-listed headers.
if want dast; then
  if command -v docker >/dev/null && command -v python3 >/dev/null; then
    mkdir -p "$WORK/dast/www" && echo '<html><body>seed</body></html>' >"$WORK/dast/www/index.html"
    python3 -m http.server 18080 --bind 127.0.0.1 --directory "$WORK/dast/www" >/dev/null 2>&1 &
    srv=$!; sleep 1
    cp "$(dirname "$0")/../.zap/rules.tsv" "$WORK/dast/rules.tsv" && chmod -R 777 "$WORK/dast"
    # HSTS (10035) never fires over plain HTTP; 10020/10021/10038 do.
    expect_trip dast 'FAIL-NEW: [1-9]' docker run --rm --network host -v "$WORK/dast:/zap/wrk:rw" \
      ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://127.0.0.1:18080 -c rules.tsv -I
    kill "$srv" 2>/dev/null
  else
    echo "- dast: SKIPPED (needs docker + python3)"; SKIP=$((SKIP+1))
  fi
fi

echo "---- tripped: $PASS   NOT caught: $FAIL   skipped: $SKIP"
[ "$FAIL" -eq 0 ]
