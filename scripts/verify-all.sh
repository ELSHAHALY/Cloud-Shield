#!/usr/bin/env bash
# =============================================================================
# CloudShield — verify-all (Phase F D1–D7)
#
# Runs every local gate in sequence and stops at the first failure:
#   preflight -> terraform -> soar -> docs-api -> spa -> checkov -> gitleaks
#   -> actionlint -> local-smoke
# Each domain mirrors its CI job in .github/workflows/ci.yml. NOT covered
# (CI is the authority): Semgrep, Trivy fs/image, ZAP.
#
# Usage:  scripts/verify-all.sh [domain ...]      (default: all, in order)
# Env:    VERIFY_ALLOW_SKIP=1   a missing tool skips its domain (RESULT: INCOMPLETE)
#         VERIFY_COMPOSE_NO_BUILD=1  local-smoke starts the stack from images
#                               already built (offline rehearsal) instead of
#                               `make local-up` (which builds)
#         NO_COLOR=1            plain output
#         PYTHON, TF_CLI_CONFIG_FILE, TF_PLUGIN_CACHE_DIR are honoured.
# Exit:   0 all selected domains passed (or skipped, under VERIFY_ALLOW_SKIP)
#         1 a check failed   2 a prerequisite is missing / bad usage
#         3 the working tree changed during the run (a bug in this script)
#
# The tree is never edited: terraform runs on a scratch copy, `fmt` only
# checks, zips go to the scratch dir. Logs stay in $TMPDIR/cloudshield-verify.*.
# =============================================================================
# Functions below are called indirectly (traps, "$fn", need/have checks).
# shellcheck disable=SC2329
set -Euo pipefail

ALL_DOMAINS="preflight terraform soar docs-api spa checkov gitleaks actionlint local-smoke"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-python3}"

# Pins this script compares against or runs (keep in step with ci.yml / Makefile).
PIN_TF="1.16.5"; PIN_GITLEAKS="8.30.1"; PIN_CHECKOV="3.3.26"; PIN_RUFF="0.17.0"
PIN_NODE_MAJOR="24"; PIN_PY="3.13"; PIN_MOTO="5.2.4"
MOTO_IMAGE="motoserver/moto:5.2.4@sha256:120b1589c6df7e35d2092935f6ff724486bb2c4189d0e36ce795baba1400ffd2"
HADOLINT_IMAGE="hadolint/hadolint:v2.14.0@sha256:27086352fd5e1907ea2b934eb1023f217c5ae087992eb59fde121dce9c9ff21e"
ACTIONLINT_IMAGE="rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667"
DOCKERFILES="app/docs-api/Dockerfile app/spa/Dockerfile app/local-dev/Dockerfile"
COMPOSE_FILE="docker-compose.local.yml"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
  C_OK=$'\033[32m'; C_BAD=$'\033[31m'; C_WARN=$'\033[33m'; C_DIM=$'\033[2m'; C_B=$'\033[1m'; C_0=$'\033[0m'
else
  C_OK=""; C_BAD=""; C_WARN=""; C_DIM=""; C_B=""; C_0=""
fi

usage() { sed -n '11,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

# --- selection ---------------------------------------------------------------
SELECTED=""
for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
    preflight) ;;                                   # always runs
    terraform|soar|docs-api|spa|checkov|gitleaks|actionlint|local-smoke) SELECTED="$SELECTED $arg" ;;
    *) echo "verify-all: unknown domain '$arg' (choose from: ${ALL_DOMAINS#preflight })" >&2; exit 2 ;;
  esac
done
[ -n "$SELECTED" ] || SELECTED=" ${ALL_DOMAINS#preflight }"
is_selected() { case " $SELECTED " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# --- state (bash 3.2 compatible: no associative arrays) ---------------------
key() { printf '%s' "$1" | tr '-' '_'; }
set_var() { printf -v "$1_$(key "$2")" '%s' "$3"; }
get_var() { local v; v="$1_$(key "$2")"; printf '%s' "${!v:-}"; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cloudshield-verify.XXXXXX")"
LOGDIR="$WORK/logs"; mkdir -p "$LOGDIR"
WARNINGS=""; SKIPS=0; FAILED_DOMAIN=""; CURRENT_DOMAIN="preflight"; FINAL_RC=0
MOTO_CONTAINER=""; STACK_UP=0; SUMMARY_DONE=0
START_ALL="$(date +%s)"

warn() { WARNINGS="${WARNINGS}  ! $1"$'\n'; }
note() { [ -n "$1" ] && printf '  %s%s%s\n' "$C_DIM" "$1" "$C_0"; return 0; }

hash_stdin() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi | cut -d' ' -f1; }
tree_state() {
  git -C "$REPO" status --porcelain=v1 --untracked-files=all
  printf 'worktree %s\n' "$(git -C "$REPO" diff --binary | hash_stdin)"
  printf 'index %s\n' "$(git -C "$REPO" diff --cached --binary | hash_stdin)"
}
TREE_BEFORE="$(tree_state)"

# run <domain> <description> <command...>: appends to the domain log
run() {
  local d="$1" desc="$2"; shift 2
  note "$desc"
  printf '\n$ %s\n' "$*" >>"$LOGDIR/$d.log"
  "$@" >>"$LOGDIR/$d.log" 2>&1
}
# run_in <domain> <dir> <description> <command...>
run_in() {
  local d="$1" dir="$2" desc="$3"; shift 3
  note "$desc"
  printf '\n$ (cd %s) %s\n' "$dir" "$*" >>"$LOGDIR/$d.log"
  (cd "$REPO/$dir" && "$@") >>"$LOGDIR/$d.log" 2>&1
}

have() { command -v "$1" >/dev/null 2>&1; }
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
docker_ok() { have docker && docker info >/dev/null 2>&1; }

# --- cleanup + summary (always) ---------------------------------------------
cleanup() {
  if [ -n "$MOTO_CONTAINER" ]; then docker rm -f "$MOTO_CONTAINER" >/dev/null 2>&1 || true; MOTO_CONTAINER=""; fi
  if [ "$STACK_UP" = 1 ]; then
    (cd "$REPO" && docker compose -f "$COMPOSE_FILE" down -v --remove-orphans) >>"$LOGDIR/local-smoke.log" 2>&1 || true
    STACK_UP=0
  fi
}

summary() {
  local d r dur facts colour sym total
  [ "$SUMMARY_DONE" = 1 ] && return; SUMMARY_DONE=1
  total=$(( $(date +%s) - START_ALL ))
  printf '\n%s== verify-all summary ==%s\n' "$C_B" "$C_0"
  printf '%-12s   %-12s %6s  %s\n' "domain" "result" "time" "facts"
  for d in $ALL_DOMAINS; do
    r="$(get_var RES "$d")"; dur="$(get_var DUR "$d")"; facts="$(get_var FACTS "$d")"
    if [ -z "$r" ]; then
      if [ "$d" = preflight ] || is_selected "$d"; then r="not run"; else r="not selected"; fi
    fi
    # The symbol is printed apart from the padded word: printf pads bytes, not glyphs.
    case "$r" in
      PASS) colour="$C_OK"; sym="✓" ;; FAIL) colour="$C_BAD"; sym="✗" ;;
      SKIP) colour="$C_WARN"; sym="-" ;; *) colour="$C_DIM"; sym=" " ;;
    esac
    printf '%s%-12s %s %-12s%s %6s  %s\n' "$colour" "$d" "$sym" "$r" "$C_0" "${dur:+${dur}s}" "$facts"
  done
  [ -n "$WARNINGS" ] && printf '\n%sWarnings%s\n%s' "$C_WARN" "$C_0" "$WARNINGS"
  printf '\nNot covered here (CI is the authority): semgrep, trivy fs, trivy image + SBOM, ZAP.\n'
  printf 'Logs: %s\n' "$LOGDIR"
  if [ "$FINAL_RC" = 3 ]; then
    printf '%sRESULT: FAIL (exit 3): the working tree changed during the run%s\n' "$C_BAD" "$C_0"
  elif [ "$FINAL_RC" = 2 ]; then
    printf '%sRESULT: FAIL (exit 2): a prerequisite is missing (see preflight)%s\n' "$C_BAD" "$C_0"
  elif [ "$FINAL_RC" = 130 ] || [ "$FINAL_RC" = 143 ]; then
    printf '%sRESULT: INTERRUPTED (exit %s) during %s after %ss%s\n' "$C_BAD" "$FINAL_RC" "$CURRENT_DOMAIN" "$total" "$C_0"
  elif [ "$FINAL_RC" != 0 ]; then
    printf '%sRESULT: FAIL (exit %s) in %s after %ss%s\n' "$C_BAD" "$FINAL_RC" "${FAILED_DOMAIN:-$CURRENT_DOMAIN}" "$total" "$C_0"
  elif [ "$SKIPS" -gt 0 ]; then
    printf '%sRESULT: INCOMPLETE (%s skipped) after %ss: not a full verification%s\n' "$C_WARN" "$SKIPS" "$total" "$C_0"
  else
    printf '%sRESULT: PASS after %ss%s\n' "$C_OK" "$total" "$C_0"
  fi
}

on_exit() {
  local rc=$?
  [ "$FINAL_RC" = 0 ] && FINAL_RC=$rc
  trap - EXIT INT TERM
  cleanup
  if [ "$(tree_state)" != "$TREE_BEFORE" ]; then
    FINAL_RC=3
    printf '\n%sThe working tree changed during the run:%s\n' "$C_BAD" "$C_0"
    diff <(printf '%s\n' "$TREE_BEFORE") <(tree_state) | sed 's/^/  /' || true
  fi
  summary
  exit "$FINAL_RC"
}
trap on_exit EXIT
trap 'FINAL_RC=130; exit 130' INT
trap 'FINAL_RC=143; exit 143' TERM

# --- preflight -----------------------------------------------------------------
PREFLIGHT_MISSING=""
need() {          # need <domain> <check-description> <hint> <command...>
  local d="$1" what="$2" hint="$3"; shift 3
  if "$@" >/dev/null 2>&1; then return 0; fi
  if [ "${VERIFY_ALLOW_SKIP:-}" = 1 ]; then
    if [ -z "$(get_var SKIPREASON "$d")" ]; then set_var SKIPREASON "$d" "$what"; fi
    printf '  %s- %s: missing → %s will be SKIPPED (hint: %s)%s\n' "$C_WARN" "$what" "$d" "$hint" "$C_0"
  else
    printf '  %s✗ %s%s\n      hint: %s\n' "$C_BAD" "$what" "$C_0" "$hint"
    PREFLIGHT_MISSING="${PREFLIGHT_MISSING} $d"
  fi
}
version_warn() { # version_warn <tool> <actual> <pin>
  case "$2" in "$3"*) ;; *) warn "$1 $2 differs from the CI pin $3" ;; esac
}
compose_ok() {
  local v; v="$(docker compose version --short 2>/dev/null)"; v="${v#v}"
  [ -n "$v" ] || return 1
  local major="${v%%.*}" rest="${v#*.}"; local minor="${rest%%.*}"
  [ "$major" -gt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -ge 20 ]; }
}
node_ok() { have node && [ "$(node -p 'process.versions.node.split(".")[0]')" = "$PIN_NODE_MAJOR" ]; }
py_ok() { have "$PY" && "$PY" -c 'import sys, pytest, pytest_cov, moto, boto3; sys.exit(0 if sys.version_info >= (3, 12) else 1)'; }
tf_providers_ok() {
  [ -n "${TF_CLI_CONFIG_FILE:-}" ] && [ -f "$TF_CLI_CONFIG_FILE" ] && return 0
  have curl && curl -sSf -m 8 -o /dev/null https://registry.terraform.io/.well-known/terraform.json
}
port_free() { ! port_busy "$1"; }
not_shallow() { [ "$(git -C "$REPO" rev-parse --is-shallow-repository)" = "false" ]; }
hadolint_ok() { have hadolint || docker_ok; }
actionlint_ok() { have actionlint || docker_ok; }

preflight() {
  run preflight "bash -n on this script" bash -n "${BASH_SOURCE[0]}" || return 1
  have git || { echo "git is required" >&2; return 2; }
  if is_selected terraform; then
    need terraform "terraform on PATH" "install Terraform $PIN_TF (releases.hashicorp.com)" have terraform
    need terraform "provider registry reachable or TF_CLI_CONFIG_FILE set" "set TF_CLI_CONFIG_FILE to a provider mirror config" tf_providers_ok
    have terraform && version_warn terraform "$(terraform version -json 2>/dev/null | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["terraform_version"])' 2>/dev/null || echo unknown)" "$PIN_TF"
  fi
  if is_selected soar; then
    need soar "$PY ≥ 3.12 with pytest, pytest-cov, moto, boto3" "pip install -r soar/requirements-dev.txt" py_ok
    need soar "ruff on PATH" "pip install -r soar/requirements-dev.txt" have ruff
    have ruff && version_warn ruff "$(ruff --version 2>/dev/null | awk '{print $2}')" "$PIN_RUFF"
    have "$PY" && version_warn python "$("$PY" -c 'import platform; print(platform.python_version())' 2>/dev/null)" "$PIN_PY"
    py_ok && version_warn moto "$("$PY" -c 'import moto; print(moto.__version__)' 2>/dev/null)" "$PIN_MOTO"
  fi
  local d
  for d in docs-api spa local-smoke; do
    is_selected "$d" && need "$d" "Node $PIN_NODE_MAJOR and npm on PATH" "use the version in app/.nvmrc (nvm use)" node_ok
  done
  for d in docs-api local-smoke; do
    is_selected "$d" && need "$d" "Docker daemon running" "start Docker (docker info must succeed)" docker_ok
    is_selected "$d" && need "$d" "host port 5000 free (moto)" "make local-down; docker stop cloudshield-moto" port_free 5000
  done
  if is_selected local-smoke; then
    need local-smoke "docker compose ≥ 2.20" "update Docker Desktop / the compose plugin" compose_ok
    need local-smoke "host port 3000 free (SPA)" "make local-down" port_free 3000
  fi
  if is_selected checkov; then
    need checkov "checkov on PATH" "pip install checkov==$PIN_CHECKOV" have checkov
    need checkov "hadolint on PATH or Docker running" "start Docker, or install hadolint v2.14.0" hadolint_ok
    have checkov && version_warn checkov "$(checkov --version 2>/dev/null)" "$PIN_CHECKOV"
  fi
  if is_selected gitleaks; then
    need gitleaks "gitleaks on PATH" "install gitleaks $PIN_GITLEAKS" have gitleaks
    need gitleaks "full clone (gitleaks scans all history)" "git fetch --unshallow" not_shallow
    have gitleaks && version_warn gitleaks "$(gitleaks version 2>/dev/null)" "$PIN_GITLEAKS"
  fi
  if is_selected actionlint; then
    need actionlint "actionlint on PATH or Docker running" "start Docker, or install actionlint" actionlint_ok
  fi
  [ -z "$PREFLIGHT_MISSING" ] || return 2
}

# --- domains -------------------------------------------------------------------
dom_terraform() {
  local tf="$WORK/tf" dir n=0 ok=0
  export TF_PLUGIN_CACHE_DIR="${TF_PLUGIN_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/cloudshield/tf-plugins}"
  export TF_IN_AUTOMATION=1
  mkdir -p "$tf" "$TF_PLUGIN_CACHE_DIR"
  # detection/ too: modules/detection catalogues ../../../../detection/athena-queries.
  note "copy infra/terraform + detection/ to a scratch dir (init writes .terraform/ and lock files there)"
  (cd "$REPO" && git ls-files -co --exclude-standard -z infra/terraform detection \
    | while IFS= read -r -d '' f; do [ -e "$f" ] && printf '%s\0' "$f"; done \
    | tar --null -T - -cf -) | tar -xf - -C "$tf" || return 1
  run terraform "terraform fmt -check -recursive" terraform -chdir="$tf" fmt -check -recursive -diff infra/terraform || return 1
  for dir in "$tf"/infra/terraform/bootstrap "$tf"/infra/terraform/environments/*/ "$tf"/infra/terraform/modules/*/; do
    dir="${dir%/}"; n=$((n+1))
    run terraform "validate ${dir#"$tf"/}" terraform -chdir="$dir" init -backend=false -input=false -no-color || return 1
    run terraform "" terraform -chdir="$dir" validate -no-color || return 1
    ok=$((ok+1))
  done
  set_var FACTS terraform "validate $ok/$n"
  for dir in "$tf"/infra/terraform/modules/*/; do
    [ -d "${dir}tests" ] || continue
    run terraform "test ${dir#"$tf"/}" terraform -chdir="${dir%/}" test -no-color || return 1
  done
}

dom_soar() {
  run_in soar soar "ruff check + format --check" ruff check . ../scripts/package_soar.py || return 1
  run_in soar soar "" ruff format --check . ../scripts/package_soar.py || return 1
  run_in soar soar "pytest --cov (gate: fail_under in soar/pyproject.toml)" "$PY" -m pytest --cov || return 1
  run_in soar soar "ATT&CK export in sync with docs-api" "$PY" -m tools.export_attack_table --check ../app/docs-api/src/soc/attack-table.generated.json || return 1
  run soar "deterministic package (built twice)" "$PY" "$REPO/scripts/package_soar.py" --out "$WORK/soar-a.zip" || return 1
  run soar "" "$PY" "$REPO/scripts/package_soar.py" --out "$WORK/soar-b.zip" || return 1
  local a b; a="$(hash_stdin <"$WORK/soar-a.zip")"; b="$(hash_stdin <"$WORK/soar-b.zip")"
  printf 'package sha256: %s %s\n' "$a" "$b" >>"$LOGDIR/soar.log"
  [ "$a" = "$b" ] || { echo "package is not deterministic" >>"$LOGDIR/soar.log"; return 1; }
}

start_moto() {
  MOTO_CONTAINER="cloudshield-verify-moto-$$"
  run "$1" "start moto ($PIN_MOTO) on 127.0.0.1:5000" docker run -d --rm --name "$MOTO_CONTAINER" -p 127.0.0.1:5000:5000 "$MOTO_IMAGE" || return 1
  local _
  for _ in $(seq 1 60); do
    if have curl; then curl -sf -o /dev/null http://127.0.0.1:5000/moto-api/ && return 0
    else port_busy 5000 && return 0; fi
    sleep 1
  done
  echo "moto did not become healthy in 60 s" >>"$LOGDIR/$1.log"; return 1
}
stop_moto() { docker rm -f "$MOTO_CONTAINER" >/dev/null 2>&1 || true; MOTO_CONTAINER=""; }

dom_docs_api() {
  local d=docs-api p=app/docs-api
  run_in "$d" "$p" "npm ci --ignore-scripts" npm ci --ignore-scripts --no-audit --no-fund || return 1
  run_in "$d" "$p" "lint (--max-warnings 0)" npm run lint -- --max-warnings 0 || return 1
  run_in "$d" "$p" "typecheck" npm run typecheck || return 1
  run_in "$d" "$p" "OpenAPI drift" npm run openapi:check || return 1
  start_moto "$d" || return 1
  run_in "$d" "$p" "jest --coverage --ci (moto)" env MOTO_ENDPOINT=http://127.0.0.1:5000 AWS_ACCESS_KEY_ID=local-only AWS_SECRET_ACCESS_KEY=local-only AWS_REGION=us-east-1 npx jest --coverage --ci
  local rc=$?
  stop_moto
  return "$rc"
}

dom_spa() {
  local d=spa p=app/spa
  run_in "$d" "$p" "npm ci --ignore-scripts" npm ci --ignore-scripts --no-audit --no-fund || return 1
  run_in "$d" "$p" "lint" npm run lint || return 1
  run_in "$d" "$p" "typecheck" npm run typecheck || return 1
  run_in "$d" "$p" "vitest run --coverage" npx vitest run --coverage || return 1
  run_in "$d" "$p" "production build (cognito) + bundle check" env VITE_AUTH_MODE=cognito VITE_COGNITO_USER_POOL_ID=us-east-1_Placeholder VITE_COGNITO_CLIENT_ID=placeholderclientid VITE_AWS_REGION=us-east-1 npm run build || return 1
  run_in "$d" "$p" "" node scripts/check-bundle.mjs dist || return 1
  note "no local-idp string in dist/"
  if grep -R "local-idp" "$REPO/$p/dist/" >>"$LOGDIR/$d.log" 2>&1; then echo "dist/ contains the local auth branch" >>"$LOGDIR/$d.log"; return 1; fi
}

dom_checkov() {
  local f
  run_in checkov . "checkov terraform" checkov -d infra/terraform --framework terraform --quiet --compact --download-external-modules false || return 1
  run_in checkov . "checkov dockerfile" checkov -d app --framework dockerfile --quiet --compact || return 1
  for f in $DOCKERFILES; do
    if have hadolint; then
      run_in checkov . "hadolint $f" hadolint --config .hadolint.yaml "$f" || return 1
    else
      run_in checkov . "hadolint $f (docker)" docker run --rm -i -v "$REPO:/w:ro" -w /w "$HADOLINT_IMAGE" hadolint --config /w/.hadolint.yaml "$f" || return 1
    fi
  done
}

dom_gitleaks() {
  run_in gitleaks . "gitleaks git (full history, redacted)" gitleaks git . --redact --verbose --exit-code 1
}

dom_actionlint() {
  if have actionlint; then
    run_in actionlint . "actionlint" actionlint .github/workflows/*.yml
  else
    run_in actionlint . "actionlint (docker, pinned)" docker run --rm -v "$REPO:/repo:ro" -w /repo "$ACTIONLINT_IMAGE" .github/workflows/*.yml
  fi
}

dom_local_smoke() {
  local d=local-smoke p=app/local-dev
  run_in "$d" . "docker compose config" docker compose -f "$COMPOSE_FILE" config -q || return 1
  run_in "$d" "$p" "local-dev: npm ci, lint, typecheck, jest" npm ci --ignore-scripts --no-audit --no-fund || return 1
  run_in "$d" "$p" "" npm run lint || return 1
  run_in "$d" "$p" "" npm run typecheck || return 1
  # seed.test.ts needs moto (the CI app job runs it next to its moto service).
  start_moto "$d" || return 1
  run_in "$d" "$p" "" env MOTO_ENDPOINT=http://127.0.0.1:5000 npx jest --ci || { stop_moto; return 1; }
  stop_moto                                       # frees 5000 for the compose moto
  STACK_UP=1
  if [ "${VERIFY_COMPOSE_NO_BUILD:-}" = 1 ]; then
    run_in "$d" . "compose up (pre-built images, VERIFY_COMPOSE_NO_BUILD=1)" docker compose -f "$COMPOSE_FILE" up -d --no-build --wait --wait-timeout 300 || return 1
  else
    run_in "$d" . "make local-up (build + start)" make local-up || return 1
  fi
  run_in "$d" . "make local-smoke" make local-smoke
  local rc=$?
  run_in "$d" . "make local-down" make local-down || true
  STACK_UP=0
  return "$rc"
}

# --- facts (best effort; never changes a result) ------------------------------
facts_for() {
  local d="$1" log="$LOGDIR/$1.log" f=""
  [ -f "$log" ] || return 0
  case "$d" in
    terraform)
      local passed; passed="$(grep -Eo 'Success! [0-9]+ passed' "$log" | awk '{s+=$2} END {if (NR) print s}')"
      f="$(get_var FACTS terraform)${passed:+, test $passed passed}" ;;
    soar)
      f="$(grep -Eo '[0-9]+ passed' "$log" | tail -1)"
      local cov; cov="$(grep -E '^TOTAL' "$log" | tail -1 | awk '{print $NF}')"
      f="${f:-—}${cov:+, coverage $cov}" ;;
    docs-api|spa)
      local t c
      if [ "$d" = docs-api ]; then t="$(grep -Eo 'Tests: +[0-9]+ passed' "$log" | tail -1 | grep -Eo '[0-9]+')"
      else t="$(grep -E 'Tests +[0-9]+ passed' "$log" | tail -1 | grep -Eo '[0-9]+ passed' | grep -Eo '[0-9]+')"; fi
      c="$(grep -E '^All files' "$log" | tail -1 | awk -F'|' '{gsub(/ /,""); printf "stmts %s%% br %s%% fn %s%% lines %s%%", $2, $3, $4, $5}')"
      f="${t:+$t tests}${c:+, $c}" ;;
    checkov)
      # Order of the CI commands: terraform first, then dockerfile.
      f="$(grep -Eo 'Passed checks: [0-9]+, Failed checks: [0-9]+' "$log" \
        | awk -F'[:,] *' '{printf "%s%s %s passed / %s failed", (NR>1?"; ":""), (NR==1?"terraform":"dockerfile"), $2, $4}')" ;;
    gitleaks)
      f="$(grep -Eo '[0-9]+ commits scanned' "$log" | tail -1)"
      grep -q 'no leaks found' "$log" && f="${f:+$f, }no leaks found" ;;
    actionlint) [ "$(get_var RES actionlint)" = PASS ] && f="no findings" ;;
    local-smoke)
      local n; n="$(grep -c '^PASS ' "$log" || true)"
      grep -q 'all checks passed' "$log" && f="$n checks, all passed" ;;
  esac
  set_var FACTS "$d" "${f:-—}"
}

# --- main ----------------------------------------------------------------------
printf '%sCloudShield verify-all%s  commit %s%s  %s  %s\n' "$C_B" "$C_0" \
  "$(git -C "$REPO" rev-parse --short HEAD)" \
  "$([ -n "$(git -C "$REPO" status --porcelain)" ] && echo ' (dirty)')" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(uname -sm)"

run_domain() {
  local d="$1" fn="$2" t0 rc reason
  CURRENT_DOMAIN="$d"
  printf '\n%s▶ %s%s\n' "$C_B" "$d" "$C_0"
  reason="$(get_var SKIPREASON "$d")"
  if [ -n "$reason" ]; then
    set_var RES "$d" SKIP; set_var FACTS "$d" "skipped (missing: $reason)"; SKIPS=$((SKIPS+1))
    printf '%s- %s SKIPPED (missing: %s)%s\n' "$C_WARN" "$d" "$reason" "$C_0"
    return 0
  fi
  t0="$(date +%s)"
  "$fn"; rc=$?
  set_var DUR "$d" "$(( $(date +%s) - t0 ))"
  if [ "$rc" -eq 0 ]; then
    set_var RES "$d" PASS; facts_for "$d"
    printf '%s✓ %s%s\n' "$C_OK" "$d" "$C_0"
  else
    set_var RES "$d" FAIL; FAILED_DOMAIN="$d"; facts_for "$d"
    printf '%s✗ %s failed (exit %s); last lines of %s:%s\n' "$C_BAD" "$d" "$rc" "$LOGDIR/$d.log" "$C_0"
    tail -n 25 "$LOGDIR/$d.log" 2>/dev/null | sed 's/^/    /'
  fi
  return "$rc"
}

printf '\n%s▶ preflight%s\n' "$C_B" "$C_0"
T0="$(date +%s)"
preflight; rc=$?
set_var DUR preflight "$(( $(date +%s) - T0 ))"
if [ "$rc" -ne 0 ]; then
  set_var RES preflight FAIL; set_var FACTS preflight "missing:${PREFLIGHT_MISSING:- see log}"
  FINAL_RC=2; [ "$rc" -eq 1 ] && FINAL_RC=1
  exit "$FINAL_RC"
fi
set_var RES preflight PASS; set_var FACTS preflight "${SELECTED# }"

for d in ${ALL_DOMAINS#preflight }; do
  is_selected "$d" || continue
  fn="dom_$(key "$d")"
  run_domain "$d" "$fn" || { FINAL_RC=1; exit 1; }
done
exit 0
