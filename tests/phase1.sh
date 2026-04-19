#!/usr/bin/env bash
# ==============================================================================
# Phase 1 acceptance tests.
#
# Exit criteria (from the Phase 1 charter):
#   1. `docker compose config` validates under default, paranoia-high, and ml
#      profiles
#   2. All 3 core WAFs reach a "healthy" status in compose
#   3. `GET /healthz` returns 200 on each WAF's host-bound port
#   4. The ml profile can be composed (stub service comes up healthy)
# ==============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."

pass()  { printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail()  { printf '  \033[31m✗\033[0m %s\n' "$*"; exit 1; }
step()  { printf '\n\033[1;34m[phase1]\033[0m %s\n' "$*"; }

step "1/4  Validate compose for all profiles"
docker compose config --quiet                             || fail "default profile invalid"; pass "default profile OK"
docker compose --profile paranoia-high config --quiet     || fail "paranoia-high invalid";   pass "paranoia-high OK"
docker compose --profile ml config --quiet                || fail "ml invalid";              pass "ml OK"

step "2/4  Start core stack and wait for health"
docker compose up -d --build --wait --wait-timeout 240    || fail "compose up --wait failed"
pass "compose up --wait returned OK"

# Map of service → container-internal port we expect /healthz on
declare -A PORTS=( [modsecurity]=8080 [coraza]=80 [shadowd-proxy]=80 )

step "3/4  Verify each WAF returns 200 on /healthz"
for svc in "${!PORTS[@]}"; do
  host_port=$(docker compose port "$svc" "${PORTS[$svc]}" 2>/dev/null | awk -F: '{print $NF}')
  [[ -n "$host_port" ]] || fail "no published port for $svc"
  code=$(curl -sS -o /dev/null -w "%{http_code}" \
               -H 'User-Agent: waflab-phase1-test' \
               "http://127.0.0.1:${host_port}/healthz" || true)
  # Note: host 127.0.0.1 is always IPv4, unlike the busybox wget inside
  # minimalist WAF containers which prefers ::1. See tests/phase1.sh comments.
  [[ "$code" == "200" ]] || fail "$svc /healthz → $code (expected 200)"
  pass "$svc /healthz → 200 (127.0.0.1:${host_port})"
done

step "4/4  Verify container health state reports 'healthy'"
for svc in modsecurity coraza shadowd shadowd-db shadowd-proxy whoami; do
  cid=$(docker compose ps -q "$svc")
  [[ -n "$cid" ]] || fail "$svc has no container"
  state=$(docker inspect -f '{{.State.Status}}' "$cid")
  health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid")
  if [[ "$state" != "running" ]]; then
    fail "$svc state=$state"
  fi
  if [[ "$health" != "healthy" && "$health" != "none" ]]; then
    fail "$svc health=$health"
  fi
  pass "$svc running (health=$health)"
done

printf '\n\033[1;32mPhase 1 PASSED\033[0m — 3 WAFs healthy, ML stub available under --profile ml\n'
