#!/usr/bin/env bash
# ==============================================================================
# Phase 4 acceptance tests — 5 mutators + full 100-payload corpus end-to-end.
#
# Exit criteria (from the Phase 4 charter):
#   1. engine pytest suite green, including all four new mutators + models
#   2. corpus meets prompt.md §6 minima (sqli≥25, xss≥25, cmdi≥15, lfi≥15,
#      ssti≥10, xxe≥10 — total ≥100)
#   3. every mutator from §7 registered: lexical, encoding, structural,
#      context_displacement, multi_request
#   4. compose config valid under --profile engine
#   5. engine image builds + the core stack is healthy
#   6. `make run` with all 5 mutators × all 6 classes against DVWA + Juice Shop
#      produces ≥1 JSON per (waf × target × mutator × class) cell that has an
#      endpoint; manifest totals match the filesystem
#   7. ModSec blocks at least one variant per non-trivial mutator category
#      (sanity: every mutator actually hits the WAF)
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
. "$(dirname "$0")/_lib.sh"
waflab_nix_reexec "$0" "$@"

pass()  { printf '  \e[32m✓\e[0m %s\n' "$*"; }
fail()  { printf '  \e[31m✗\e[0m %s\n' "$*"; exit 1; }
step()  { printf '\n\e[1;34m[phase4]\e[0m %s\n' "$*"; }

PY=engine/.venv/bin/python

step "1/7  Engine venv + unit tests green"
if [[ ! -x "$PY" ]]; then
  python3 -m venv engine/.venv
  engine/.venv/bin/pip install -q --disable-pip-version-check -e 'engine/[dev]'
fi
"$PY" -m pytest engine/tests -q || fail "pytest"
pass "pytest green"

step "2/7  Corpus meets charter minima (≥100 payloads across 6 classes)"
"$PY" - <<'PY_EOF'
from wafeval.payloads.loader import load_corpus
from wafeval.models import VulnClass
minima = {"sqli":25,"xss":25,"cmdi":15,"lfi":15,"ssti":10,"xxe":10}
all_ok = True
for cls, n in minima.items():
    got = len(load_corpus(classes=[VulnClass(cls)]))
    ok = got >= n
    all_ok = all_ok and ok
    mark = "OK" if ok else "FAIL"
    print(f"  {cls:6s} {got:3d} (need ≥{n}) {mark}")
tot = len(load_corpus())
print(f"  total: {tot} (need ≥100)")
if not all_ok or tot < 100:
    raise SystemExit(1)
PY_EOF
pass "corpus OK"

step "3/7  All 5 mutators from prompt.md §7 registered"
"$PY" - <<'PY_EOF'
from wafeval.mutators import REGISTRY
need = {"lexical","encoding","structural","context_displacement","multi_request"}
missing = need - set(REGISTRY)
if missing:
    raise SystemExit(f"missing: {missing}")
print("  registered:", sorted(REGISTRY.keys()))
PY_EOF
pass "mutator registry complete"

step "4/7  Compose config valid under --profile engine"
docker compose --profile engine config --quiet || fail "compose (engine) invalid"
pass "compose --profile engine OK"

step "5/7  Build engine image + bring stack up healthy"
docker compose --profile engine build engine >/dev/null || fail "engine build"
docker compose up -d --wait --wait-timeout 600 --remove-orphans >/dev/null \
  || fail "compose up --wait"
pass "stack healthy + image built"

step "6/7  Run all 5 mutators × all 6 classes × DVWA+Juice Shop"
RUN_ID="phase4-$(date -u +%Y%m%dT%H%M%SZ)"
docker compose --profile engine run --rm \
  --name waflab-engine-phase4 \
  engine run \
  --classes sqli,xss,cmdi,lfi,ssti,xxe \
  --mutators lexical,encoding,structural,context_displacement,multi_request \
  --targets dvwa,juiceshop \
  --run-id "$RUN_ID" >/tmp/engine-phase4.log 2>&1 \
  || { tail -30 /tmp/engine-phase4.log; fail "engine run"; }
pass "engine run completed ($RUN_ID)"

OUT="results/raw/$RUN_ID"
[[ -f "$OUT/manifest.json" ]] || fail "manifest.json missing"

# Every (waf × target × mutator) cell has at least one JSON — i.e. the engine
# didn't silently skip any combo with a defined endpoint.
for waf in baseline modsec coraza shadowd; do
  for target in dvwa juiceshop; do
    for mut in lexical encoding structural context_displacement multi_request; do
      n=$("$PY" - <<PY_EOF
import json, pathlib
n = sum(
    1 for p in pathlib.Path("$OUT/$waf/$target").glob("*.json")
    if json.loads(p.read_text()).get("mutator") == "$mut"
)
print(n)
PY_EOF
)
      [[ "$n" -gt 0 ]] || fail "no records for $waf × $target × $mut"
    done
  done
  pass "$waf × {dvwa,juiceshop} × 5 mutators covered"
done

manifest_total=$("$PY" -c "import json; print(json.load(open('$OUT/manifest.json'))['totals']['datapoints'])")
fs_total=$(find "$OUT" -name '*.json' ! -name 'manifest.json' | wc -l)
[[ "$manifest_total" == "$fs_total" ]] \
  || fail "manifest totals=$manifest_total vs filesystem=$fs_total"
pass "manifest ↔ filesystem in sync ($fs_total datapoints)"

step "7/7  ModSec blocks at least one variant per mutator"
"$PY" - <<PY_EOF
import json, pathlib, collections
root = pathlib.Path("$OUT/modsec")
c = collections.Counter()
for p in root.rglob("*.json"):
    d = json.loads(p.read_text())
    if d["verdict"] == "blocked":
        c[d["mutator"]] += 1
need = {"lexical","encoding","structural","context_displacement","multi_request"}
missing = need - set(c)
for m in sorted(need):
    print(f"  modsec blocked — {m:24s} {c.get(m,0)}")
if missing:
    raise SystemExit(f"no modsec block recorded for {missing}")
PY_EOF
pass "modsec engaged against every mutator"

printf '\n\e[1;32mPhase 4 PASSED\e[0m — 5 mutators × 100-payload corpus × 6 vuln classes end-to-end\n'
