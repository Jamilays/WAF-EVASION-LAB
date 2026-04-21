# WAF Evasion Research Lab

Reproducible single-command lab that replicates and extends Jamila Yusifova's black-box study **"Evasion of Web Application Firewalls Through Payload Obfuscation"** — four open-source WAFs in front of vulnerable apps, a pluggable mutation engine, and a live dashboard.

> ⚠ **Authorized use only.** This lab contains intentionally vulnerable apps and an offensive payload engine. Do not point it at systems you do not own or have explicit written authorization to test. All services are bound to `127.0.0.1`.

> 🤖 **This README doubles as memory for future Claude sessions.** Read the "State of the World" section below before making changes — it records the current invariants, gotchas, and decisions that aren't derivable from the code alone.

---

## Status

**Phase 7 in progress.** All four WAFs legitimately enforcing, 201-payload corpus across 12 vuln classes, engine + analyzer + reporter + dashboard all green, paranoia-high comparison data captured, open-appsec ML agent wired in for real.

| Phase | Scope | Status |
|---|---|---|
| 1 | Skeleton, compose, 3 WAFs healthy, ML stub, paranoia-high profile | ✅ |
| 2 | DVWA / WebGoat / Juice Shop + Traefik hostname routing (9 WAF×target + 3 baselines) | ✅ |
| 3 | Engine core + 1 mutator end-to-end + payload corpus start | ✅ |
| 4 | 5 mutators + 100+ payload corpus | ✅ |
| 5 | Analyzer + Markdown/LaTeX reporter | ✅ |
| 6 | FastAPI (`--profile dashboard`) + Vite/React/TS/Tailwind dashboard | ✅ |
| **7** | Real shadowd + open-appsec, expanded corpus (201 payloads, 12 classes), PL1↔PL4 compare, Hall of Fame | ⏳ *in progress* |

Parked items live in [TODO.md](TODO.md).

---

## State of the World (for future-Claude memory)

### WAFs — all 4 legitimately enforcing

| WAF | How it blocks | Gotchas |
|---|---|---|
| **ModSecurity v3 + CRS 4.25** (`owasp/modsecurity-crs:4.25.0-nginx-alpine-202604040104`) | Libinjection + ~1000 CRS rules. `PARANOIA` env var tunes the PL. | `PARANOIA=4` in compose env for `modsec-ph-*` services **doesn't activate the JSON-SQL plugin rules** (942550 family) — those ship separately. So modsec-ph shows the SAME bypass rate as modsec on JSON-SQL payloads. |
| **Coraza** (`waflab/coraza:phase1`, built from `corazawaf/coraza/v3`) | Same CRS 4.25 rule set loaded via `coreruleset.FS`. | **CRITICAL:** `@coraza.conf-recommended` defaults to `SecRuleEngine DetectionOnly` — blocks nothing. We force `SecRuleEngine On` via `CORAZA_BLOCKING_MODE=on` (default). PL4 directive in compose (`SecAction ... tx.blocking_paranoia_level=4`) **does** activate JSON-SQL rules (unlike modsec-ph). |
| **Shadow Daemon** (`zecure/shadowd:2.2.0`) | TCP :9115 analyser + 120 blacklist filters; verdict over HMAC-signed wire protocol. | Requires DB profile bootstrap. `MODE_ACTIVE=1`, `MODE_PASSIVE=2`, `MODE_LEARNING=3` — **lower number = stricter** (counterintuitive). `server_ip` column stored as `*` which `prepare_wildcard()` converts to SQL `%`; storing literal `%` gets escaped to `\%` and matches nothing. The proxy (`waflab/shadowd-proxy`) speaks the real wire protocol `profile_id\n hmac\n json\n`. 120-filter library is weaker than CRS — expected higher bypass rate. `SHADOWD_FALLBACK_BLOCK=false` by default (was a regex safety net before the daemon was properly wired). |
| **open-appsec** (`ghcr.io/openappsec/agent-unified:latest`) | NGINX + ML attachment in one container, multiplexing all 3 `openappsec-*.local` Host headers via server blocks. | Standalone profile requires 4 sidecars: `openappsec-smartsync`, `openappsec-shared-storage`, `openappsec-tuning`, `openappsec-db` (Postgres **16**, not 18 — 18 moved the data dir). `local_policy.yaml` in `wafs/openappsec/localconfig/` sets `prevent-learn` + `minimum-confidence: critical`. Healthcheck probes `/healthz` which the nginx default_server handles *before* the agent attachment (agent takes 30-45 s to load policy). |

### Targets

| Target | Auth flow | Sink notes |
|---|---|---|
| **DVWA** (`vulnerables/web-dvwa:latest`) | Login via `POST /login.php` with scraped `user_token` (see `runner/session.py`). The `security` cookie is set **directly by the engine** (not via `/security.php?security=low` GET which relies on 302 redirect that `follow_redirects=False` misses). | `/vulnerabilities/exec/` runs `ping -c 4 <ip>` → ~4 s per baseline request → saturates PHP-FPM pool. **Use `MAX_CONCURRENCY=4` for cmdi workloads** (see note below). |
| **Juice Shop** (`bkimminich/juice-shop:v19.2.1`) | Unauthenticated. | `/rest/products/search?q=` is the canonical SQLi sink (SQLite → `SQLITE_ERROR` page leaks details on malformed queries). Does NOT reflect `q` in JSON, so XSS there is `baseline_fail` and intentionally has no endpoint in targets.yaml. |
| **WebGoat** (`webgoat/webgoat:v2025.3`) | Unauthenticated for login endpoint; lesson API requires Spring session. | **No endpoints in targets.yaml** — the previous `/WebGoat/login?q=` routing never triggered anything. Restoring WebGoat is in [TODO.md](TODO.md) item #1. Matrix is **4 WAFs × 2 targets** right now, not 4 × 3. |

### Engine (Python, `engine/src/wafeval/`)

- **Per-route `httpx.AsyncClient`** — one client per (waf, target) route to avoid cookie jar leaks between routes. The old shared jar made DVWA session appear to work on WAF routes when actually only baseline authenticated.
- **Verdict classifier** (`runner/verdict.py`): baseline-first. If baseline didn't trigger, return `BASELINE_FAIL` regardless of what the WAF did — so denominators are comparable across WAFs. 2xx response with no exploit marker → `BLOCKED` (silent-sanitise case). 5xx with exploit marker → `ALLOWED` (Juice Shop SQLITE_ERROR is a successful SQLi).
- **Trigger model** — supports `contains`, `regex`, `reflected`, `status`, `any_of`. `any_of` lets one payload match against DVWA's "First name" *or* Juice Shop's SQLITE_ERROR so the corpus stays DRY.
- **Context-displacement + multi_request mutators** — relocate payloads into HTTP headers. The `_header_safe()` helper percent-encodes control chars + non-ASCII so h11's field-value validation doesn't reject (SQLi `\n` payloads, Unicode-quote SQLi, etc.).
- **Request timeout** — default 30s (was 15s). DVWA cmdi's 4s ping × PHP-FPM worker queue was timing out at 15s under MAX_CONCURRENCY=10; 30s + concurrency=4 fixes it cleanly.
- **YAML package-data** — `pyproject.toml` has `[tool.hatch.build.targets.wheel.force-include]` for every `payloads/*.yaml` and `targets.yaml`. Without this, wheel-installed package loses the corpus.
- **⚠ Rebuild the engine image after editing `targets.yaml` or any payload YAML** — `docker compose --profile engine run --rm engine ...` uses the built image, so stale image = stale routes. Confirmed bug: the first Phase-7 run used the old image because `docker compose build engine` was kicked off concurrently with the run.

### Analyzer / Reporter (`engine/src/wafeval/{analyzer,reporter}/`)

- Two lenses: `true_bypass` (paper methodology, DVWA anchor, baseline-confirmed only) and `waf_view` (baseline-agnostic, used for Juice Shop where triggers vary per payload).
- `waf_view` denominator excludes `baseline_fail + error` (it's "requests that actually tested the WAF", not "everything on disk").
- Reporter renders `—` for cells where `n < 5` (Wilson CI > ±0.4 at that size is misleading).
- Hall of Fame section (`reporter/hall_of_fame.py`) lists top-N variants by how many (waf × target) cells they bypass.

### API / Dashboard (`--profile dashboard`)

- FastAPI on 127.0.0.1:8001, read-only.
- Endpoints: `/health`, `/runs`, `/runs/latest`, `/runs/{id}/{manifest|live|bypass-rates|per-payload|per-variant|records/.../...|figures/...|hall-of-fame|report}`, `/runs/compare`.
- Dashboard on 127.0.0.1:3000 (nginx-served Vite bundle + `/api/*` proxy). Tabs: Live Run, Results (heatmap + table + baseline_fail column), **Hall of Fame**, Payload Explorer (12-class dropdown), Compare Runs.

### Runtime knobs

| Env / CLI flag | Default | Purpose |
|---|---|---|
| `MAX_CONCURRENCY` | 10 in compose, **4** for cmdi-heavy runs | Parallel requests cap — honour DVWA PHP-FPM pool limit. |
| `REQUEST_TIMEOUT_S` | 30 | Per-request httpx timeout. |
| `RESPONSE_SNIPPET_BYTES` | 65536 | Bytes of response body saved in each `*.json` record. |
| `SHADOWD_ENFORCE` | `true` | Translate shadowd verdicts into 403s. |
| `SHADOWD_FALLBACK_BLOCK` | `false` | Regex safety net in shadowd-proxy; leave off now that real daemon works. |
| `CORAZA_BLOCKING_MODE` | `on` | Force `SecRuleEngine On` — CRITICAL, default-off means zero blocks. |
| `OPENAPPSEC_DB_*` | `openappsec` / `openappsec_dev_only` | Postgres creds for tuning service. |

### Host-OS gotchas (NixOS)

- `make` is not in PATH. Use `nix-shell -p make --run "make <target>"` or call the underlying commands directly.
- Python's numpy/pandas needs `libstdc++` + `zlib` via `nix-shell -p stdenv.cc.cc.lib zlib` with `LD_LIBRARY_PATH` set. The `tests/phase*.sh` scripts auto-reexec under nix-shell via `tests/_lib.sh`.

### Compose profiles gotcha

`docker compose down` only stops services in the **default** profile — anything started under `--profile ml` / `--profile paranoia-high` / `--profile dashboard` keeps running. Use `make down-all` (or `docker compose --profile paranoia-high --profile ml --profile dashboard --profile engine --profile report down`) to tear the whole lab down.

---

## Quickstart

Requirements: Docker 25+, Docker Compose v2, ~6 GB free RAM on first boot (WebGoat is heavy). On NixOS, install with `nix-shell -p docker docker-compose`.

```bash
cp .env.example .env          # optional; override ports / paranoia / enforce flags

# Validate compose under every profile
docker compose config --quiet
docker compose --profile paranoia-high --profile ml --profile dashboard config --quiet

# Bring up the core matrix (3 targets + 9 WAF×target + baselines)
docker compose up -d --build --wait --wait-timeout 600

# Acceptance suite
bash tests/phase2.sh
```

After `docker compose up`, the entire WAF × target matrix is reachable through a single Traefik front door at **http://127.0.0.1:8000**. Traefik routes by `Host` header — no `/etc/hosts` edits required:

```bash
# baseline (direct to target, no WAF)
curl -H 'Host: baseline-dvwa.local'      http://127.0.0.1:8000/login.php
curl -H 'Host: baseline-juiceshop.local' http://127.0.0.1:8000/

# through a WAF (SQLi attack — 403 = blocked, 200 benign = passed)
curl -H 'Host: modsec-juiceshop.local'        "http://127.0.0.1:8000/rest/products/search?q=1'+UNION+SELECT+NULL--"
curl -H 'Host: coraza-juiceshop.local'        "http://127.0.0.1:8000/rest/products/search?q=1'+UNION+SELECT+NULL--"
curl -H 'Host: shadowd-juiceshop.local'       "http://127.0.0.1:8000/rest/products/search?q=1'+UNION+SELECT+NULL--"
curl -H 'Host: openappsec-juiceshop.local'    "http://127.0.0.1:8000/rest/products/search?q=1'+UNION+SELECT+NULL--"   # needs --profile ml
```

Traefik dashboard (read-only, loopback): http://127.0.0.1:8088/dashboard/

### Optional profiles

```bash
docker compose --profile paranoia-high up -d --wait   # + modsec-ph-* + coraza-ph-* (6 services)
docker compose --profile ml up -d --wait              # + real open-appsec ML agent + 4 standalone sidecars
docker compose --profile dashboard up -d --build --wait  # + api (FastAPI) + dashboard (React)
```

With `--profile dashboard`:

- **Dashboard** — http://127.0.0.1:3000 — tabs: Live Run, Results, Hall of Fame, Payload Explorer, Compare Runs.
- **API** — http://127.0.0.1:8001 — `/docs` for live OpenAPI.

Both mount `results/` read-only. Trigger a run with `make run` and watch the Live Run tab poll it.

---

## The matrix

**Default profile** (12 routes):

| WAF | dvwa | webgoat | juiceshop |
|---|---|---|---|
| baseline (no WAF) | `baseline-dvwa.local` | `baseline-webgoat.local` | `baseline-juiceshop.local` |
| ModSecurity | `modsec-dvwa.local` | `modsec-webgoat.local` | `modsec-juiceshop.local` |
| Coraza | `coraza-dvwa.local` | `coraza-webgoat.local` | `coraza-juiceshop.local` |
| Shadow Daemon | `shadowd-dvwa.local` | `shadowd-webgoat.local` | `shadowd-juiceshop.local` |

**With `--profile paranoia-high`** (+6): `modsec-ph-*`, `coraza-ph-*`.

**With `--profile ml`** (+3): `openappsec-*` — all routed to the single `openappsec` container which splits by Host-header internally.

**Note:** WebGoat has routes but **no engine endpoints** (see targets.yaml). The engine skips WebGoat automatically. Restoring it is [TODO.md](TODO.md) item #1.

---

## Running experiments

```bash
# Full 201-payload corpus × 5 mutators × 2 targets × 4 WAFs (PL1) — ~20 min at MAX_CONCURRENCY=4
docker compose --profile engine run --rm -e MAX_CONCURRENCY=4 --name waflab-engine \
  engine run \
  --classes sqli,xss,cmdi,lfi,ssti,xxe,nosql,ldap,ssrf,jndi,graphql,crlf \
  --mutators lexical,encoding,structural,context_displacement,multi_request \
  --run-id "research-$(date -u +%Y%m%dT%H%M%SZ)"

# Paranoia-high comparison
docker compose --profile engine run --rm -e MAX_CONCURRENCY=4 \
  engine run --wafs baseline,modsec-ph,coraza-ph \
  --classes sqli,xss,cmdi,lfi,ssti,xxe,nosql,ldap,ssrf,jndi,graphql,crlf \
  --mutators lexical,encoding,structural,context_displacement,multi_request \
  --run-id "paranoia-high-$(date -u +%Y%m%dT%H%M%SZ)"

# open-appsec only (needs --profile ml)
docker compose --profile engine --profile ml run --rm -e MAX_CONCURRENCY=4 \
  engine run --wafs baseline,openappsec \
  --classes sqli,xss,cmdi,lfi,ssti,xxe,nosql,ldap,ssrf,jndi,graphql,crlf \
  --mutators lexical,encoding,structural,context_displacement,multi_request \
  --run-id "openappsec-$(date -u +%Y%m%dT%H%M%SZ)"

# Generate reports + Hall of Fame for any run
nix-shell -p stdenv.cc.cc.lib zlib --run "LD_LIBRARY_PATH=\$(nix-build --no-out-link '<nixpkgs>' -A stdenv.cc.cc.lib)/lib:\$(nix-build --no-out-link '<nixpkgs>' -A zlib)/lib:\$LD_LIBRARY_PATH engine/.venv/bin/python -m wafeval report --run-id <RUN_ID>"
```

Results under `results/{raw,processed,figures,reports}/<run_id>/`. Each run produces 3 CSVs, 8 figures (PNG+SVG), `report.md` + `report.tex`.

---

## Testing

`tests/phase<N>.sh` is the canonical acceptance suite. On NixOS each script self-reexecs under `nix-shell` for libstdc++/zlib.

```bash
bash tests/phase1.sh   # WAF liveness
bash tests/phase2.sh   # routing matrix (9 WAF×target, WAF engagement)
bash tests/phase3.sh   # engine core + lexical mutator end-to-end
bash tests/phase4.sh   # 5 mutators × corpus minima
bash tests/phase5.sh   # analyzer + reporter
bash tests/phase6.sh   # FastAPI + dashboard
```

Engine unit tests (85 passing as of Phase-7 work):

```bash
nix-shell -p stdenv.cc.cc.lib zlib --run "LD_LIBRARY_PATH=\$(nix-build --no-out-link '<nixpkgs>' -A stdenv.cc.cc.lib)/lib:\$(nix-build --no-out-link '<nixpkgs>' -A zlib)/lib:\$LD_LIBRARY_PATH engine/.venv/bin/python -m pytest engine/tests -q"
```

---

## Corpus

**12 vuln classes, 201 payloads** (`engine/src/wafeval/payloads/*.yaml`):

| Class | # | Notes |
|---|---:|---|
| sqli | 42 | Classical + JSON-SQL (Team82) + Unicode + ODBC + scientific notation + hex/CHAR |
| xss | 35 | Script tag + handlers + Unicode + entity-split + mXSS + SVG animate + data-URI |
| cmdi | 15 | Pipe, semicolon, backtick, $(), $IFS, brace expansion (DVWA anchor) |
| lfi | 15 | Path traversal + PHP wrappers + null byte + encoded |
| ssti | 10 | Jinja2, Twig, Freemarker — **no DVWA sink**, WAF-view only |
| xxe | 10 | External entities + parameter entities — **no DVWA sink**, WAF-view only |
| **nosql** | **15** | MongoDB `$ne`/`$regex`/`$where` + form-encoded operators |
| **ldap** | **12** | Wildcard + OR/AND injection + AD-specific (sAMAccountName) |
| **ssrf** | **15** | AWS/GCP/Azure metadata + decimal/hex IP + file://, gopher://, dict:// |
| **jndi** | **12** | Log4Shell base + lower/upper/env/date lookups + dotless-i bypass |
| **graphql** | **10** | Introspection + batch + alias + fragment cycle |
| **crlf** | **10** | Response splitting + Set-Cookie smuggle + LF-only |

Triggers default to `any_of` so one entry fires on DVWA ("First name") or Juice Shop ("SQLITE_ERROR"). WAF-view-only classes use `TriggerStatus: 200` — the endpoint always 200s, so the WAF's decision drives the verdict.

---

## Research findings so far

**PL1 baseline** (run `research-20260421T141410Z`, 33,545 datapoints):

- **Only `encoding` leaks** against CRS v4 on DVWA (~5% bypass for ModSec + Coraza). Paper reported ~27% but that's CRS 3.x; v4's libinjection closed the gap.
- **Shadow Daemon is meaningfully weaker** on Juice Shop — up to 97% bypass on `encoding`. Its 120-filter library doesn't include JNDI, CRLF, or modern SQLi dialects. This is the *cleanest WAF architecture comparison* in the dataset.
- **CRLF payloads bypass universally** (72-91% across all 3 WAFs on Juice Shop) — the payload lands in a URL-query value, not a header sink, so WAFs don't cross-check for embedded control chars.
- **JNDI / LDAP / NoSQL / SSRF** pass DVWA route (CRS's XSS rules catch them incidentally) but slip Juice Shop's route (CRS JSON-body rules don't fire on URL query).

**PL1 vs PL4** (run `paranoia-high-20260421T151636Z`):

- **Coraza PL4 closes the encoding gap entirely** (5.7% → 0% on DVWA, 55% → 0% on Juice Shop).
- **ModSec PL4 *does not*** — its PARANOIA env var doesn't unlock the JSON-SQL plugin rules. Real-world deployment gotcha worth flagging.

**open-appsec** — corpus run `openappsec-*` (scheduled; results will land in `results/raw/openappsec-<stamp>/`). Expected to show a fundamentally different bypass profile than rule-based WAFs because it's ML-based. Minimum-confidence ladder (critical/high/medium/low) is the natural ablation dimension.

---

## Architecture

```
             127.0.0.1:8000
                  │
      ┌───────────▼───────────┐        routes by Host: header
      │        traefik        │────────────────────────────────────┐
      └───────────────────────┘                                    │
                  │                                                │
   ┌──────────────┼──────────────┬───────────────┐                 │
   ▼              ▼              ▼               ▼                 ▼
modsec-*      coraza-*      shadowd-*       openappsec-*       baseline-*
                                          (--profile ml,
                                          single container)
   │              │              │               │                 │
   │  BACKEND     │  BACKEND     │  BACKEND      │  BACKEND        │
   └──────────────┼──────────────┴───────────────┴─────────────────┘
                  ▼
         ┌────────┴────────┐
         │        │        │
        dvwa   webgoat  juiceshop
       + dvwa-db
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full detail. Developer onboarding in [docs/DEV.md](docs/DEV.md).

---

## Safety & legality

- All host ports bound to `127.0.0.1` — never `0.0.0.0`.
- DVWA / WebGoat / Juice Shop are intentionally vulnerable. Never expose them to the LAN.
- DB passwords default to `*_dev_only`; rotate via `.env` if your disk leaves your machine.
- The payload loader rejects destructive patterns (`DROP TABLE`, `rm -rf`, fork bombs, `/etc/shadow`). The multi_request mutator re-audits every generated step.
- All image tags are pinned (no `latest` except DVWA, which has no versioned tags upstream, and the open-appsec images which track `latest` on ghcr.io).

---

## Citation

Replicates the methodology of:

> Yusifova, J. *Evasion of Web Application Firewalls Through Payload Obfuscation: A Black-Box Study.* (See [paper.md](paper.md) for the extracted text.)

Phase-7 research extensions draw on:
- [PayloadsAllTheThings — WAF Bypass collection](https://github.com/kh4sh3i/WAF-Bypass)
- [Claroty Team82 — JS-ON: Security-OFF](https://claroty.com/team82/research/js-on-security-off-abusing-json-based-sql-to-bypass-waf)
- [OWASP CRS — A new rule to prevent SQL in JSON](https://coreruleset.org/20230222/a-new-rule-to-prevent-sql-in-json/)
- [zecure/shadowd_python connector — wire protocol reference](https://github.com/zecure/shadowd_python/blob/master/shadowd/connector.py)
- [open-appsec docker-compose deployment guide](https://docs.openappsec.io/getting-started/start-with-docker/deploy-with-docker-compose)
