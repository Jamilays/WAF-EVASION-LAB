# Developer onboarding (and future-AI-agent onboarding)

This file is the single stop for "how do I work on this repo?" — keep it current.

## Prerequisites

- Docker 25+ and Docker Compose v2
- GNU Make
- (For Coraza hacking) Go 1.23+
- (For Shadow Daemon proxy hacking) Python 3.12+
- ~4 GB free RAM, ~3 GB free disk for images

## Day-one flow

```bash
cp .env.example .env
make config          # validate compose across all 5 profiles
make up              # builds Coraza + shadowd-proxy, pulls the rest
make test-phase1     # runs the Phase 1 acceptance test suite
make test-phase6     # runs the full stack + FastAPI + dashboard acceptance
make up-dashboard    # bring up api + dashboard — http://127.0.0.1:3000
make api-host        # or run uvicorn from the host venv for rapid edit/reload
make logs SVC=modsecurity   # tail any service
make down            # stop everything (keeps volumes)
make clean           # nuke containers, volumes, and results/
```

### Frontend dev loop

```bash
cd dashboard
npm install
npm run dev          # Vite dev server on http://127.0.0.1:3000 (HMR)
# in another shell
make api-host        # uvicorn on 127.0.0.1:8001; Vite proxies /api/* to it
```

## Where things live

```
docker-compose.yml                 single source of truth for topology
Makefile                           UX wrapper around compose
.env.example                       ports + tunables
wafs/<waf>/                        each WAF owns its build context + README
  coraza/                          Go reverse proxy (main.go + Dockerfile)
  shadowdaemon/proxy/              Python async proxy (proxy.py + Dockerfile)
  modsecurity/                     config notes only (uses upstream image)
  openappsec/                      stub + real-enablement notes
targets/                           [Phase 2] vulnerable apps
routing/                           [Phase 2] Traefik / reverse-proxy config
engine/                            mutation + testing engine (Phases 3–5)
  src/wafeval/api/                 FastAPI read-only backend (Phase 6)
dashboard/                         Vite + React + TS + Tailwind UI (Phase 6)
results/                           bind-mounted output tree (raw/processed/figures/reports)
docs/                              architecture, dev, extension guides
tests/phase<N>.sh                  acceptance test per phase (phase1.sh … phase6.sh)
```

## Conventions

- **Ports**: all host bindings start `127.0.0.1:` — never `0.0.0.0`. If you add a new service, match this.
- **Image tags**: always pin to a specific tag including date/digest where the upstream supports it. `latest` is a bug.
- **Healthchecks**: every user-facing service has a healthcheck. `/healthz` is the standard path. Place it *before* the WAF if the WAF would otherwise block the UA (see `shadowd-proxy/proxy.py`'s dedicated route).
- **Compose profiles**: used for optional services (paranoia-high variants, ml agent). Never use profiles to smuggle prod/dev splits — that's what overrides are for.
- **Documentation**: if it changes the developer's mental model, update a doc. Prompts like "where does X live?" being ungoogleable in this repo is a fail.

## Adding a new WAF

1. Create `wafs/<name>/` with a `Dockerfile` (or use an upstream image directly) and a README that documents env vars + pinned tag.
2. Add a service block to `docker-compose.yml` following the `coraza` block as a template (healthcheck, depends_on: whoami, `ports: 127.0.0.1:${XYZ_PORT}:…`).
3. Add the port to `.env.example`.
4. Add `<waf>` to `tests/phase1.sh`'s `PORTS` map so the acceptance test covers it.
5. Document in `docs/ARCHITECTURE.md`.

## Testing philosophy

- Every phase ships a `tests/phase<N>.sh` that a CI or a human can run to verify acceptance.
- Unit tests for engine code land alongside code in `engine/tests/` (Phase 3+).
- The dashboard gets Playwright smoke tests (Phase 6+).

## Known gotchas

- The ModSecurity CRS image blocks `curl`'s default User-Agent at paranoia ≥ 2 via rule 913100. Healthchecks override the UA to `waflab-hc`.
- The Coraza runtime expects CRS to come from the embedded `coraza-coreruleset` FS, not a filesystem path — don't swap it for a tarball download.
- Shadow Daemon has no native Java/Node connectors; future DVWA integration uses its native PHP connector, but WebGoat and Juice Shop keep using `shadowd-proxy`.
