# WAF Evasion Research Lab

Reproducible single-command lab that replicates and extends Jamila Yusifova's black-box study **"Evasion of Web Application Firewalls Through Payload Obfuscation"** — four open-source WAFs in front of vulnerable apps, a pluggable mutation engine, and a live dashboard.

> ⚠ **Authorized use only.** This lab contains intentionally vulnerable apps and an offensive payload engine. Do not point it at systems you do not own or have explicit written authorization to test. All services are bound to `127.0.0.1`.

---

## Status

**Phase 2 complete.** Full 3 × 3 WAF × target routing matrix live behind a single Traefik front door, plus three no-WAF baseline routes. DVWA auto-seeded; open-appsec still stubbed.

| Phase | Scope | Status |
|---|---|---|
| 1 | Skeleton, compose, 3 WAFs healthy, ML stub, paranoia-high profile | ✅ |
| **2** | DVWA / WebGoat / Juice Shop + Traefik hostname routing (9 WAF×target + 3 baselines) | ✅ |
| 3 | Engine core + 1 mutator end-to-end + payload corpus start | ⏳ |
| 4 | Remaining 4 mutators + 100+ payload corpus | ⏳ |
| 5 | Analyzer + Markdown/LaTeX reporter | ⏳ |
| 6 | FastAPI + React dashboard | ⏳ |
| 7 | Tests, docs, safety audit, polish | ⏳ |

---

## Quickstart

Requirements: Docker 25+, Docker Compose v2, ~6 GB free RAM on first boot (WebGoat is heavy).

```bash
cp .env.example .env          # optional; override ports / paranoia
docker compose config --quiet # or: nix-shell -p make --run "make config"
docker compose up -d --build --wait --wait-timeout 600
bash tests/phase2.sh          # acceptance test
```

After `docker compose up`, the entire WAF × target matrix is reachable through a single Traefik front door at **http://127.0.0.1:8000**. Traefik routes by `Host` header — no `/etc/hosts` edits required:

```bash
# baseline (direct to target, no WAF)
curl -H 'Host: baseline-dvwa.local'      http://127.0.0.1:8000/login.php
curl -H 'Host: baseline-webgoat.local'   http://127.0.0.1:8000/WebGoat/login
curl -H 'Host: baseline-juiceshop.local' http://127.0.0.1:8000/

# through a WAF
curl -H 'Host: modsec-dvwa.local'        http://127.0.0.1:8000/
curl -H 'Host: coraza-juiceshop.local'   http://127.0.0.1:8000/
curl -H 'Host: shadowd-webgoat.local'    http://127.0.0.1:8000/WebGoat/login
```

Probe every route in one shot:

```bash
for waf in baseline modsec coraza shadowd; do
  for t in dvwa webgoat juiceshop; do
    echo -n "$waf-$t.local → "
    curl -so /dev/null -w '%{http_code}\n' -H "Host: $waf-$t.local" http://127.0.0.1:8000/
  done
done
```

Traefik dashboard (read-only, loopback): http://127.0.0.1:8088/dashboard/

### Optional profiles

```bash
docker compose --profile paranoia-high up -d --wait   # + modsec-ph-* + coraza-ph-* (6 services)
docker compose --profile ml up -d --wait              # + openappsec-* stubs (3 services)
```

---

## The matrix (12 default routes)

| WAF / route      | dvwa                         | webgoat                         | juiceshop                         |
|------------------|------------------------------|---------------------------------|-----------------------------------|
| baseline (no WAF)| `baseline-dvwa.local`        | `baseline-webgoat.local`        | `baseline-juiceshop.local`        |
| ModSecurity      | `modsec-dvwa.local`          | `modsec-webgoat.local`          | `modsec-juiceshop.local`          |
| Coraza           | `coraza-dvwa.local`          | `coraza-webgoat.local`          | `coraza-juiceshop.local`          |
| Shadow Daemon    | `shadowd-dvwa.local`         | `shadowd-webgoat.local`         | `shadowd-juiceshop.local`         |

Under `--profile paranoia-high`, add another 6: `modsec-ph-*`, `coraza-ph-*`. Under `--profile ml`, add 3 more: `openappsec-*` (currently stubbed).

---

## Architecture

```
        127.0.0.1:8000
             │
     ┌───────▼────────┐      routes by Host: header
     │    traefik     │──────────────────────────────────┐
     └────────────────┘                                  │
              │                                          │
  ┌───────────┼───────────┬──────────────┐               │
  ▼           ▼           ▼              ▼               ▼
modsec-*   coraza-*   shadowd-*      (paranoia-*      baseline-*
                                      ml-* profiles)
  │           │           │              (optional)       │
  │ BACKEND   │ BACKEND   │ BACKEND                        │
  └───────────┼───────────┴────────────────────────────────┘
              ▼
       ┌──────┴──────┐
       │             │             │
      dvwa         webgoat       juiceshop
     + dvwa-db
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detail. Developer onboarding in [docs/DEV.md](docs/DEV.md).

---

## Safety & legality

- All host ports bound to `127.0.0.1` — never `0.0.0.0`.
- DVWA / WebGoat / Juice Shop are intentionally vulnerable. Never expose them to the LAN.
- DB passwords default to `*_dev_only`; rotate via `.env` if your disk leaves your machine.
- All image tags are pinned (no `latest` except DVWA, which has no versioned tags upstream).

---

## Citation

Replicates the methodology of:

> Yusifova, J. *Evasion of Web Application Firewalls Through Payload Obfuscation: A Black-Box Study.* (See `paper.md` in the repo for the extracted text.)
