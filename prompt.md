# WAF Evasion Research Lab

## 1. MISSION

Build a fully reproducible, single-command research lab that replicates and extends the study described in the paper **"Evasion of Web Application Firewalls Through Payload Obfuscation: A Black-Box Study"** by Jamila Yusifova.

The lab must let a researcher, with **one `docker compose up` command**, spin up:

1. **Four open-source WAFs** in front of vulnerable applications
2. **Three vulnerable target apps** behind those WAFs
3. **A Python mutation + testing engine** that generates obfuscated payloads and records results
4. **A TypeScript web dashboard** that shows results in real time
5. **An automated analysis pipeline** that produces paper-ready tables, figures, CSV/JSON exports, and a Markdown/LaTeX report

The ultimate deliverable: a researcher should be able to run `make run` (or `docker compose up`) and come back to a finished report that mirrors Table 1 of the paper, with charts, raw data, and a live dashboard.

---

## 2. PROJECT NAME & STRUCTURE

**Name:** `waf-evasion-lab`

**Required directory layout:**

```
waf-evasion-lab/
├── docker-compose.yml              # The ONE command entrypoint
├── Makefile                        # Convenience wrappers (make run, make test, make report, make clean)
├── README.md                       # Quickstart + architecture diagram + citation to original paper
├── .env.example
│
├── wafs/                           # Each WAF in its own subfolder, each with its own Dockerfile
│   ├── modsecurity/                # ModSecurity v3 + OWASP CRS v4 (nginx or apache)
│   ├── coraza/                     # Coraza (Go) + CRS
│   ├── shadowdaemon/               # Shadow Daemon
│   └── openappsec/                 # open-appsec (ML-based, Check Point)
│
├── targets/                        # Vulnerable apps
│   ├── dvwa/
│   ├── webgoat/
│   └── juiceshop/
│
├── routing/                        # Reverse proxy mapping (WAF × target) pairs — see §4
│   └── traefik.yml                 # OR nginx.conf — agent picks the cleaner option
│
├── engine/                         # Python mutation + testing engine
│   ├── pyproject.toml
│   ├── src/
│   │   ├── payloads/               # Baseline payload corpus (100+ across vuln classes)
│   │   │   ├── sqli.yaml
│   │   │   ├── xss.yaml
│   │   │   ├── cmdi.yaml
│   │   │   ├── lfi.yaml
│   │   │   ├── ssti.yaml
│   │   │   └── xxe.yaml
│   │   ├── mutators/               # PLUGGABLE — one file per obfuscation category
│   │   │   ├── base.py             # Abstract Mutator class + registry decorator
│   │   │   ├── lexical.py
│   │   │   ├── encoding.py
│   │   │   ├── structural.py
│   │   │   ├── context_displacement.py
│   │   │   └── multi_request.py
│   │   ├── runner/                 # Sends payloads, records verdicts
│   │   ├── analyzer/               # Computes bypass rates, generates charts
│   │   ├── reporter/               # Emits Markdown + LaTeX report
│   │   └── api/                    # FastAPI — exposes results to dashboard
│   └── tests/                      # Unit tests for every mutator
│
├── dashboard/                      # TypeScript + React web UI
│   ├── package.json
│   ├── src/
│   └── Dockerfile
│
├── results/                        # Bind-mounted output directory
│   ├── raw/                        # Per-request JSON logs
│   ├── processed/                  # CSV aggregates
│   ├── figures/                    # PNG/SVG charts
│   └── reports/                    # Markdown + LaTeX
│
└── docs/
    ├── ARCHITECTURE.md
    ├── DEV.md                      # How to work on development of this project (For AI agents. Descriptive!)
    ├── ADDING_MUTATORS.md          # How to plug in a 6th obfuscation category
    └── ADDING_PAYLOADS.md
```

---

## 3. WAFs TO DEPLOY

All four MUST be running simultaneously, each as a separate service in `docker-compose.yml`:

| Service | Image / Base | Notes |
|---|---|---|
| `modsecurity` | `owasp/modsecurity-crs:nginx` (or apache variant) | ModSecurity v3 + OWASP CRS v4. Expose paranoia-level tuning via env var. |
| `coraza` | Build from `corazawaf/coraza` — Go-based | Must load the same CRS v4 rules for fair comparison. |
| `shadowdaemon` | `zecure/shadowd` + `zecure/shadowd-connectors` | Requires its own MySQL/PostgreSQL sidecar; include it. |
| `openappsec` | `checkpoint/infinity-next-agent` or official open-appsec compose snippets | ML-based. Must run in "learning + prevent" mode after a short warm-up. |

**All WAFs must start in their default configuration** for the first test run (matches paper's methodology). A second profile (`--profile paranoia-high`) must raise ModSecurity's paranoia level for the secondary experiment the paper describes.

---

## 4. ROUTING ARCHITECTURE

Each WAF must sit in front of each vulnerable target, so the engine can test **every (WAF × target) pair**. Use a reverse proxy (Traefik preferred, nginx acceptable) with hostname-based routing:

```
modsec-dvwa.local      → modsecurity → dvwa
modsec-webgoat.local   → modsecurity → webgoat
modsec-juiceshop.local → modsecurity → juiceshop
coraza-dvwa.local      → coraza      → dvwa
... (12 combinations total: 4 WAFs × 3 targets)
```

A `baseline-<target>.local` route (no WAF) must also exist as a control, so the engine can confirm a mutated payload actually works on the vulnerable app before claiming "bypass."

---

## 5. VULNERABLE TARGETS

All three, each as its own service:

- **DVWA** — `vulnerables/web-dvwa` — auto-set security level to "low" via entrypoint script
- **WebGoat** — `webgoat/webgoat` — bind to a fixed port
- **OWASP Juice Shop** — `bkimminich/juice-shop`

A healthcheck must confirm each is reachable before the engine starts.

---

## 6. PAYLOAD CORPUS

At least **100 baseline payloads** in YAML under `engine/src/payloads/`, broken out by class:

- **SQLi** — 25+ (union-based, boolean, time-based, stacked, second-order)
- **XSS** — 25+ (reflected, stored, DOM, polyglot, SVG, event-handler)
- **Command Injection** — 15+
- **LFI / Path Traversal** — 15+
- **SSTI** — 10+ (Jinja2, Twig, Freemarker)
- **XXE** — 10+

Each payload entry must include: `id`, `class`, `payload`, `expected_trigger` (how to confirm it worked on baseline), `cwe`, `notes`. Pull from SecLists, PayloadsAllTheThings, and OWASP test vectors. Cite sources in comments.

---

## 7. MUTATION ENGINE (THE HEART OF THE SYSTEM)

### Pluggable architecture

`engine/src/mutators/base.py` defines:

```python
class Mutator(ABC):
    category: str                  # e.g. "lexical"
    complexity_rank: int           # 1-5, for ordering in the results table
    
    @abstractmethod
    def mutate(self, payload: Payload) -> list[MutatedPayload]:
        """Return 1..N mutated variants of the input payload."""

REGISTRY: dict[str, type[Mutator]] = {}

def register(cls): REGISTRY[cls.category] = cls; return cls
```

Adding a 6th category = drop a new file in `mutators/`, decorate with `@register`. Document this in `docs/ADDING_MUTATORS.md`.

### The five required mutators (exact match to paper §Methodology)

1. **`lexical.py`** — case permutation (`SeLeCt`), whitespace injection, clause reordering, inline comments (`/**/`).
2. **`encoding.py`** — URL %-encoding (single + double), Unicode escapes, HTML entities, base64 where applicable, stacked layers.
3. **`structural.py`** — string concatenation (`CONCAT('SEL','ECT')`), `eval()` reconstruction, char-code assembly (`String.fromCharCode`).
4. **`context_displacement.py`** — move payload from URL params into JSON body, XML attributes, custom HTTP headers, multipart fields.
5. **`multi_request.py`** — split exploit across N sequential requests with shared session/cookie state. This mutator returns a list of request *sequences*, not single requests, so the runner must support session replay.

Each mutator must produce **at least 5 variants per input payload** (matching paper). Unit tests verify variants still parse/execute on the baseline target.

---

## 8. TEST RUNNER

`engine/src/runner/`:

- Async HTTP client (`httpx` or `aiohttp`) for throughput.
- For each `(payload, mutation_variant, waf, target)` tuple:
  1. Send to `baseline-<target>` — confirm payload still triggers vuln.
  2. Send to `<waf>-<target>` — record verdict: `blocked` (4xx/5xx from WAF), `allowed` (2xx + trigger confirmed), or `flagged` (allowed but WAF logged alert).
  3. Log raw request/response + metadata to `results/raw/<run_id>/<waf>/<target>/<payload_id>_<variant>.json`.
- Parallelism configurable via `MAX_CONCURRENCY` env var. Default 10.
- Rate-limit per WAF to avoid skewed results.
- Resume support: if interrupted, `make run` should continue from where it stopped.

---

## 9. ANALYZER

`engine/src/analyzer/`:

Computes, per run:

- **Bypass rate** = `allowed / (allowed + blocked)` for each `(category, waf)` cell.
- Confidence intervals (Wilson score, 95%).
- Per-vuln-class breakdown (SQLi vs XSS etc.) in addition to the paper's aggregate table.
- Exports: `results/processed/bypass_rates.csv`, `results/processed/per_payload.csv`.
- Charts (matplotlib + seaborn, save as both PNG 300dpi and SVG):
  - Heatmap: categories × WAFs, color = bypass rate.
  - Grouped bar chart matching Table 1 of the paper.
  - Line chart: bypass rate vs complexity_rank, one line per WAF.
  - Per-vuln-class small-multiples.

---

## 10. REPORTER

`engine/src/reporter/` generates `results/reports/report.md` and `report.tex` containing:

- Title, timestamp, git SHA of the lab, versions of each WAF
- Reproduced Table 1 (exact format of the paper) using live data
- All figures from the analyzer
- Auto-filled Recommendations section templated on paper §Recommendations, with deltas ("our run vs paper: +X% on context displacement")
- Bibliography including the 6 references from the paper
- LaTeX version uses the IEEE conference class; compiles with pdflatex in a sidecar container

---

## 11. DASHBOARD (TypeScript + React)

`dashboard/`:

- Vite + React + TypeScript + Tailwind
- Reads from FastAPI in `engine/src/api/`
- Tabs:
  - **Live Run** — progress bars per WAF/target, tail of recent verdicts
  - **Results** — interactive table + heatmap (recharts), filter by category/WAF/vuln-class
  - **Payload Explorer** — click a mutated payload, see raw request, response, diff vs baseline
  - **Compare Runs** — pick two run IDs, diff their tables
- Served on `http://localhost:3000`
- Read-only; no auth needed (local lab).

---

## 12. SINGLE-COMMAND UX

Primary command:
```bash
docker compose up --build
```

Must bring up: all 4 WAFs, 3 targets, routing proxy, engine, dashboard. When healthchecks pass, the engine auto-runs the full test suite, the dashboard becomes available at `localhost:3000`, and the report materializes in `results/reports/`.

Makefile conveniences:
```
make up             # docker compose up --build -d
make run            # trigger a new test run against running stack
make report         # regenerate report from latest run
make clean          # nuke results + containers
make reset-wafs     # restart WAFs with fresh rules (clears ML state)
make shell-engine   # drop into the engine container
```

---

## 13. SAFETY, LEGALITY, ETHICS

- **Bind all services to 127.0.0.1 by default.** The `.env.example` must explicitly warn against exposing these containers — they include intentionally vulnerable apps.
- README must include a clear "Authorized use only — do not point the engine at third-party systems" notice.
- The multi-request mutator must not include any destructive payloads (no `DROP TABLE`, no `rm -rf`); use read-only equivalents.

---

## 14. DELIVERY PROTOCOL — HOW I WANT THE AGENT TO WORK

**Before writing any code, the agent MUST:**

1. **Restate understanding** — one short paragraph confirming it grasps the mission.
2. **Propose a phased build plan** with checkpoints, e.g.:
   - Phase 1: skeleton + docker compose with WAFs only
   - Phase 2: targets + routing
   - Phase 3: engine core + one mutator end-to-end
   - Phase 4: remaining mutators + full corpus
   - Phase 5: analyzer + reporter
   - Phase 6: dashboard
   - Phase 7: polish, docs, tests
3. **Flag unknowns** — list any config details it's unsure about (e.g. exact open-appsec compose snippet) and how it'll resolve them (doc lookup, fallback, ask me).
4. **Wait for my go-ahead** before Phase 1.

**During build:**
- After each phase, stop and show: what's done, what works end-to-end, what's next. Let me test before moving on.
- Every file > 50 lines gets a comment header explaining its purpose.
- Every mutator and analyzer function has a docstring citing the paper section it implements.
- Run `docker compose config` to validate the compose file after every change to it.
- Write tests alongside code, not after.

**Quality bar:**
- The lab must produce a report that a reviewer can compare line-by-line against Table 1 of the paper.
- The mutation engine must be obviously extensible — a new contributor should be able to add a 6th category in under 30 minutes using only `docs/ADDING_MUTATORS.md`.
- All obvious footguns (exposed ports, destructive payloads, unpinned image tags) are caught.

---

## 15. REFERENCE: THE ORIGINAL PAPER

The paper this lab replicates is a black-box study testing 4 open-source WAFs (ModSecurity+CRS, Coraza, Shadow Daemon, open-appsec) against 40 baseline payloads (20 SQLi + 20 XSS) mutated across 5 obfuscation categories. Its key finding: bypass rates rise monotonically with obfuscation complexity — ~12% lexical, ~27% encoding, ~46% structural, ~62% context displacement, ~80% multi-request sequencing — and stateless per-request inspection has a hard architectural ceiling that rules alone can't overcome.

This lab must reproduce those numbers (within reasonable variance from mutation randomness) and extend the methodology to Juice Shop + four additional vuln classes.

---

## 16. FIRST RESPONSE EXPECTED FROM THE AGENT

Respond with:
1. Understanding restatement
2. Phased plan
3. Unknowns + resolution strategy
4. Estimated total LOC and time per phase
5. The single question you most need answered before starting

**Do not write code yet.** Wait for my reply.
