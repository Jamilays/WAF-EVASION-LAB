# Engine — Phases 3–7

Python mutation + testing engine, analyzer, reporter, and read-only FastAPI
dashboard backend. Architecture (prompt.md §7–§11):

```
engine/
├── pyproject.toml
├── Dockerfile                 # builds waflab/engine:phase3 (used by engine, reporter, api)
├── src/wafeval/
│   ├── models.py              # Payload, MutatedPayload, VerdictRecord, RouteResult (incl. waf_headers)
│   ├── config.py              # targets.yaml loader
│   ├── targets.yaml           # (target, vuln_class) → HTTP request template
│   ├── payloads/              # YAML corpora per vuln class + named single-file corpora + loader
│   ├── mutators/              # base.py + 7 concrete mutators
│   │   ├── base.py            # ABC + @register decorator + REGISTRY
│   │   ├── noop.py            # identity — for benign-corpus FPR runs
│   │   ├── lexical.py         # case, whitespace, /**/, clause reorder
│   │   ├── encoding.py        # URL/double-URL/unicode/HTML-entity/base64
│   │   ├── structural.py      # CONCAT, eval(), fromCharCode, …
│   │   ├── context_displacement.py  # JSON / XML / headers / multipart
│   │   ├── multi_request.py   # sequenced exploits with shared cookie jar
│   │   └── adaptive.py        # compositional (stacks two base mutators; seed-ranked)
│   ├── runner/
│   │   ├── engine.py          # async fan-out, baseline cache, raw JSON writer, waf-header capture
│   │   ├── verdict.py         # blocked / blocked_silent / allowed / flagged / baseline_fail
│   │   └── session.py         # DVWA + WebGoat login bootstrap
│   ├── analyzer/              # pandas, Wilson CIs, charts, CSVs, ordered ablations, latency
│   │   ├── aggregate.py       # raw JSON → flat DataFrame
│   │   ├── bypass.py          # true_bypass + waf_view + Wilson CI
│   │   ├── charts.py          # heatmap, grouped bars, small multiples
│   │   ├── export.py          # bypass_rates.csv / per_payload.csv / per_variant.csv
│   │   ├── combined.py        # merge N runs — last-in-list wins on WAF overlap
│   │   ├── ladder.py          # ordered ablation (paranoia, min-confidence) + FPR overlay
│   │   └── latency.py         # p50/p95/p99 per (waf, target) — feeds reporter Appendix B
│   ├── reporter/              # Markdown + LaTeX (IEEEtran) + combined + Hall of Fame
│   │   ├── markdown.py        # report.md — Table 1 + figures + Hall of Fame + Appendices A/B
│   │   ├── latex.py           # report.tex — IEEE conference class
│   │   ├── combined.py        # report-combined.{md,tex} for N-run merges
│   │   ├── hall_of_fame.py    # top-N variants by (waf × target) bypass cells
│   │   └── _data.py           # paper Table 1 reference + bibliography + mutator docstrings
│   ├── api/                   # FastAPI read-only backend
│   │   ├── app.py             # build_app() — routes
│   │   ├── store.py           # mtime-cached DataFrame access
│   │   └── __main__.py        # `python -m wafeval.api` / `wafeval-api`
│   └── cli.py                 # `wafeval run | report | report-combined | ladder`
└── tests/                     # 144 tests across mutators, loader, verdict, session, analyzer, latency, reporter, api, combined, ladder, benign-fpr, header-safe, waf-header-capture
```

## Quickstart (from the repo root)

```bash
# Host dev — editable install, run against the running stack.
# On NixOS wrap with ./scripts/with-nix-libs so numpy/pandas C-extensions
# resolve libstdc++ + zlib; the Makefile host-venv targets already do this.
python3 -m venv engine/.venv
engine/.venv/bin/pip install -e 'engine/[dev]'
engine/.venv/bin/python -m wafeval run --targets dvwa --classes sqli

# Containerised — `make run` starts the engine inside the waflab network
make run

# Regenerate report from the latest run (MD + TeX + 8 figures + Hall of
# Fame + Appendix A waf-view + Appendix B latency profile)
make report

# Serve the dashboard backend from the host venv for rapid edit/reload
make api-host          # uvicorn on 127.0.0.1:8001
```

Results land under `results/raw/<run_id>/<waf>/<target>/<payload>__<variant>.json`
with a `manifest.json` at the run root. CSVs go to `results/processed/<run_id>/`,
charts to `results/figures/<run_id>/`, and reports to `results/reports/<run_id>/`.

Each `VerdictRecord`'s `waf_route.waf_headers` captures WAF-identifying
response headers (name → value) the proxy stamped — e.g. Coraza's
`X-Coraza-Rules-Matched` + `X-Coraza-Interrupt-Rule`, Shadow Daemon's
`X-Shadowd-Threats` + `X-Shadowd-Verdict`, and the `X-Waflab-Waf` self-ID
our custom proxies emit. The dashboard's Payload Explorer detail pane
renders these as a key/value table when present.

## Adding a mutator

See `docs/ADDING_MUTATORS.md`. Short version: drop a new file under
`src/wafeval/mutators/`, subclass `Mutator`, decorate with `@register`,
return ≥5 variants per input, add a test.
