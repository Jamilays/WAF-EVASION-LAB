# Engine — Phases 3–6

Python mutation + testing engine, analyzer, reporter, and read-only FastAPI
dashboard backend. Architecture (prompt.md §7–§11):

```
engine/
├── pyproject.toml
├── Dockerfile                 # builds waflab/engine:phase3 (used by engine, reporter, api)
├── src/wafeval/
│   ├── models.py              # Payload, MutatedPayload, VerdictRecord, …
│   ├── config.py              # targets.yaml loader
│   ├── targets.yaml           # (target, vuln_class) → HTTP request template
│   ├── payloads/              # YAML corpora per vuln class + loader
│   ├── mutators/              # base.py + 5 concrete mutators (Phase 4)
│   │   ├── base.py            # ABC + @register decorator + REGISTRY
│   │   ├── lexical.py         # case, whitespace, /**/, clause reorder
│   │   ├── encoding.py        # URL/double-URL/unicode/HTML-entity/base64
│   │   ├── structural.py      # CONCAT, eval(), fromCharCode, …
│   │   ├── context_displacement.py  # JSON / XML / headers / multipart
│   │   └── multi_request.py   # sequenced exploits with shared cookie jar
│   ├── runner/
│   │   ├── engine.py          # async fan-out, baseline cache, raw JSON writer
│   │   ├── verdict.py         # blocked / allowed / flagged / baseline_fail
│   │   └── session.py         # DVWA login bootstrap
│   ├── analyzer/              # Phase 5: pandas, Wilson CIs, charts, CSVs
│   │   ├── aggregate.py       # raw JSON → flat DataFrame
│   │   ├── bypass.py          # true_bypass + waf_view + Wilson CI
│   │   ├── charts.py          # heatmap, grouped bars, small multiples
│   │   └── export.py          # bypass_rates.csv / per_payload.csv / per_variant.csv
│   ├── reporter/              # Phase 5: Markdown + LaTeX (IEEEtran)
│   ├── api/                   # Phase 6: FastAPI read-only backend
│   │   ├── app.py             # build_app() — routes
│   │   ├── store.py           # mtime-cached DataFrame access
│   │   └── __main__.py        # `python -m wafeval.api` / `wafeval-api`
│   └── cli.py                 # `wafeval run …` / `wafeval report …`
└── tests/                     # 71 tests across mutators, loader, verdict, analyzer, reporter, api
```

## Quickstart (from the repo root)

```bash
# Host dev — editable install, run against the running Phase 2 stack
python3 -m venv engine/.venv
engine/.venv/bin/pip install -e 'engine/[dev]'
engine/.venv/bin/python -m wafeval run --targets dvwa --classes sqli

# Containerised — `make run` starts the engine inside the waflab network
make run

# Regenerate report from the latest run
make report

# Serve the dashboard backend from the host venv for rapid edit/reload
make api-host          # uvicorn on 127.0.0.1:8001
```

Results land under `results/raw/<run_id>/<waf>/<target>/<payload>__<variant>.json`
with a `manifest.json` at the run root. CSVs go to `results/processed/<run_id>/`,
charts to `results/figures/<run_id>/`, and reports to `results/reports/<run_id>/`.

## Adding a mutator

See `docs/ADDING_MUTATORS.md`. Short version: drop a new file under
`src/wafeval/mutators/`, subclass `Mutator`, decorate with `@register`,
return ≥5 variants per input, add a test.
