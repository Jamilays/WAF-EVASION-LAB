# Engine — Phase 3

Python mutation + testing engine. Architecture (prompt.md §7–§9):

```
engine/
├── pyproject.toml
├── Dockerfile                 # builds waflab/engine:phase3
├── src/wafeval/
│   ├── models.py              # Payload, MutatedPayload, VerdictRecord, …
│   ├── config.py              # targets.yaml loader
│   ├── targets.yaml           # (target, vuln_class) → HTTP request template
│   ├── payloads/              # YAML corpora per vuln class + loader
│   │   ├── loader.py
│   │   ├── sqli.yaml
│   │   └── xss.yaml
│   ├── mutators/              # pluggable (base.py + one concrete: lexical.py)
│   │   ├── base.py            # ABC + @register decorator + REGISTRY
│   │   └── lexical.py         # case, whitespace, /**/, …
│   ├── runner/
│   │   ├── engine.py          # async fan-out, baseline cache, raw JSON writer
│   │   ├── verdict.py         # blocked / allowed / flagged / baseline_fail
│   │   └── session.py         # DVWA login bootstrap
│   └── cli.py                 # `wafeval run …` / `python -m wafeval run …`
└── tests/                     # mutator + loader + verdict unit tests
```

## Quickstart (from the repo root)

```bash
# Host dev — editable install, run against the running Phase 2 stack
python3 -m venv engine/.venv
engine/.venv/bin/pip install -e 'engine/[dev]'
engine/.venv/bin/python -m wafeval run --targets dvwa --classes sqli

# Containerised — `make run` starts the engine inside the waflab network
make run
```

Results land under `results/raw/<run_id>/<waf>/<target>/<payload>__<variant>.json`
with a `manifest.json` at the run root.

## Adding a mutator

See `docs/ADDING_MUTATORS.md`. Short version: drop a new file under
`src/wafeval/mutators/`, subclass `Mutator`, decorate with `@register`,
return ≥5 variants per input, add a test.
