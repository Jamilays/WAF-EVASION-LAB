# Engine — [Phase 3+]

Python mutation + testing engine. Directory layout from the charter:

```
engine/
├── pyproject.toml
├── src/
│   ├── payloads/     # YAML corpora per vuln class
│   ├── mutators/     # lexical / encoding / structural / context_displacement / multi_request
│   ├── runner/       # async HTTP, verdict recording, resume support
│   ├── analyzer/     # bypass rate + CIs + charts
│   ├── reporter/     # MD + LaTeX report
│   └── api/          # FastAPI → dashboard
└── tests/
```

Entrypoint lands in Phase 3 with one mutator end-to-end.
