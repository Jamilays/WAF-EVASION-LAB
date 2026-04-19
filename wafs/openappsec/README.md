# open-appsec — STUBBED (Phase 1)

Per the Phase 1 charter ("3 WAFs healthy + ML profile stubbed"), open-appsec is represented by an identifiable placeholder service under `--profile ml`. It uses `traefik/whoami` so the port binds cleanly and health checks trivially; no ML analysis happens.

```bash
make up-ml    # brings up the stub on 127.0.0.1:8084
```

## Enabling the real agent (post-Phase 1)

open-appsec ships as a CheckPoint-published container. To enable:

1. Choose an agent image + tag from https://github.com/openappsec/openappsec (the standalone docker agent).
2. Replace the `openappsec` service in `docker-compose.yml` with the real agent compose snippet (it typically needs `SHARED_STORAGE_HOST`, `LEARNING_HOST`, and a volume for local learning state).
3. Add a warm-up gate: the agent spends ~60s in "learning" mode before it flips to "prevent". Model this with a `healthcheck` that first polls for the agent's `/api/status` endpoint, then for `mode=prevent`.
4. Seed a deterministic ruleset (`policy.yaml`) so runs are comparable across machines.

Until then: the stub is functionally a pass-through proxy. The engine (Phase 3+) will see it as "all allowed" and skip it in the comparison unless the user opts in by replacing the stub with the real agent.
