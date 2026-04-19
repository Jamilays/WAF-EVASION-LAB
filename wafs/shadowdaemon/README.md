# Shadow Daemon

Shadow Daemon is architecturally different from the other three WAFs: it's a **language-level** WAF. Official connectors exist only for PHP, Perl, and Python — there is no nginx/Apache reverse-proxy connector published by upstream.

## Phase 1 shape

We ship three containers:

| Service | Image | Purpose |
|---|---|---|
| `shadowd-db` | `zecure/shadowd_database:12.4` | Postgres schema/config store |
| `shadowd` | `zecure/shadowd:2.2.0` | Analysis daemon, TCP :9115 |
| `shadowd-proxy` | built from `./proxy/` | Python async reverse proxy that speaks the shadowd JSON wire protocol; sits in front of arbitrary HTTP apps |

The proxy exposes `http://127.0.0.1:8083/`. `GET /healthz` always returns 200 (does not round-trip to shadowd — health must not depend on the analyzer's verdict).

## Phase 2 plan

- DVWA gets the **native PHP connector** (no custom proxy involvement) — matches paper methodology.
- WebGoat and Juice Shop continue to use `shadowd-proxy` (no native Java/Node connector).
- Flip `SHADOWD_ENFORCE=true` so the verdict becomes blocking rather than advisory.
- Seed the Postgres store with a `waflab` profile and its HMAC key.
