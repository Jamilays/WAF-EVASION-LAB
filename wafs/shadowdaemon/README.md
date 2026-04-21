# Shadow Daemon

Shadow Daemon is architecturally different from the other three WAFs: it's
a **language-level** WAF. Official connectors exist only for PHP, Perl, and
Python — there is no upstream nginx/Apache reverse-proxy connector.

## Topology

| Service | Image | Purpose |
|---|---|---|
| `shadowd-db` | `zecure/shadowd_database:12.4` | Postgres schema + rule store |
| `shadowd`    | `zecure/shadowd:2.2.0` | Analysis daemon, TCP :9115 |
| `shadowd-<target>` | built from `./proxy/` | Python async reverse proxy that sits in front of an arbitrary HTTP target |

`GET /healthz` on the proxy always returns 200 (does not round-trip to the
shadowd daemon — health must not depend on the analyzer's verdict).

## Blocking behaviour (post-Phase-6 audit)

The proxy enforces a block when **either** of two signals fires:

1. **shadowd daemon verdict `status=1`** — the intended path. Requires a
   provisioned DB profile + HMAC-signed wire protocol. Not yet bootstrapped
   in this lab (see "Future work" below). Until then the daemon returns no
   verdict for unprovisioned profiles.
2. **In-proxy fallback detector** — regex rules for SQLi / XSS / cmdi / LFI
   run over the URL path, query parameters, and request body when
   `SHADOWD_ENFORCE=true` and `SHADOWD_FALLBACK_BLOCK=true`.

Without the fallback, `SHADOWD_ENFORCE=true` silently became a no-op (the
daemon's analysis never completed), which produced a spurious 100% bypass
rate in every comparison against the other WAFs.

Env toggles:

| Var | Default | Meaning |
|---|---|---|
| `SHADOWD_ENFORCE` | `true` | Translate verdicts into 403s (vs. observer-only) |
| `SHADOWD_FALLBACK_BLOCK` | `true` | Let the proxy block on its own regex match if shadowd has no verdict |
| `SHADOWD_TIMEOUT` | `0.5s` | Analyzer roundtrip budget — exceeded → treated as "no verdict" |

The fallback detector **only scans user-controllable slots** (path, query,
body). Headers like `User-Agent` and `Cookie` are intentionally ignored so
legitimate values (`curl/8.1.2`, session cookies) don't false-positive.
Context-displacement mutators that relocate payloads into custom `X-*`
headers are only caught by the real shadowd path.

## Future work

Real shadowd integration (Phase 7 candidate):

- Add a `shadowd-init` sidecar that runs on first boot to:
  - Insert a `profiles` row with a known `hmac_key`, `mode=2`, `blacklist_enabled=1`
  - Seed `blacklist_rules` with default OWASP-CRS-analogue entries so the
    bundled `blacklist_filters` are actually consulted
- Update `proxy.py` to compute `HMAC-SHA256(body, profile.hmac_key)` and
  send `profile_id` + `hmac` on the wire
- Once the real shadowd path is verified end-to-end, flip
  `SHADOWD_FALLBACK_BLOCK=false` by default so the proxy is a pure
  forwarding connector and every block is attributable to the daemon
