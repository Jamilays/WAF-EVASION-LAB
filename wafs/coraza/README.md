# Coraza (Go) + OWASP CRS v4

Small Go reverse proxy that wraps a Coraza WAF around `net/http/httputil`, loading CRS v4 from the [`coraza-coreruleset`](https://github.com/corazawaf/coraza-coreruleset) embedded FS — same ruleset as ModSecurity, fair comparison.

## Files

- `main.go` — entrypoint (~70 lines)
- `go.mod` — pins `coraza/v3` and `coraza-coreruleset`
- `Dockerfile` — two-stage build, static binary on Alpine

## Env

| Env var | Default | Notes |
|---|---|---|
| `BACKEND` | `http://whoami:80` | Upstream URL |
| `LISTEN_ADDR` | `:80` | Proxy bind |
| `CORAZA_EXTRA_DIRECTIVES` | `""` | Appended after CRS setup; used by `paranoia-high` profile to raise `tx.blocking_paranoia_level` |

## Paranoia-high override

Handled by the compose `coraza-ph` service — passes a `SecAction` that sets `tx.blocking_paranoia_level=4` after CRS setup.
