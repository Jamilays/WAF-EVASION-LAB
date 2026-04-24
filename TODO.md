# TODO

Items that would improve the lab but take more than a quick session. Listed
in rough priority order (top = most valuable-per-hour, bottom = largest).

---

### 1. Response-side rule-ID extraction

Response-header fingerprinting and latency profiles landed (see
`RouteResult.waf_headers` + the markdown reporter's Appendix B). The
remaining piece — which CRS rule IDs actually fired on a block — is
harder because the upstream `owasp/modsecurity-crs:nginx-alpine` image
returns a bare `403 Forbidden` HTML body with no rule IDs, and our
Coraza Go proxy likewise drops matched-rule information after
`WrapHandler` decides to deny.

**Scope:**
- ModSec: mount `SecAuditLog` from the container and tail-parse it to
  correlate rule IDs back to each request (requires JSON audit log
  format + a request-id correlation header).
- Coraza: patch `wafs/coraza/main.go` to capture `tx.MatchedRules()` on
  interrupt and stamp them into an `X-Coraza-Rules-Matched` header so
  the engine's existing `waf_headers` capture surfaces them for free.
- Needs a container rebuild + a light end-to-end smoke run to verify.
