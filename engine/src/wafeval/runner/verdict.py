"""Verdict classifier.

Implements prompt.md §8 verdict rules:
  - blocked: WAF returned 4xx/5xx matching a block signature
  - allowed: 2xx and baseline trigger confirmed → real bypass
  - flagged: 2xx but WAF logged / signaled detection (headers, sentinel body)
  - baseline_fail: baseline didn't confirm vuln — can't claim bypass
  - error: network/timeout/protocol failure

Block signatures are per-WAF. ModSecurity's CRS nginx image returns 403 with
a plain "403 Forbidden" body; Coraza returns 403 + the "phase:X" Coraza
diagnostic; shadowd-proxy returns 500 when SHADOWD_ENFORCE=true (Phase 3
default is false, so shadowd is observed but not enforced).
"""
from __future__ import annotations

import re
from typing import Final

from wafeval.models import Payload, RouteResult, TriggerContains, TriggerReflected, TriggerRegex, TriggerStatus, Verdict

_BLOCK_STATUS_CODES: Final = frozenset({403, 406, 501})
_FLAG_HEADERS: Final = (
    "x-coraza-status",
    "x-modsec-interrupted",
    "x-shadowd-verdict",
)
_BLOCK_BODY_MARKERS: Final = (
    "mod_security",
    "modsecurity",
    "forbidden by coraza",
    "request denied by coraza",
    "request blocked by shadow",
)


def baseline_triggered(payload: Payload, baseline: RouteResult) -> bool:
    """True iff the baseline response proves the vuln fired.

    Returns False on any network-level error. For ``reflected`` triggers the
    marker defaults to the raw payload body when the author didn't supply one.
    """
    if baseline.error or baseline.status_code is None or baseline.response_snippet is None:
        return False
    body = baseline.response_snippet

    t = payload.trigger
    if isinstance(t, TriggerContains):
        return t.needle in body
    if isinstance(t, TriggerRegex):
        return re.search(t.pattern, body) is not None
    if isinstance(t, TriggerReflected):
        marker = t.marker or payload.payload
        return marker in body
    if isinstance(t, TriggerStatus):
        return baseline.status_code == t.code
    raise AssertionError(f"unknown trigger kind: {t!r}")


def classify(
    payload: Payload,
    baseline: RouteResult,
    waf_route: RouteResult,
) -> Verdict:
    """Return the verdict for one (payload, waf_route) datapoint."""
    if waf_route.error is not None:
        return Verdict.ERROR

    code = waf_route.status_code
    body = (waf_route.response_snippet or "").lower()
    headers_flagged = any(h in _FLAG_HEADERS for h in (waf_route.notes or "").lower().split(","))

    # Block signatures first — a 403 with a ModSec body is unambiguous.
    if code in _BLOCK_STATUS_CODES:
        return Verdict.BLOCKED
    if code is not None and 500 <= code < 600 and any(m in body for m in _BLOCK_BODY_MARKERS):
        return Verdict.BLOCKED

    # 2xx — needs baseline confirmation to claim bypass.
    if code is not None and 200 <= code < 400:
        if not baseline_triggered(payload, baseline):
            return Verdict.BASELINE_FAIL
        if headers_flagged or any(m in body for m in _BLOCK_BODY_MARKERS):
            return Verdict.FLAGGED
        return Verdict.ALLOWED

    # Unclassified status → error.
    return Verdict.ERROR
