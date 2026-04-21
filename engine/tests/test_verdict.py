"""Verdict-classifier unit tests.

Covers the four interesting branches: blocked, allowed, baseline_fail, flagged.
"""
from __future__ import annotations

import pytest

from wafeval.models import Payload, RouteResult, Verdict
from wafeval.runner.verdict import classify


@pytest.fixture
def payload() -> Payload:
    return Payload.model_validate({
        "id": "p1", "class": "sqli",
        "payload": "1' or '1'='1 -- -",
        "trigger": {"kind": "contains", "needle": "First name"},
    })


def _rr(route: str, status: int | None, body: str = "", *, error: str | None = None, notes: str | None = None) -> RouteResult:
    return RouteResult(
        route=route, status_code=status,
        response_ms=1.0 if status else None,
        response_bytes=len(body) if status else None,
        response_snippet=body if status else None,
        error=error, notes=notes,
    )


def test_blocked_on_403(payload):
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    waf = _rr("modsec-dvwa.local", 403, "403 Forbidden")
    assert classify(payload, baseline, waf) is Verdict.BLOCKED


def test_allowed_when_baseline_triggered(payload):
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    waf = _rr("modsec-dvwa.local", 200, "First name: admin")
    assert classify(payload, baseline, waf) is Verdict.ALLOWED


def test_baseline_fail_suppresses_bypass_claim(payload):
    baseline = _rr("baseline-dvwa.local", 200, "no rows")
    waf = _rr("coraza-dvwa.local", 200, "no rows")
    assert classify(payload, baseline, waf) is Verdict.BASELINE_FAIL


def test_flagged_on_block_marker_in_2xx(payload):
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    waf = _rr("shadowd-dvwa.local", 200, "Request blocked by Shadow Daemon observer")
    assert classify(payload, baseline, waf) is Verdict.FLAGGED


def test_error_on_network_failure(payload):
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    waf = _rr("modsec-dvwa.local", None, error="ConnectError('timeout')")
    assert classify(payload, baseline, waf) is Verdict.ERROR


def test_blocked_on_5xx_with_waf_marker(payload):
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    waf = _rr("modsec-dvwa.local", 500, "ModSecurity: Access denied")
    assert classify(payload, baseline, waf) is Verdict.BLOCKED
