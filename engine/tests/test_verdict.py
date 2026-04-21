"""Verdict-classifier unit tests.

Covers every branch: error, baseline_fail (incl. redirects and stripped
payloads), blocked, allowed, flagged, plus the any_of composite trigger.
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


@pytest.fixture
def any_of_payload() -> Payload:
    return Payload.model_validate({
        "id": "p2", "class": "sqli",
        "payload": "' UNION SELECT 1 -- -",
        "trigger": {
            "kind": "any_of",
            "any_of": [
                {"kind": "contains", "needle": "First name"},
                {"kind": "regex", "pattern": "SQLITE_ERROR|syntax error"},
            ],
        },
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


def test_baseline_fail_even_when_waf_blocks(payload):
    """WAF 403 w/ baseline that didn't fire → BASELINE_FAIL, not BLOCKED.

    Previously this was (falsely) classified BLOCKED and inflated the
    denominator vs. WAFs that didn't block. Post-Bundle-2 the baseline
    check gates every other verdict.
    """
    baseline = _rr("baseline-dvwa.local", 200, "no rows")
    waf = _rr("modsec-dvwa.local", 403, "403 Forbidden")
    assert classify(payload, baseline, waf) is Verdict.BASELINE_FAIL


def test_302_redirect_is_baseline_fail_not_allowed(payload):
    """3xx means the app never reached the sink — can't call it a bypass."""
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    waf = _rr("coraza-dvwa.local", 302, "")
    assert classify(payload, baseline, waf) is Verdict.BASELINE_FAIL


def test_waf_2xx_without_marker_is_blocked(payload):
    """WAF returned 200 but the trigger marker is absent — payload stripped/transformed.

    This is the "silent" block pattern — open-appsec, Cloudflare Ruleset
    Engine, etc. sometimes pass the request but sanitise the query.
    """
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    waf = _rr("coraza-dvwa.local", 200, "ID: 1<br/>no rows returned")
    assert classify(payload, baseline, waf) is Verdict.BLOCKED


def test_flagged_on_block_marker_in_2xx(payload):
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    # Marker present (exploit landed) AND WAF sentinel body present.
    waf = _rr("shadowd-dvwa.local", 200, "First name: admin — Request blocked by Shadow Daemon observer")
    assert classify(payload, baseline, waf) is Verdict.FLAGGED


def test_error_on_network_failure(payload):
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    waf = _rr("modsec-dvwa.local", None, error="ConnectError('timeout')")
    assert classify(payload, baseline, waf) is Verdict.ERROR


def test_blocked_on_5xx_with_waf_marker(payload):
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    waf = _rr("modsec-dvwa.local", 500, "ModSecurity: Access denied")
    assert classify(payload, baseline, waf) is Verdict.BLOCKED


def test_any_of_trigger_dvwa_marker(any_of_payload):
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    waf = _rr("shadowd-dvwa.local", 200, "First name: admin")
    assert classify(any_of_payload, baseline, waf) is Verdict.ALLOWED


def test_any_of_trigger_juiceshop_error(any_of_payload):
    """Juice Shop 500 + SQLITE_ERROR is a successful SQLi bypass."""
    baseline = _rr("baseline-juiceshop.local", 500, "Error: SQLITE_ERROR: near UNION")
    waf = _rr("coraza-juiceshop.local", 500, "Error: SQLITE_ERROR: near UNION")
    assert classify(any_of_payload, baseline, waf) is Verdict.ALLOWED


def test_5xx_without_marker_is_baseline_fail(payload):
    baseline = _rr("baseline-dvwa.local", 200, "First name: admin")
    waf = _rr("coraza-dvwa.local", 500, "something went wrong — not a WAF signature")
    assert classify(payload, baseline, waf) is Verdict.BASELINE_FAIL
