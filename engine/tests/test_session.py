"""Tests for runner/session.py helpers — keep the DVWA login-token regex
locked against a frozen fixture so a future DVWA upgrade that rearranges the
login form can't silently break authentication."""
from __future__ import annotations

import textwrap

from wafeval.runner.session import DEFAULT_USER_AGENT, parse_user_token


def test_parse_user_token_single_quotes():
    # Matches the live DVWA v1.10 body shipped with vulnerables/web-dvwa.
    html = textwrap.dedent("""
        <form action="login.php" method="post">
          <input type="submit" value="Login" name="Login">
          <input type='hidden' name='user_token' value='93106c62957de7d146b717296dab4d08' />
        </form>
    """)
    assert parse_user_token(html) == "93106c62957de7d146b717296dab4d08"


def test_parse_user_token_double_quotes():
    html = '<input type="hidden" name="user_token" value="deadbeefcafef00d" />'
    assert parse_user_token(html) == "deadbeefcafef00d"


def test_parse_user_token_missing_returns_none():
    assert parse_user_token("<html>no form here</html>") is None


def test_parse_user_token_non_hex_rejected():
    # Must be a hex string — a decoy ``value='notatoken!'`` shouldn't match.
    assert parse_user_token("name='user_token' value='notatoken!'") is None


def test_default_user_agent_is_not_scripted():
    ua = DEFAULT_USER_AGENT.lower()
    # CRS rule 913100 flags common scripted UAs — keep us out of the list.
    for bad in ("httpx", "wafeval", "python-requests", "curl", "wget", "nikto"):
        assert bad not in ua
    assert "mozilla" in ua
