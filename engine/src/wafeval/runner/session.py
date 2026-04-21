"""DVWA session bootstrap.

The /vulnerabilities/* pages require an authenticated session. This module
logs in once per ``(waf, target)`` route that needs auth and returns the
authenticated cookie jar for the caller to attach to every subsequent
request.

Implementation detail: DVWA's login form carries a CSRF ``user_token`` field
that is scraped from the GET /login.php response. ``security=low`` is set by
injecting the cookie client-side rather than relying on the GET-redirect
dance to /security.php — older versions of this file followed the redirect,
which silently dropped the cookie when the client had ``follow_redirects=False``.
"""
from __future__ import annotations

import re

import httpx
import structlog

from wafeval.config import DvwaLogin

log = structlog.get_logger(__name__)

# Quote-agnostic: DVWA emits ``value='...'`` but a fork could switch to ``"``.
# The regex also tolerates attribute-order flips (``value=...`` appearing
# before ``name=``) by scanning for the two anchors in either order.
_TOKEN_RE = re.compile(
    r"""name=['"]user_token['"]\s+value=['"]([a-f0-9]{16,64})['"]""",
    re.IGNORECASE,
)

# A benign, modern UA — survives CRS rule 913100 (bad-bot UA) at every
# paranoia level we ship (PL1 default + PL4 --profile paranoia-high).
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)


def parse_user_token(html: str) -> str | None:
    """Extract DVWA's ``user_token`` from a login-page body.

    Exposed so the test suite can exercise the regex against fixture HTML
    without standing up a full DVWA.
    """
    m = _TOKEN_RE.search(html)
    return m.group(1) if m else None


async def login_dvwa(
    client: httpx.AsyncClient,
    base_url: str,
    host: str,
    login: DvwaLogin,
) -> dict[str, str]:
    """Authenticate against DVWA through ``host`` and return cookies.

    Called once per route that has ``expect_auth=True`` endpoints. DVWA
    tracks sessions by a PHPSESSID cookie — the returned dict is the
    authoritative jar for that route and should not be merged with a shared
    client jar (see runner/engine.py for the per-route isolation).
    """
    headers = {"Host": host, "User-Agent": DEFAULT_USER_AGENT}

    r1 = await client.get(f"{base_url}{login.path}", headers=headers, follow_redirects=False)
    token = parse_user_token(r1.text) or ""
    if not token:
        log.warning("dvwa.login.no_token", host=host, status=r1.status_code)

    cookies = dict(r1.cookies)
    # DVWA's install flow stamps the PHPSESSID on the login-page GET when the
    # client arrives without one. If the shared-jar case in the past nuked
    # Set-Cookie, the login POST below would fail; a per-route client jar
    # (Bundle 3) plus this direct ``cookies`` dict makes the flow robust.

    form = {
        "username": login.username,
        "password": login.password,
        "Login": "Login",
        "user_token": token,
    }
    r2 = await client.post(
        f"{base_url}{login.path}",
        data=form,
        headers=headers,
        cookies=cookies,
        follow_redirects=False,
    )
    cookies.update(r2.cookies)

    # Set security=low directly — the previous GET /security.php?security=low
    # flow relied on DVWA's 302 redirect stamping the cookie, which doesn't
    # happen reliably when follow_redirects is off. Setting it client-side is
    # deterministic and matches what DVWA's own form would do.
    cookies["security"] = "low"

    log.info(
        "dvwa.login.done",
        host=host,
        status=r2.status_code,
        have_phpsessid="PHPSESSID" in cookies,
        have_token=bool(token),
    )
    return cookies
