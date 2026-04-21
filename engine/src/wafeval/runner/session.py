"""DVWA session bootstrap.

The /vulnerabilities/* pages require an authenticated session. This module
logs in once per ``(waf, target)`` route that needs auth and caches the
resulting cookies for the rest of the run.

Implementation detail: DVWA's login form carries a CSRF ``user_token`` field
that is scraped from the GET /login.php response. We also have to set
``security=low`` on /security.php so the SQLi/XSS pages behave as expected
(the dvwa-init container already sets DB-side defaults, but cookie-side has
to be done by the client).
"""
from __future__ import annotations

import re

import httpx
import structlog

from wafeval.config import DvwaLogin

log = structlog.get_logger(__name__)

_TOKEN_RE = re.compile(
    r"name=['\"]user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]",
    re.IGNORECASE,
)


async def login_dvwa(
    client: httpx.AsyncClient,
    base_url: str,
    host: str,
    login: DvwaLogin,
) -> dict[str, str]:
    """Authenticate against DVWA through ``host`` and return cookies.

    Called once per route that has ``expect_auth=True`` endpoints. DVWA tracks
    sessions by a PHPSESSID cookie — the returned dict feeds straight into
    httpx's per-request ``cookies=`` param.
    """
    headers = {"Host": host, "User-Agent": "wafeval-phase3"}

    r1 = await client.get(f"{base_url}{login.path}", headers=headers, follow_redirects=False)
    token_m = _TOKEN_RE.search(r1.text)
    if token_m is None:
        log.warning("dvwa.login.no_token", host=host, status=r1.status_code)
        token = ""
    else:
        token = token_m.group(1)
    cookies = dict(r1.cookies)

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

    # Set security=low. The cookie is set server-side once this GET is made.
    await client.get(
        f"{base_url}/security.php?security=low&seclev_submit=Submit",
        headers=headers,
        cookies=cookies,
        follow_redirects=False,
    )

    log.info(
        "dvwa.login.done",
        host=host,
        status=r2.status_code,
        have_phpsessid="PHPSESSID" in cookies,
    )
    return cookies
