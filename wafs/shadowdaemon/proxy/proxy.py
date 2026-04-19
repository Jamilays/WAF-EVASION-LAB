"""
Shadow Daemon reverse-proxy connector (Phase 1).

Shadow Daemon publishes only language-level connectors (PHP / Perl / Python).
To put it in front of arbitrary HTTP apps (WebGoat, Juice Shop, placeholder
backends) the lab ships this small async reverse proxy that speaks the Shadow
Daemon JSON wire protocol on TCP :9115 and proxies approved requests to BACKEND.

Phase 1 scope:
  - /healthz always returns 200 (bypasses shadowd — health must not depend on
    the daemon's verdict)
  - All other paths are proxied to BACKEND unchanged
  - shadowd analysis is called best-effort; if SHADOWD_ENFORCE=false the
    verdict is logged but not enforced (learning mode)

Phase 2+ will:
  - sign requests with an HMAC profile key
  - enforce block verdicts with a 403
  - annotate responses with x-waflab-verdict headers
  - add request-mutation support so the engine can record which CRS-analogue
    rules fired (shadowd returns a threat list)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Mount, Route

logger = logging.getLogger("shadowd-proxy")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

BACKEND = os.getenv("BACKEND", "http://whoami:80").rstrip("/")
SHADOWD_HOST = os.getenv("SHADOWD_HOST", "shadowd")
SHADOWD_PORT = int(os.getenv("SHADOWD_PORT", "9115"))
SHADOWD_ENFORCE = os.getenv("SHADOWD_ENFORCE", "false").lower() == "true"
SHADOWD_TIMEOUT = float(os.getenv("SHADOWD_TIMEOUT", "0.5"))

_client: httpx.AsyncClient | None = None


async def _analyze(request: Request) -> dict[str, Any] | None:
    """Send the request to shadowd:9115 and return the parsed verdict.

    Returns None on any failure — the proxy is permissive on analyzer errors
    so a transient shadowd blip does not take the whole WAF lane down.
    """
    payload = {
        "version": "1.0.0-waflab",
        "client_ip": request.client.host if request.client else "0.0.0.0",
        "caller": "waflab-proxy",
        "resource": request.url.path,
        "input": {
            "SERVER|REQUEST_METHOD": request.method,
            "SERVER|REQUEST_URI": request.url.path + (f"?{request.url.query}" if request.url.query else ""),
            **{f"HEADER|{k.upper()}": v for k, v in request.headers.items()},
            **{f"GET|{k}": v for k, v in request.query_params.items()},
        },
        "hashes": {},
    }
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(SHADOWD_HOST, SHADOWD_PORT),
            timeout=SHADOWD_TIMEOUT,
        )
    except (OSError, asyncio.TimeoutError) as e:
        logger.debug("shadowd connect failed: %s", e)
        return None
    try:
        writer.write(json.dumps(payload).encode() + b"\n")
        await writer.drain()
        raw = await asyncio.wait_for(reader.readline(), timeout=SHADOWD_TIMEOUT)
    except (OSError, asyncio.TimeoutError) as e:
        logger.debug("shadowd read failed: %s", e)
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return None


async def healthz(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok\n", status_code=200)


async def proxy(request: Request) -> Response:
    assert _client is not None

    verdict = await _analyze(request)
    if verdict and verdict.get("status") == 1 and SHADOWD_ENFORCE:
        logger.info("shadowd BLOCK %s %s threats=%s",
                    request.method, request.url.path, verdict.get("threats"))
        return PlainTextResponse("Blocked by Shadow Daemon\n", status_code=403,
                                 headers={"x-waflab-verdict": "blocked",
                                          "x-waflab-waf": "shadowdaemon"})

    # Build upstream URL
    upstream = f"{BACKEND}{request.url.path}"
    if request.url.query:
        upstream += f"?{request.url.query}"

    body = await request.body()
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}

    try:
        resp = await _client.request(
            request.method, upstream, headers=headers, content=body,
        )
    except httpx.RequestError as e:
        logger.warning("backend error: %s", e)
        return PlainTextResponse(f"Upstream error: {e}\n", status_code=502,
                                 headers={"x-waflab-verdict": "upstream_error"})

    response_headers = {k: v for k, v in resp.headers.items()
                        if k.lower() not in ("content-encoding", "transfer-encoding", "content-length", "connection")}
    response_headers["x-waflab-verdict"] = (
        "allowed" if not verdict else f"analyzed:status={verdict.get('status')}"
    )
    response_headers["x-waflab-waf"] = "shadowdaemon"
    return Response(content=resp.content, status_code=resp.status_code,
                    headers=response_headers, media_type=resp.headers.get("content-type"))


async def _on_startup() -> None:
    global _client
    _client = httpx.AsyncClient(timeout=10.0, follow_redirects=False)
    logger.info("shadowd-proxy up — backend=%s shadowd=%s:%d enforce=%s",
                BACKEND, SHADOWD_HOST, SHADOWD_PORT, SHADOWD_ENFORCE)


async def _on_shutdown() -> None:
    if _client is not None:
        await _client.aclose()


app = Starlette(
    routes=[
        Route("/healthz", healthz, methods=["GET"]),
        Route("/{path:path}", proxy,
              methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]),
    ],
    on_startup=[_on_startup],
    on_shutdown=[_on_shutdown],
)
