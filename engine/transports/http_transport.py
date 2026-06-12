from __future__ import annotations

import asyncio
import gzip
import json
from typing import Any

import httpx

from config.settings import settings
from transports.base import SendResult, SourceMeta, Transport
from utils.logger import get_logger

logger = get_logger(__name__)

MAX_RETRIES = 3
RETRY_BASE_DELAY = 1.0

_LOG_TYPE_CONTENT_TYPE = {
    "json": "application/json",
    "raw": "text/plain",
    "cef": "text/plain",
    "leef": "text/plain",
}


def _build_body(payload: str, log_type: str, source_id: str) -> bytes:
    if log_type == "json":
        try:
            event = json.loads(payload) if isinstance(payload, str) else payload
        except json.JSONDecodeError:
            event = {"raw": payload}
        if isinstance(event, dict):
            event = {"simulated_log_source": source_id, **event}
        return json.dumps([event]).encode("utf-8")
    # raw / cef / leef: prepend simulated_log_source so XSIAM can extract it
    stripped = payload.rstrip("\n")
    return f'simulated_log_source="{source_id}" {stripped}\n'.encode("utf-8")


class HTTPTransport(Transport):
    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    def _build_headers(self, meta: SourceMeta) -> dict[str, str]:
        api_key = meta.http_api_key or settings.xsiam_api_key
        content_type = _LOG_TYPE_CONTENT_TYPE.get(meta.http_log_type, "text/plain")
        headers: dict[str, str] = {
            "Content-Type": content_type,
            "Authorization": api_key,
        }
        if meta.http_compression == "gzip":
            headers["Content-Encoding"] = "gzip"
        return headers

    async def send(self, payload: str, source_meta: SourceMeta) -> SendResult:
        body = _build_body(payload, source_meta.http_log_type, source_meta.source_id)
        if source_meta.http_compression == "gzip":
            encoded = gzip.compress(body)
        else:
            encoded = body

        headers = self._build_headers(source_meta)

        src = source_meta.source_id
        url = settings.xsiam_url
        for attempt in range(MAX_RETRIES):
            try:
                client = self._get_client()
                resp = await client.post(url, content=encoded, headers=headers)
                if resp.status_code >= 400:
                    body_snippet = resp.text[:1000]
                    logger.error({
                        "event": "xsiam_http_error",
                        "source": src,
                        "status": resp.status_code,
                        "url": url,
                        "response": body_snippet,
                    })
                else:
                    logger.info({
                        "event": "xsiam_http_ok",
                        "source": src,
                        "status": resp.status_code,
                        "bytes": len(encoded),
                    })
                resp.raise_for_status()
                return SendResult(success=True, bytes_sent=len(encoded))
            except httpx.HTTPStatusError as e:
                status = e.response.status_code
                if status == 429:
                    retry_after = float(e.response.headers.get("Retry-After", RETRY_BASE_DELAY * (2 ** attempt)))
                    if attempt < MAX_RETRIES - 1:
                        await asyncio.sleep(retry_after)
                        continue
                if status < 500 or attempt == MAX_RETRIES - 1:
                    return SendResult(success=False, error=f"HTTP {status}: {e.response.text[:200]}")
                await asyncio.sleep(RETRY_BASE_DELAY * (2 ** attempt))
            except Exception as e:
                logger.error({"event": "xsiam_connect_error", "source": src, "url": url, "error": str(e)})
                if attempt == MAX_RETRIES - 1:
                    return SendResult(success=False, error=str(e))
                await asyncio.sleep(RETRY_BASE_DELAY * (2 ** attempt))

        return SendResult(success=False, error="Max retries exceeded")

    async def send_batch(self, events: list[dict[str, Any]], source_meta: SourceMeta) -> SendResult:
        sid = source_meta.source_id
        if source_meta.http_log_type == "json":
            augmented = [
                {"simulated_log_source": sid, **e} if isinstance(e, dict) else {"simulated_log_source": sid, "raw": str(e)}
                for e in events
            ]
            body = json.dumps(augmented).encode("utf-8")
        else:
            body = "\n".join(
                f'simulated_log_source="{sid}" {e.get("raw", json.dumps(e)) if isinstance(e, dict) else str(e)}'
                for e in events
            ).encode("utf-8") + b"\n"

        if source_meta.http_compression == "gzip":
            encoded = gzip.compress(body)
        else:
            encoded = body

        headers = self._build_headers(source_meta)

        src = source_meta.source_id
        url = settings.xsiam_url
        for attempt in range(MAX_RETRIES):
            try:
                client = self._get_client()
                resp = await client.post(url, content=encoded, headers=headers)
                if resp.status_code >= 400:
                    logger.error({
                        "event": "xsiam_http_error",
                        "source": src,
                        "status": resp.status_code,
                        "url": url,
                        "response": resp.text[:1000],
                    })
                else:
                    logger.info({
                        "event": "xsiam_http_ok",
                        "source": src,
                        "status": resp.status_code,
                        "bytes": len(encoded),
                    })
                resp.raise_for_status()
                return SendResult(success=True, bytes_sent=len(encoded))
            except httpx.HTTPStatusError as e:
                status = e.response.status_code
                if status == 429:
                    retry_after = float(e.response.headers.get("Retry-After", RETRY_BASE_DELAY * (2 ** attempt)))
                    if attempt < MAX_RETRIES - 1:
                        await asyncio.sleep(retry_after)
                        continue
                if status < 500 or attempt == MAX_RETRIES - 1:
                    return SendResult(success=False, error=f"HTTP {status}")
                await asyncio.sleep(RETRY_BASE_DELAY * (2 ** attempt))
            except Exception as e:
                logger.error({"event": "xsiam_connect_error", "source": src, "url": url, "error": str(e)})
                if attempt == MAX_RETRIES - 1:
                    return SendResult(success=False, error=str(e))
                await asyncio.sleep(RETRY_BASE_DELAY * (2 ** attempt))

        return SendResult(success=False, error="Max retries exceeded")

    async def health_check(self) -> bool:
        try:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(settings.xsiam_url)
            health_url = urlunparse(parsed._replace(path="/healthcheck", query="", fragment=""))
            client = self._get_client()
            resp = await client.get(health_url, timeout=5.0)
            return resp.status_code < 500
        except Exception:
            return False

    def reset(self) -> None:
        self._client = None

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
