from __future__ import annotations

import asyncio
import hashlib
import json
import random
import string
import time
from typing import Any

import httpx

from config.settings import settings
from transports.base import SendResult, SourceMeta, Transport
from utils.logger import get_logger

logger = get_logger(__name__)

MAX_BATCH_EVENTS = 1000
MAX_BATCH_BYTES = 1_000_000  # 1 MB
MAX_RETRIES = 3
RETRY_BASE_DELAY = 1.0

_NONCE_CHARS = string.ascii_letters + string.digits


def _sign_request(api_key: str, nonce: str, timestamp: str) -> str:
    # XSIAM uses plain SHA256 of concatenated string, not HMAC.
    # See: docs-cortex.paloaltonetworks.com HTTP log collector auth guide.
    return hashlib.sha256(f"{api_key}{nonce}{timestamp}".encode()).hexdigest()


class HTTPTransport(Transport):
    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None
        self._batch: list[dict[str, Any]] = []
        self._batch_lock = asyncio.Lock()

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    def _build_headers(self, dataset: str, content_type: str = "application/json") -> dict[str, str]:
        # Nonce: 64 random alphanumeric chars per XSIAM API spec
        nonce = "".join(random.choices(_NONCE_CHARS, k=64))
        timestamp = str(int(time.time() * 1000))
        signature = _sign_request(settings.xsiam_api_key, nonce, timestamp)
        return {
            "Content-Type": content_type,
            "x-xdr-auth-id": settings.xsiam_auth_id,
            "x-xdr-nonce": nonce,
            "x-xdr-timestamp": timestamp,
            "x-xdr-hmac": signature,
            "x-xdr-dataset": dataset,
        }

    async def send(self, payload: str, source_meta: SourceMeta) -> SendResult:
        try:
            event = json.loads(payload) if isinstance(payload, str) else payload
        except json.JSONDecodeError:
            event = {"raw": payload}

        dataset = source_meta.dataset or settings.xsiam_dataset
        event["_source_id"] = source_meta.source_id
        event["_dataset"] = dataset

        body = json.dumps([event])
        encoded = body.encode()

        for attempt in range(MAX_RETRIES):
            try:
                client = self._get_client()
                headers = self._build_headers(dataset)
                resp = await client.post(settings.xsiam_url, content=encoded, headers=headers)
                resp.raise_for_status()
                return SendResult(success=True, bytes_sent=len(encoded))
            except httpx.HTTPStatusError as e:
                status = e.response.status_code
                # Retry on 5xx and 429 (rate limited); 429 respects Retry-After if present
                if status == 429:
                    retry_after = float(e.response.headers.get("Retry-After", RETRY_BASE_DELAY * (2 ** attempt)))
                    if attempt < MAX_RETRIES - 1:
                        await asyncio.sleep(retry_after)
                        continue
                if status < 500 or attempt == MAX_RETRIES - 1:
                    return SendResult(success=False, error=str(e))
                await asyncio.sleep(RETRY_BASE_DELAY * (2 ** attempt))
            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    return SendResult(success=False, error=str(e))
                await asyncio.sleep(RETRY_BASE_DELAY * (2 ** attempt))

        return SendResult(success=False, error="Max retries exceeded")

    async def send_batch(self, events: list[dict], source_meta: SourceMeta) -> SendResult:
        dataset = source_meta.dataset or settings.xsiam_dataset
        body = json.dumps(events)
        encoded = body.encode()

        for attempt in range(MAX_RETRIES):
            try:
                client = self._get_client()
                headers = self._build_headers(dataset)
                resp = await client.post(settings.xsiam_url, content=encoded, headers=headers)
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
                    logger.warning({"event": "http_send_error", "status": status, "source": source_meta.source_id})
                    return SendResult(success=False, error=str(e))
                await asyncio.sleep(RETRY_BASE_DELAY * (2 ** attempt))
            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    logger.error({"event": "http_send_exception", "error": str(e), "source": source_meta.source_id})
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
