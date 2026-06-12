from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
import uuid
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


def _sign_request(api_key: str, nonce: str, timestamp: str) -> str:
    message = f"{api_key}{nonce}{timestamp}"
    return hmac.new(api_key.encode(), message.encode(), hashlib.sha256).hexdigest()


class HTTPTransport(Transport):
    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None
        self._url = settings.xsiam_url
        self._api_key = settings.xsiam_api_key
        self._dataset = settings.xsiam_dataset
        self._batch: list[dict[str, Any]] = []
        self._batch_lock = asyncio.Lock()

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    def _build_headers(self, content_type: str = "application/json") -> dict[str, str]:
        nonce = str(uuid.uuid4()).replace("-", "")
        timestamp = str(int(time.time() * 1000))
        auth_id = "1"
        signature = hmac.new(
            self._api_key.encode(),
            f"{self._api_key}{nonce}{timestamp}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return {
            "Content-Type": content_type,
            "x-xdr-auth-id": auth_id,
            "x-xdr-nonce": nonce,
            "x-xdr-timestamp": timestamp,
            "x-xdr-hmac": signature,
            "x-xdr-dataset": self._dataset,
        }

    async def send(self, payload: str, source_meta: SourceMeta) -> SendResult:
        try:
            event = json.loads(payload) if isinstance(payload, str) else payload
        except json.JSONDecodeError:
            event = {"raw": payload}

        event["_source_id"] = source_meta.source_id
        event["_dataset"] = self._dataset

        body = json.dumps([event])
        encoded = body.encode()

        for attempt in range(MAX_RETRIES):
            try:
                client = self._get_client()
                headers = self._build_headers()
                resp = await client.post(self._url, content=encoded, headers=headers)
                resp.raise_for_status()
                return SendResult(success=True, bytes_sent=len(encoded))
            except httpx.HTTPStatusError as e:
                if e.response.status_code < 500 or attempt == MAX_RETRIES - 1:
                    return SendResult(success=False, error=str(e))
                await asyncio.sleep(RETRY_BASE_DELAY * (2**attempt))
            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    return SendResult(success=False, error=str(e))
                await asyncio.sleep(RETRY_BASE_DELAY * (2**attempt))

        return SendResult(success=False, error="Max retries exceeded")

    async def send_batch(self, events: list[dict], source_meta: SourceMeta) -> SendResult:
        body = json.dumps(events)
        encoded = body.encode()

        for attempt in range(MAX_RETRIES):
            try:
                client = self._get_client()
                headers = self._build_headers()
                resp = await client.post(self._url, content=encoded, headers=headers)
                resp.raise_for_status()
                return SendResult(success=True, bytes_sent=len(encoded))
            except httpx.HTTPStatusError as e:
                if e.response.status_code < 500 or attempt == MAX_RETRIES - 1:
                    logger.warning({"event": "http_send_error", "status": e.response.status_code, "source": source_meta.source_id})
                    return SendResult(success=False, error=str(e))
                await asyncio.sleep(RETRY_BASE_DELAY * (2**attempt))
            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    logger.error({"event": "http_send_exception", "error": str(e), "source": source_meta.source_id})
                    return SendResult(success=False, error=str(e))
                await asyncio.sleep(RETRY_BASE_DELAY * (2**attempt))

        return SendResult(success=False, error="Max retries exceeded")

    async def health_check(self) -> bool:
        try:
            client = self._get_client()
            resp = await client.get(self._url.rsplit("/", 2)[0] + "/healthcheck", timeout=5.0)
            return resp.status_code < 500
        except Exception:
            # Treat any connectivity issue as unhealthy when no URL is reachable
            # but don't crash the engine
            return False

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
