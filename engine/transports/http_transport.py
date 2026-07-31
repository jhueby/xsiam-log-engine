from __future__ import annotations

import asyncio
import gzip
import json
from datetime import datetime, timezone
from typing import Any

import httpx

from config.settings import settings
from transports.base import SendResult, SourceMeta, Transport
from utils.logger import get_logger
from utils.vendor_map import canonical_dataset, vendor_product

logger = get_logger(__name__)

MAX_RETRIES = 3
RETRY_BASE_DELAY = 1.0

_LOG_TYPE_CONTENT_TYPE = {
    "json": "application/json",
    "raw": "text/plain",
    "cef": "text/plain",
    "leef": "text/plain",
}


# Cribl's Cortex XSIAM Destination enforces these; exceeding them is a
# delivery failure at the destination rather than something XSIAM rejects,
# so the emulation surfaces it the same way instead of sending anyway.
CRIBL_MAX_EVENT_BYTES = 5 * 1024 * 1024        # 5 MB per individual event
CRIBL_MAX_BATCH_BYTES = int(9.5 * 1024 * 1024)  # 9.5 MB per batch


def _cribl_identifiers(meta: SourceMeta) -> dict[str, str]:
    """The identifier set Cribl derives from its internal __-prefixed fields
    (__sourceIdentifier, __inputId, __vendor, __product).

    Those fields never appear in the delivered body — Cribl maps them to HTTP
    headers, which is how XSIAM picks the parser, dataset and XDM mapping. An
    earlier version of this emulation invented body fields (cribl_pipe,
    cribl_host, cribl_breaker) that no real Cribl worker sends; they made the
    payload look Cribl-ish while producing traffic XSIAM would route
    differently from the real thing.
    """
    source_id = meta.source_id
    vendor, product = vendor_product(source_id)
    return {
        "Source-Identifier": meta.cribl_source_identifier or source_id,
        # Cribl generates this from the Source that received the event; it is
        # set automatically and must not be dropped.
        "Integration-Identifier": f"cribl:in_{source_id}",
        "vendor": meta.cribl_vendor or vendor or source_id,
        "product": meta.cribl_product or product or source_id,
    }


def cribl_routing_note(source_id: str) -> str:
    """Where a Cribl-emulated source's events actually land, for the operator.

    vendor/product decide the destination dataset, not this engine's
    xsiam_dataset (which only drives correlation-rule generation and the
    Ingestion view). That matters because several of these are real,
    populated datasets on a production tenant: turning emulation on for a
    Windows source delivers simulated events into the same
    microsoft_windows_raw that holds genuine Windows telemetry.
    """
    return canonical_dataset(source_id)


def _cribl_envelope(event: Any, meta: SourceMeta) -> dict[str, Any]:
    """Wrap an event the way the XSIAM Destination delivers it.

    The destination sends `{"data": <event>, "collector_ms": <epoch ms>}`,
    with `data` as a native JSON object when the event is structured. Nothing
    Cribl-specific is added to the event itself.
    """
    return {"data": event, "collector_ms": int(datetime.now(timezone.utc).timestamp() * 1000)}


def _augment_json_event(event: dict, meta: SourceMeta) -> dict:
    tagged = {"simulated_log_source": meta.source_id, **event}
    return _cribl_envelope(tagged, meta) if meta.cribl_emulation else tagged


def _augment_raw_line(line: str, meta: SourceMeta) -> str:
    return f'simulated_log_source="{meta.source_id}" {line}'


def _build_body(payload: str, meta: SourceMeta) -> bytes:
    stripped = payload.rstrip("\n")

    if meta.http_log_type == "json":
        try:
            event = json.loads(stripped)
        except json.JSONDecodeError:
            event = {"raw": stripped}
        if isinstance(event, dict):
            event = _augment_json_event(event, meta)
        return (json.dumps(event) + "\n").encode("utf-8")

    # raw / cef / leef
    # If the payload is already a JSON object, inject fields rather than
    # prefixing them so the JSON structure stays valid (XSIAM auto-detects
    # JSON and rejects a bare key=value prefix in front of a JSON body).
    try:
        event = json.loads(stripped)
        if isinstance(event, dict):
            event = _augment_json_event(event, meta)
            return (json.dumps(event) + "\n").encode("utf-8")
    except (json.JSONDecodeError, ValueError):
        pass

    # Plain-text log (CEF, LEEF, syslog-style).
    tagged = _augment_raw_line(stripped, meta)
    if meta.cribl_emulation:
        # Cribl still wraps non-JSON events; `data` carries the raw string
        # and the `format` header tells XSIAM how to read it.
        return (json.dumps(_cribl_envelope(tagged, meta)) + "\n").encode("utf-8")
    return (tagged + "\n").encode("utf-8")


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
        if meta.cribl_emulation:
            # The destination always sends JSON regardless of the original
            # event format, because the {"data", "collector_ms"} envelope is
            # JSON even when `data` holds a raw string.
            headers["Content-Type"] = "application/json"
            headers.update(_cribl_identifiers(meta))
            # Tells XSIAM how to read the contents of `data`.
            headers["format"] = "json" if meta.http_log_type == "json" else "raw"
            # NOTE: Cribl labels its credential a "Bearer Token", but the
            # XSIAM HTTP collector this engine targets authenticates with the
            # key sent verbatim (confirmed against a live tenant). The header
            # is left as-is rather than guessing at a "Bearer " prefix that
            # would silently break ingestion if wrong.
        if meta.http_compression == "gzip":
            headers["Content-Encoding"] = "gzip"
        return headers

    async def send(self, payload: str, source_meta: SourceMeta) -> SendResult:
        body = _build_body(payload, source_meta)

        # Cribl's destination rejects an oversized event before it reaches
        # XSIAM. Measured pre-compression, since that is the size the
        # destination checks. Emulating the limit means a source that would
        # be dropped in a real pipeline is dropped here too, rather than
        # appearing to deliver successfully.
        if source_meta.cribl_emulation and len(body) > CRIBL_MAX_EVENT_BYTES:
            error = (
                f"Event is {len(body)} bytes, over Cribl's {CRIBL_MAX_EVENT_BYTES}-byte "
                f"per-event limit for the XSIAM destination"
            )
            logger.error({"event": "cribl_event_too_large", "source": source_meta.source_id,
                          "bytes": len(body), "limit": CRIBL_MAX_EVENT_BYTES})
            return SendResult(success=False, error=error)

        if source_meta.http_compression == "gzip":
            encoded = gzip.compress(body)
        else:
            encoded = body

        headers = self._build_headers(source_meta)

        src = source_meta.source_id
        url = settings.xsiam_url
        logger.info({
            "event": "xsiam_request",
            "source": src,
            "log_type": source_meta.http_log_type,
            "compression": source_meta.http_compression,
            "bytes": len(encoded),
            "preview": body[:300].decode("utf-8", errors="replace"),
        })
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
        if source_meta.http_log_type == "json":
            augmented = [
                _augment_json_event(e, source_meta) if isinstance(e, dict)
                else _augment_json_event({"raw": str(e)}, source_meta)
                for e in events
            ]
            body = json.dumps(augmented).encode("utf-8")
        else:
            body = "\n".join(
                _augment_raw_line(e.get("raw", json.dumps(e)) if isinstance(e, dict) else str(e), source_meta)
                for e in events
            ).encode("utf-8") + b"\n"

        # Same rationale as the per-event guard in send(): the destination
        # enforces a batch ceiling, so an over-limit batch must fail here
        # rather than report success for events that would never arrive.
        if source_meta.cribl_emulation and len(body) > CRIBL_MAX_BATCH_BYTES:
            error = (
                f"Batch is {len(body)} bytes, over Cribl's {CRIBL_MAX_BATCH_BYTES}-byte "
                f"batch limit for the XSIAM destination"
            )
            logger.error({"event": "cribl_batch_too_large", "source": source_meta.source_id,
                          "bytes": len(body), "events": len(events), "limit": CRIBL_MAX_BATCH_BYTES})
            return SendResult(success=False, error=error)

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
