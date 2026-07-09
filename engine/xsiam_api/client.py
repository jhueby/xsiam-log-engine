from __future__ import annotations

from typing import Any

import httpx

from config.settings import settings
from utils.logger import get_logger

logger = get_logger(__name__)

# Engine-managed correlation rules carry this name prefix. delete_rule()
# refuses anything without it, so user-authored rules are untouchable.
RULE_PREFIX = "[LogSim] "

# The wire paths and field names below are the only places that know the
# XSIAM public API schema. If a real tenant disagrees (field naming, request
# wrapper), fix it here — nothing outside this module parses raw responses.
CORRELATIONS_PATH = "/public_api/v1/correlations/"
INCIDENTS_PATH = "/public_api/v1/incidents/get_incidents/"

TIMEOUT = 15.0

_GATED_HINT = (
    "The XSIAM correlations API rejected the request. This endpoint requires a "
    "standard API key with the Instance Administrator role, and may be "
    "feature-flag-gated on some tenants (contact Palo Alto support to enable it)."
)


class XsiamApiError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


class XsiamApiNotConfigured(XsiamApiError):
    def __init__(self) -> None:
        super().__init__(0, "XSIAM Public API is not configured. Set the API URL, key ID, and key under Configuration.")


def _from_api(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize one rule object from the wire into engine-internal form."""
    return {
        "name": raw.get("name") or raw.get("rule_name") or "",
        "description": raw.get("description") or "",
        "xql_query": raw.get("xql_query") or raw.get("xql") or raw.get("query") or "",
        "severity": raw.get("severity") or "",
        "enabled": bool(raw.get("enabled", True)),
        "dataset": raw.get("dataset") or "",
    }


def _to_api(rule: dict[str, Any]) -> dict[str, Any]:
    """Serialize an engine-internal rule into wire form."""
    return {
        "name": rule["name"],
        "description": rule.get("description", ""),
        "xql_query": rule.get("xql_query", ""),
        "severity": rule.get("severity", "informational"),
        "enabled": rule.get("enabled", True),
        "dataset": rule.get("dataset", ""),
    }


def _extract_rule_list(reply: Any) -> list[dict[str, Any]]:
    """The list response wrapper is unverified; accept the plausible shapes."""
    if isinstance(reply, dict):
        for key in ("correlations", "rules", "objects", "data"):
            if isinstance(reply.get(key), list):
                reply = reply[key]
                break
        else:
            reply = []
    if not isinstance(reply, list):
        return []
    return [_from_api(r) for r in reply if isinstance(r, dict)]


class XsiamApiClient:
    """Thin client for the XSIAM public (management) API.

    Management calls fail fast and loudly: 15 s timeout, no retries — unlike
    the ingest transport, a failed rule push should surface immediately.
    """

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=TIMEOUT)
        return self._client

    @staticmethod
    def is_configured() -> bool:
        return bool(settings.xsiam_api_url and settings.xsiam_api_key_id and settings.xsiam_api_secret)

    @staticmethod
    def _base_url() -> str:
        return settings.xsiam_api_url.rstrip("/")

    # Headers are built per-request so GUI config changes apply without restart.
    @staticmethod
    def _headers() -> dict[str, str]:
        return {
            "Authorization": settings.xsiam_api_secret,
            "x-xdr-auth-id": settings.xsiam_api_key_id,
            "Content-Type": "application/json",
        }

    async def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        if not self.is_configured():
            raise XsiamApiNotConfigured()
        url = self._base_url() + path
        logger.info({"event": "xsiam_api_request", "method": method, "url": url})
        try:
            client = self._get_client()
            resp = await client.request(method, url, json=body, headers=self._headers())
        except Exception as e:
            logger.error({"event": "xsiam_api_connect_error", "url": url, "error": str(e)})
            raise XsiamApiError(0, f"Could not reach the XSIAM API at {url}: {e}") from e
        if resp.status_code >= 400:
            snippet = resp.text[:300]
            logger.error({"event": "xsiam_api_http_error", "url": url, "status": resp.status_code, "response": snippet})
            if resp.status_code in (401, 403):
                raise XsiamApiError(resp.status_code, f"{_GATED_HINT} Response: {snippet}")
            raise XsiamApiError(resp.status_code, f"XSIAM API returned HTTP {resp.status_code}: {snippet}")
        try:
            payload = resp.json()
        except ValueError:
            payload = {}
        return payload.get("reply", payload) if isinstance(payload, dict) else payload

    async def list_rules(self) -> list[dict[str, Any]]:
        reply = await self._request("GET", CORRELATIONS_PATH)
        return _extract_rule_list(reply)

    async def upsert_rule(self, rule: dict[str, Any]) -> dict[str, Any]:
        await self._request("POST", CORRELATIONS_PATH, {"request_data": [_to_api(rule)]})
        return rule

    async def delete_rule(self, name: str) -> None:
        if not name.startswith(RULE_PREFIX):
            raise ValueError(
                f"Refusing to delete correlation rule '{name}': it is not engine-managed "
                f"(missing the '{RULE_PREFIX}' prefix)."
            )
        await self._request("DELETE", CORRELATIONS_PATH, {"request_data": {"names": [name]}})

    async def probe_incidents(self) -> None:
        """Auth probe against a broadly-permissioned endpoint — distinguishes
        bad credentials from the correlations-specific role/feature gate."""
        await self._request("POST", INCIDENTS_PATH, {"request_data": {"search_from": 0, "search_to": 1}})

    async def check_reachable(self) -> None:
        """Network-level probe: any HTTP response counts as reachable."""
        if not self.is_configured():
            raise XsiamApiNotConfigured()
        url = self._base_url() + "/"
        try:
            client = self._get_client()
            await client.get(url)
        except Exception as e:
            raise XsiamApiError(0, f"Could not reach {url}: {e}") from e

    def reset(self) -> None:
        self._client = None

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()


xsiam_api_client = XsiamApiClient()
