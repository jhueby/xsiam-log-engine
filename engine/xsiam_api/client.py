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
#
# The Cortex public API is POST/JSON-RPC-style throughout, not REST-ish —
# every operation (including reads and deletes) is a POST to a verb-suffixed
# path with a {"request_data": ...} body. All three paths below are confirmed
# against a real tenant. The original REST-ish guess
# (GET/POST/DELETE on a bare /public_api/v1/correlations/) doesn't exist on
# the tenant's gateway at all -- it 500s exactly like any other unroutable
# path there (confirmed by probing a deliberately bogus endpoint and getting
# the identical generic error), rather than the 401/403 a feature-gated-but-
# present endpoint would return. Only /get, /insert and /delete exist;
# /create, /update, /set and /remove do not.
CORRELATIONS_GET_PATH = "/public_api/v1/correlations/get"
CORRELATIONS_INSERT_PATH = "/public_api/v1/correlations/insert"
CORRELATIONS_DELETE_PATH = "/public_api/v1/correlations/delete"
INCIDENTS_PATH = "/public_api/v1/incidents/get_incidents/"
DATASETS_PATH = "/public_api/v1/xql/get_datasets"

# Internal severity word -> Cortex severity enum. The API rejects the plain
# words this engine used to send ("informational"); confirmed valid enum
# values come back from /get as SEV_0N0_* strings.
_SEVERITY_TO_API = {
    "informational": "SEV_010_INFO",
    "low": "SEV_020_LOW",
    "medium": "SEV_030_MEDIUM",
    "high": "SEV_040_HIGH",
    "critical": "SEV_050_CRITICAL",
}

# /insert rejects a partial object -- it requires the full field set below
# (the tenant enumerates them in its validation error). Values here mirror a
# real scheduled rule on the tenant.
#
# mapping_strategy is deliberately "CUSTOM", not "AUTO": the API advertises
# both as valid, but "AUTO" is rejected in practice ("Correlation mapping AUTO
# is invalid") unless additional mapping config is supplied.
#
# The wire "dataset" field is the *alerts* target dataset, not the source
# dataset being queried -- the source dataset lives inside xql_query. Every
# real rule on the tenant uses "alerts", so engine-pushed rules do too.
_ALERTS_DATASET = "alerts"

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
    """Normalize one rule object from the wire into engine-internal form.

    Confirmed against a real tenant's /correlations/get response: the
    enabled flag is actually named is_enabled (this module originally
    guessed "enabled", which silently always read as True/missing on real
    data -- every rule looked enabled regardless of its real state). severity
    comes back as a Cortex enum (e.g. "SEV_020_LOW") and is surfaced verbatim
    rather than mapped back to a plain word, so the GUI shows what the tenant
    actually holds; _SEVERITY_TO_API handles the outbound direction.
    """
    return {
        "name": raw.get("name") or raw.get("rule_name") or "",
        "description": raw.get("description") or "",
        "xql_query": raw.get("xql_query") or raw.get("xql") or raw.get("query") or "",
        "severity": raw.get("severity") or "",
        "enabled": bool(raw.get("is_enabled", raw.get("enabled", True))),
        "dataset": raw.get("dataset") or "",
    }


def _to_api(rule: dict[str, Any]) -> dict[str, Any]:
    """Serialize an engine-internal rule into wire form.

    /insert requires the complete field set (it rejects a partial object
    outright), so the scheduling/alert-shaping fields the engine has no
    opinion about are filled with the same defaults a real tenant rule uses.
    """
    xql = rule.get("xql_query", "")
    name = rule["name"]
    severity = _SEVERITY_TO_API.get(str(rule.get("severity", "")).lower(), "SEV_010_INFO")
    return {
        "name": name,
        "description": rule.get("description", ""),
        "xql_query": xql,
        "severity": severity,
        "is_enabled": bool(rule.get("enabled", True)),
        "dataset": _ALERTS_DATASET,
        # Alert shaping: mirror the rule's own identity, nothing fancier.
        "alert_name": name,
        "alert_category": "OTHER",
        "alert_type": None,
        "alert_description": rule.get("description", ""),
        "alert_domain": "DOMAIN_SECURITY",
        "alert_fields": {},
        "user_defined_severity": None,
        "user_defined_category": None,
        "mitre_defs": {},
        # Scheduling: every 30 minutes over a 1-hour window, matching the
        # tenant's own existing rules. UTC so behavior doesn't depend on the
        # tenant's locale.
        "execution_mode": "SCHEDULED",
        "search_window": "1 hours",
        "simple_schedule": "30 minutes",
        "crontab": "*/30 * * * *",
        "timezone": "UTC",
        "suppression_enabled": False,
        "suppression_duration": None,
        "suppression_fields": None,
        "investigation_query_link": xql,
        "drilldown_query_timeframe": "ALERT",
        "mapping_strategy": "CUSTOM",
        "action": "ALERTS",
        "lookup_mapping": [],
    }


def _dataset_from_api(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize one dataset row from /xql/get_datasets.

    The tenant returns display-cased, space-separated keys ("Dataset Name",
    "Total Events") rather than the snake_case the rest of this API uses.

    Note "Last Updated" is day-granular (midnight UTC), so it cannot answer
    "did the events I just sent land" -- total_events is the signal that
    actually moves. Callers shouldn't present last_updated as a live
    ingestion indicator.
    """
    return {
        "name": raw.get("Dataset Name") or "",
        "type": raw.get("Type") or "",
        "total_events": raw.get("Total Events") or 0,
        "total_size_bytes": raw.get("Total Size Stored") or 0,
        "last_updated_ms": raw.get("Last Updated"),
    }


def _raise_for_item_errors(reply: Any) -> None:
    """/insert reports per-item failures in an "errors" list. It returns HTTP
    400 when every item fails (caught upstream by the status check), but a
    partial failure comes back 200 -- so the body has to be inspected too or
    a rule that was never created reports as pushed."""
    if not isinstance(reply, dict):
        return
    errors = reply.get("errors")
    if isinstance(errors, list) and errors:
        details = "; ".join(
            str(e.get("status", e)) if isinstance(e, dict) else str(e) for e in errors
        )
        raise XsiamApiError(400, f"XSIAM rejected the correlation rule: {details}")


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
    def _headers(has_body: bool) -> dict[str, str]:
        headers = {
            "Authorization": settings.xsiam_api_secret,
            "x-xdr-auth-id": settings.xsiam_api_key_id,
        }
        if has_body:
            headers["Content-Type"] = "application/json"
        return headers

    async def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        if not self.is_configured():
            raise XsiamApiNotConfigured()
        url = self._base_url() + path
        logger.info({"event": "xsiam_api_request", "method": method, "url": url})
        try:
            client = self._get_client()
            # Some tenant-side deployments eagerly parse the request body as
            # JSON whenever Content-Type: application/json is present -- a
            # bodyless GET (list_rules) that still carries that header trips
            # a bug on their end (an empty-body JSON parse crashing their
            # WSGI app), surfacing as an opaque 500 with no useful detail.
            # Only send the header when there's an actual body to describe.
            resp = await client.request(method, url, json=body, headers=self._headers(body is not None))
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
        # Paginated rather than a single unbounded request -- the tenant
        # enforces a hard max window size (confirmed live -- err_extra:
        # "Search size must fulfill the requirement: 0 < search_size <=
        # 100"), so a single request can't reliably fetch everything past
        # 100 rules; this loops until a short page signals the end.
        page_size = 100
        max_pages = 50  # safety valve against an unexpected non-terminating loop
        all_rules: list[dict[str, Any]] = []
        search_from = 0
        for _ in range(max_pages):
            reply = await self._request(
                "POST", CORRELATIONS_GET_PATH,
                {"request_data": {"search_from": search_from, "search_to": search_from + page_size}},
            )
            page = _extract_rule_list(reply)
            all_rules.extend(page)
            if len(page) < page_size:
                break
            search_from += page_size
        return all_rules

    async def upsert_rule(self, rule: dict[str, Any]) -> dict[str, Any]:
        """Create (or replace) one engine-managed rule.

        There is no update-by-name endpoint: /insert always creates, and it
        happily accepts a name that already exists -- pushing twice produced
        two rules with identical names on a real tenant. So "upsert" is
        delete-then-insert, which keeps a re-push idempotent instead of
        silently accumulating duplicates.

        The pre-delete is unconditional (a no-op when nothing matches) and
        scoped to this rule's own [LogSim] name via delete_rule()'s prefix
        guard, so it can never touch a user-authored rule. Caveat: if the
        insert then fails, the previous version is already gone -- acceptable
        because engine-managed rules are regenerable from the source
        definition, and the alternative (insert-then-dedupe) leaves duplicate
        rules live on the tenant in the failure case.
        """
        await self.delete_rule(rule["name"], require_managed=True)
        reply = await self._request("POST", CORRELATIONS_INSERT_PATH, {"request_data": [_to_api(rule)]})
        _raise_for_item_errors(reply)
        return rule

    async def delete_rule(self, name: str, require_managed: bool = True) -> None:
        if require_managed and not name.startswith(RULE_PREFIX):
            raise ValueError(
                f"Refusing to delete correlation rule '{name}': it is not engine-managed "
                f"(missing the '{RULE_PREFIX}' prefix)."
            )
        # Filter-based, scoped to this exact name. "At least one filter is
        # required for the delete method" -- an unfiltered delete is rejected
        # by the API, which is a useful backstop against a mass deletion.
        await self._request(
            "POST", CORRELATIONS_DELETE_PATH,
            {"request_data": {"filters": [{"field": "name", "operator": "eq", "value": name}]}},
        )

    async def list_datasets(self) -> list[dict[str, Any]]:
        """Every dataset on the tenant. Unlike correlations/get this returns
        the full set in one call (no search window), and the reply is a bare
        list rather than an {objects: [...]} wrapper."""
        reply = await self._request("POST", DATASETS_PATH, {"request_data": {}})
        if not isinstance(reply, list):
            return []
        return [_dataset_from_api(row) for row in reply if isinstance(row, dict)]

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
