from __future__ import annotations

import asyncio
import json
import ssl
import uuid
from datetime import datetime, timezone
from xml.sax.saxutils import escape

import httpx

from config.settings import settings
from transports.base import SendResult, SourceMeta, Transport
from utils.logger import get_logger

logger = get_logger(__name__)

# WEF push-subscription envelope. The engine simulates Windows hosts pushing
# events to the BrokerVM WEC listener using the Windows Event Forwarding (WEF)
# protocol. In production, BrokerVM also supports pull-based collection via
# WinRM, but the push model is used here for simulation.
_WSMAN_ENVELOPE = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
            xmlns:wse="http://schemas.microsoft.com/wbem/wsman/1/wsman">
  <s:Header>
    <a:To>http://{host}:{port}/wsman</a:To>
    <a:ReplyTo>
      <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <w:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</w:ResourceURI>
    <a:Action>http://schemas.microsoft.com/wbem/wsman/1/wsman/Event</a:Action>
    <a:MessageID>uuid:{message_id}</a:MessageID>
  </s:Header>
  <s:Body>
    <wse:Collect>
      <wse:Events>
        <wse:Event Action="http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog">
          {event_xml}
        </wse:Event>
      </wse:Events>
    </wse:Collect>
  </s:Body>
</s:Envelope>"""


def _build_event_xml(event: dict) -> str:
    ts = escape(str(event.get("TimeCreated", datetime.now(timezone.utc).isoformat())))
    event_id = int(event.get("EventID", 0))
    channel = escape(str(event.get("Channel", "Security")))
    computer = escape(str(event.get("Computer", "WIN-UNKNOWN")))
    provider = escape(str(event.get("Provider", "Microsoft-Windows-Security-Auditing")))
    provider_guid = escape(str(event.get("ProviderGuid", "54849625-5478-4994-A5BA-3E3B0328C30D")))
    level = int(event.get("Level", 4))
    task = int(event.get("Task", 0))
    keywords = escape(str(event.get("Keywords", "0x8020000000000000")))
    record_id = int(event.get("EventRecordID", 1))
    process_id = int(event.get("ProcessID", 4))
    thread_id = int(event.get("ThreadID", 8))
    security_user_id = escape(str(event.get("SecurityUserID", "S-1-5-18")))

    data_items = ""
    for k, v in event.get("EventData", {}).items():
        data_items += f'      <Data Name="{escape(str(k))}">{escape(str(v))}</Data>\n'

    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="{provider}" Guid="{{{provider_guid}}}"/>
    <EventID>{event_id}</EventID>
    <Version>0</Version>
    <Level>{level}</Level>
    <Task>{task}</Task>
    <Opcode>0</Opcode>
    <Keywords>{keywords}</Keywords>
    <TimeCreated SystemTime="{ts}"/>
    <EventRecordID>{record_id}</EventRecordID>
    <Correlation/>
    <Execution ProcessID="{process_id}" ThreadID="{thread_id}"/>
    <Channel>{channel}</Channel>
    <Computer>{computer}</Computer>
    <Security UserID="{security_user_id}"/>
  </System>
  <EventData>
{data_items}  </EventData>
</Event>"""


class WECTransport(Transport):
    def __init__(self) -> None:
        self._host = settings.brokervm_host
        self._port = settings.brokervm_wec_port
        self._use_tls = settings.brokervm_wec_use_tls
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            scheme = "https" if self._use_tls else "http"
            verify: bool | str = False
            if self._use_tls and settings.tls_ca_cert_path:
                verify = settings.tls_ca_cert_path
            self._client = httpx.AsyncClient(
                base_url=f"{scheme}://{self._host}:{self._port}",
                verify=verify,
                timeout=15.0,
            )
        return self._client

    async def send(self, payload: str, source_meta: SourceMeta) -> SendResult:
        try:
            event = json.loads(payload) if isinstance(payload, str) else payload
        except Exception:
            event = {}

        event_xml = _build_event_xml(event)
        message_id = str(uuid.uuid4())
        envelope = _WSMAN_ENVELOPE.format(
            host=self._host,
            port=self._port,
            message_id=message_id,
            event_xml=event_xml,
        )
        encoded = envelope.encode("utf-8")

        try:
            client = self._get_client()
            resp = await client.post(
                "/wsman",
                content=encoded,
                headers={
                    "Content-Type": "application/soap+xml;charset=UTF-8",
                    "User-Agent": "WEC/5.0 WinRM",
                },
            )
            if resp.status_code in (200, 201, 202):
                return SendResult(success=True, bytes_sent=len(encoded))
            return SendResult(success=False, error=f"HTTP {resp.status_code}")
        except Exception as e:
            self._client = None
            logger.error({"event": "wec_send_error", "error": str(e), "source": source_meta.source_id})
            return SendResult(success=False, error=str(e))

    async def health_check(self) -> bool:
        try:
            client = self._get_client()
            resp = await client.get("/wsman", timeout=3.0)
            return resp.status_code < 500
        except Exception:
            return False

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
