from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from config.settings import settings
from transports.base import SendResult, SourceMeta, Transport
from utils.logger import get_logger

logger = get_logger(__name__)

SYSLOG_FACILITY_USER = 1
SYSLOG_SEVERITY_INFO = 6


def _rfc5424(msg: str, hostname: str = "engine", app_name: str = "log-engine",
             facility: int = SYSLOG_FACILITY_USER, severity: int = SYSLOG_SEVERITY_INFO) -> bytes:
    priority = facility * 8 + severity
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    header = f"<{priority}>1 {ts} {hostname} {app_name} - - -"
    return f"{header} {msg}\n".encode("utf-8")


def _rfc3164(msg: str, hostname: str = "engine", app_name: str = "log-engine",
             facility: int = SYSLOG_FACILITY_USER, severity: int = SYSLOG_SEVERITY_INFO) -> bytes:
    priority = facility * 8 + severity
    ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    return f"<{priority}>{ts} {hostname} {app_name}: {msg}\n".encode("utf-8")


class UDPSyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self.transport = transport

    def error_received(self, exc: Exception) -> None:
        logger.error({"event": "udp_error", "error": str(exc)})


class SyslogTransport(Transport):
    def __init__(self) -> None:
        self._host = settings.brokervm_host
        self._port = settings.brokervm_syslog_port
        self._proto = settings.brokervm_syslog_proto
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._tcp_writer: asyncio.StreamWriter | None = None
        self._connect_lock = asyncio.Lock()

    async def _ensure_udp(self) -> asyncio.DatagramTransport:
        if self._udp_transport is None or self._udp_transport.is_closing():
            loop = asyncio.get_event_loop()
            protocol = UDPSyslogProtocol()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: protocol,
                remote_addr=(self._host, self._port),
                family=socket.AF_INET,
            )
            self._udp_transport = transport
        return self._udp_transport

    async def _ensure_tcp(self) -> asyncio.StreamWriter:
        async with self._connect_lock:
            if self._tcp_writer is None or self._tcp_writer.is_closing():
                if self._proto == "tls":
                    ctx = ssl.create_default_context()
                    ca = settings.tls_ca_cert_path
                    cert = settings.tls_client_cert_path
                    key = settings.tls_client_key_path
                    if ca:
                        ctx.load_verify_locations(ca)
                    if cert and key:
                        ctx.load_cert_chain(cert, key)
                    _, writer = await asyncio.open_connection(self._host, self._port, ssl=ctx)
                else:
                    _, writer = await asyncio.open_connection(self._host, self._port)
                self._tcp_writer = writer
        return self._tcp_writer

    async def send(self, payload: str, source_meta: SourceMeta) -> SendResult:
        hostname = source_meta.source_id.replace("_", "-")
        framed = _rfc5424(payload, hostname=hostname, app_name=source_meta.source_id)

        try:
            if self._proto == "udp":
                transport = await self._ensure_udp()
                transport.sendto(framed)
                return SendResult(success=True, bytes_sent=len(framed))
            else:
                writer = await self._ensure_tcp()
                length_prefix = f"{len(framed)} ".encode()
                writer.write(length_prefix + framed)
                await writer.drain()
                return SendResult(success=True, bytes_sent=len(framed))
        except Exception as e:
            self._udp_transport = None
            self._tcp_writer = None
            logger.error({"event": "syslog_send_error", "error": str(e), "source": source_meta.source_id})
            return SendResult(success=False, error=str(e))

    async def health_check(self) -> bool:
        try:
            if self._proto == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                sock.connect((self._host, self._port))
                sock.close()
                return True
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self._host, self._port), timeout=3.0
                )
                writer.close()
                return True
        except Exception:
            return False

    async def close(self) -> None:
        if self._udp_transport:
            self._udp_transport.close()
        if self._tcp_writer:
            self._tcp_writer.close()
