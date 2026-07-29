# BrokerVM Setup Guide

## Prerequisites

- Palo Alto Cortex XDR BrokerVM deployed and reachable from the engine host
- Network connectivity on the ports listed below

## Required Ports

| Protocol | Default Port | `.env` Variable | Purpose |
|----------|-------------|----------------|---------|
| UDP/TCP/TLS | 514 | `BROKERVM_SYSLOG_PORT` | Syslog ingestion |
| HTTPS (mutual TLS) | 5986 | `BROKERVM_WEC_PORT` | WEC/WinRM ingestion |
| HTTPS | 443 | `XSIAM_URL` | Direct XSIAM HTTP ingest |

## Syslog Listener Configuration

On the BrokerVM, configure a syslog listener:

1. In Cortex XDR → Settings → Data Collection → Brokers
2. Select your BrokerVM → Add Syslog Collector
3. Configure port (default 514) and protocol (UDP/TCP/TLS)
4. Note the BrokerVM IP — set `BROKERVM_HOST` in `.env`

For TLS syslog:
```
TLS_CA_CERT_PATH=/app/certs/brokervm-ca.pem
TLS_CLIENT_CERT_PATH=/app/certs/client.crt
TLS_CLIENT_KEY_PATH=/app/certs/client.key
BROKERVM_SYSLOG_PROTO=tls
```

Mount certs in `docker-compose.yml` under `./certs:/app/certs:ro`.

## WEC / WEF Configuration

The BrokerVM's WEC endpoint accepts Windows Event Log XML over WS-Management (WinRM). WEC is **always mutual TLS** — there is no plain-HTTP mode:

1. Enable the WEC collector on BrokerVM port 5986 (HTTPS)
2. Set `WEC_SUBSCRIPTION_URL` to the subscription manager string copied from the BrokerVM (this also sets host + port — see the root [README](../README.md#wec-setup)), or set `BROKERVM_WEC_PORT` directly as a fallback
3. Upload the BrokerVM-issued `.pfx` client certificate under GUI **Configuration → WEC Client Certificate** — authentication is mutual TLS, so this is required, not optional
4. The engine sends SOAP envelopes with full EVTX-compatible XML over the resulting TLS connection

## XSIAM Direct HTTP Ingest

For HTTP sources (CrowdStrike, Okta, Azure AD, AWS CloudTrail):

1. In your XSIAM tenant → Settings → Data Ingestion → HTTP Log Collector
2. Create a new collector and copy the ingest URL and API key
3. Set in `.env`:
   ```
   XSIAM_URL=https://<tenant>.xdr.us.paloaltonetworks.com/logs/v1/event
   XSIAM_API_KEY=<your-api-key>
   ```

The engine sends the API key verbatim as the `Authorization` header on every request — no request signing:
- Header `Authorization`: `<XSIAM_API_KEY>`
- Header `Content-Type`: set per source's configured HTTP log type (JSON/raw/CEF/LEEF)

(This is separate from the *Public API* used for correlation-rule management, which authenticates with `Authorization: <XSIAM_API_SECRET>` + `x-xdr-auth-id: <XSIAM_API_KEY_ID>` — see `XSIAM_API_URL`/`XSIAM_API_KEY_ID`/`XSIAM_API_SECRET` in the root README's Configuration table.)

## Testing Connectivity

```bash
# Test syslog UDP
echo '<134>Jun 11 12:00:00 test engine: connectivity check' | nc -u <BROKERVM_HOST> 514

# Test WEC endpoint (expect a TLS handshake, not a plain HTTP response — WEC is mutual TLS only)
curl -vk https://<BROKERVM_HOST>:5986/wsman

# Test XSIAM HTTP
curl -X POST <XSIAM_URL> \
  -H "Content-Type: application/json" \
  -H "Authorization: <XSIAM_API_KEY>" \
  -d '{"test": "event"}'
```

## Health Check

```bash
curl http://localhost:8080/api/health
```

Returns:
```json
{
  "status": "ok",
  "transports": {
    "http": true,
    "syslog": false,
    "wec": false
  }
}
```

`false` means the transport target is unreachable. The engine continues generating logs regardless — errors are counted in `GET /api/stats`.
