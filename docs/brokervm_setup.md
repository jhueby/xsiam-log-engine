# BrokerVM Setup Guide

## Prerequisites

- Palo Alto Cortex XDR BrokerVM deployed and reachable from the engine host
- Network connectivity on the ports listed below

## Required Ports

| Protocol | Default Port | `.env` Variable | Purpose |
|----------|-------------|----------------|---------|
| UDP/TCP/TLS | 514 | `BROKERVM_SYSLOG_PORT` | Syslog ingestion |
| HTTP/HTTPS | 5985/5986 | `BROKERVM_WEC_PORT` | WEC/WinRM ingestion |
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

The BrokerVM's WEC endpoint accepts Windows Event Log XML over WS-Management (WinRM):

1. Enable the WEC collector on BrokerVM port 5985 (HTTP) or 5986 (HTTPS)
2. Set `BROKERVM_WEC_PORT` and `BROKERVM_WEC_USE_TLS` accordingly
3. The engine sends SOAP envelopes with full EVTX-compatible XML

## XSIAM Direct HTTP Ingest

For HTTP sources (CrowdStrike, Okta, Azure AD, AWS CloudTrail):

1. In your XSIAM tenant → Settings → Data Ingestion → HTTP Log Collector
2. Create a new collector and copy the ingest URL and API key
3. Set in `.env`:
   ```
   XSIAM_URL=https://<tenant>.xdr.us.paloaltonetworks.com/logs/v1/event
   XSIAM_API_KEY=<your-api-key>
   ```

The engine signs each request with HMAC-SHA256 per the XSIAM spec:
- Header `x-xdr-auth-id`: auth ID (currently "1")
- Header `x-xdr-nonce`: random UUID without dashes
- Header `x-xdr-timestamp`: Unix ms timestamp
- Header `x-xdr-hmac`: `HMAC-SHA256(api_key, api_key + nonce + timestamp)`

## Testing Connectivity

```bash
# Test syslog UDP
echo '<134>Jun 11 12:00:00 test engine: connectivity check' | nc -u <BROKERVM_HOST> 514

# Test WEC endpoint
curl -v http://<BROKERVM_HOST>:5985/wsman

# Test XSIAM HTTP
curl -X POST <XSIAM_URL> \
  -H "Content-Type: application/json" \
  -H "x-xdr-auth-id: 1" \
  -H "x-xdr-nonce: abc123" \
  -d '[{"test": "event"}]'
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
