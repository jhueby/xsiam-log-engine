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

> Note the limit of this check: `syslog: true` only means a socket connected. Nothing in this repo receives and *parses* the traffic, so framing correctness (RFC 5424, octet counting) and the WEC mutual-TLS handshake can't be verified without a real BrokerVM. See the options below.

---

## Can the BrokerVM run as a container in this stack?

Short answer: **not as a native container.** This came up as a "deploy BVM" button idea; the trade-offs are captured here so the decision isn't re-litigated from scratch.

### Why not natively

The BrokerVM ships as OVA, QCOW2, VHD, VHD_Azure, or VMDK. Those are all **VM disk images** — a full OS including its own kernel. Docker containers share the host kernel and start a process; there is no `docker run` path for any of these formats.

Extracting the root filesystem (`qemu-nbd` / `libguestfs` → `docker import`) is technically possible but not advisable:

- The BrokerVM is an appliance built around systemd as PID 1, kernel modules, and device access — most of which doesn't survive the transplant.
- The result can't be activated, updated, or supported through normal Palo Alto channels.
- Repackaging a licensed Palo Alto appliance is very likely contrary to its EULA, independent of whether it works.

### Option A — QEMU/KVM inside a container

A compose service running QEMU (e.g. a `qemux/qemu`-style image) can boot a user-supplied QCOW2. This is legitimate — the image stays the operator's own download, nothing is repackaged or redistributed.

Constraints to weigh:

- Requires `/dev/kvm` and an effectively privileged container. Rules out Docker Desktop on macOS/Windows without nested-virt pain, and most CI.
- Resource cost is disproportionate to this stack: the engine is capped at **2 CPU / 512 MB**, while a BrokerVM wants roughly 8 vCPU / 16 GB RAM and hundreds of GB of disk depending on which applets are enabled. *(Verify against current Palo Alto documentation — sizing changes between releases.)*
- Activation and tenant pairing remain manual, so a one-click button would save a `qemu-system-x86_64` invocation, not the actual setup work.

If pursued, keep it an opt-in overlay (`docker-compose.bvm.yml`) referencing an operator-supplied image path — never bundle the appliance image in this repo.

### Option B — a local BrokerVM stand-in (protocol sink)

A small service implementing the *receiving* side of the three transports: syslog UDP/TCP/TLS on 514, a WEC/WS-Man HTTPS endpoint on 5986 with mutual TLS, and an HTTP collector endpoint — surfacing what actually arrived, decoded.

This closes the gap noted above the fold: RFC 5424 framing, TCP octet counting, TLS client-cert handshakes, and SOAP envelope structure all become verifiable offline, on any host, with no licensing questions.

What it deliberately does **not** do: prove a *real* BrokerVM accepts the traffic, or exercise the BVM→XSIAM leg. It is a protocol-conformance target, not an emulator, and should be labelled that way wherever it appears in the UI so a green light is never mistaken for real BVM validation.

### Current status

Neither option is implemented. Option B is the recommended starting point if local end-to-end verification becomes a priority; Option A only makes sense for someone with the hardware who needs true appliance behavior.
