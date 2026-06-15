# XSIAM Log Engine

A production-quality, Dockerized enterprise log simulation engine. Generates realistic log traffic from 22+ sources and forwards it to a Palo Alto XSIAM tenant or Cortex XDR BrokerVM via HTTP, Syslog (UDP/TCP/TLS), and WEC.

## Quickstart

```bash
git clone <repo>
cd xsiam-log-engine
cp .env.example .env
# Edit .env with your XSIAM URL, API key, and BrokerVM host
docker compose up --build
```

- GUI: http://localhost:3000
- Engine API: http://localhost:8080
- API docs: http://localhost:8080/docs

## Architecture

```mermaid
graph TB
    GUI["React GUI :3000"] -->|nginx /api/ proxy| API["FastAPI :8080"]
    API --> Engine["Engine Orchestrator"]
    Engine --> Sources["22+ Log Sources\n(async coroutines)"]
    Sources --> HTTP["HTTP → XSIAM Tenant"]
    Sources --> Syslog["Syslog → BrokerVM :514"]
    Sources --> WEC["WEC/HTTPS → BrokerVM :5986"]
    Engine --> SSE["SSE Streams\n/stats/stream\n/logs/stream"]
    API --> SSE
```

## Log Sources

| Source | Transport | Tags |
|--------|-----------|------|
| Windows Security | WEC | windows, auth |
| Windows System | WEC | windows, system |
| Windows Application | WEC | windows, app |
| Microsoft AD | WEC | windows, identity |
| Microsoft DNS | WEC | windows, dns |
| Microsoft DHCP | WEC | windows, dhcp |
| Microsoft Defender ATP | WEC | windows, edr |
| Cisco ASA | Syslog | network, firewall |
| Cisco Meraki | Syslog | network, firewall |
| Palo Alto NGFW | Syslog | network, firewall |
| Fortinet FortiGate | Syslog | network, firewall |
| Linux Syslog | Syslog | linux, system |
| Linux Auth | Syslog | linux, auth |
| Linux Auditd | Syslog | linux, audit |
| Blue Coat Proxy | Syslog | proxy, web |
| Zscaler ZIA | Syslog | proxy, cloud |
| CrowdStrike Falcon | HTTP | edr, endpoint |
| Okta | HTTP | identity, cloud |
| Azure AD / Entra ID | HTTP | identity, cloud |
| AWS CloudTrail | HTTP | cloud, aws |
| NetFlow v5/v9 | Syslog | network, flow |
| Proofpoint TAP | HTTP | email, cloud |

## Environment Variables

See `.env.example` for all variables. Key ones:

| Variable | Description |
|----------|-------------|
| `XSIAM_URL` | XSIAM HTTP ingest endpoint (`https://api-<tenant>/logs/v1/event`) |
| `XSIAM_API_KEY` | XSIAM API key |
| `XSIAM_DATASET` | Target dataset name (default `xsiam_log_engine`) |
| `BROKERVM_HOST` | BrokerVM IP or hostname |
| `BROKERVM_SYSLOG_PORT` | Syslog port (default 514) |
| `BROKERVM_SYSLOG_PROTO` | `udp` / `tcp` / `tls` |
| `BROKERVM_WEC_PORT` | WEC fallback port when no subscription URL is set (default 5986) |
| `WEC_SUBSCRIPTION_URL` | Full WEF subscription manager URL (sets WEC host + port) |
| `ENGINE_DEFAULT_EPS` | Global default events/sec |
| `ENGINE_API_TOKEN` | Optional bearer token for all `/api/*` requests |

### WEC Subscription Manager URL

Set `WEC_SUBSCRIPTION_URL` to the Windows Event Forwarding subscription string copied from your BrokerVM:

```
WEC_SUBSCRIPTION_URL=Server=HTTPS://bvm.lab:5986/wsman/SubscriptionManager/WEC,Refresh=600,IssuerCA=37210BA1582B95CB0CB558C572B503C349692604
```

The engine parses the `Server=` component to determine the WEC host and port. The `IssuerCA` thumbprint is stored for reference and Group Policy configuration. Authentication is via TLS client certificate — upload your BrokerVM-issued `.pfx` file through the GUI **Configuration → WEC Client Certificate**.

## XSIAM Setup — HTTP Ingest Parsing Rules

All HTTP sources embed a `simulated_log_source` field in every event:

- **JSON** logs: `{"simulated_log_source": "crowdstrike_falcon", ...rest of event}`
- **Raw / CEF / LEEF** logs: `simulated_log_source="crowdstrike_falcon" <rest of log line>`

Use this field to route each source to its own dataset in XSIAM. The **Sources → Parsing Rules** tab in the GUI generates ready-to-paste rules for every active source:

```
[INGEST:vendor="log", product="sim", target_dataset="log_sim_raw", no_hit=drop]filter simulated_log_source = "crowdstrike_falcon";

[INGEST:vendor="log", product="sim", target_dataset="log_sim_raw", no_hit=drop]filter simulated_log_source = "okta";
```

Add these under **Settings → XDR Data Management → Parsers → New Parser** in your XSIAM tenant.

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/sources` | List all sources + status |
| POST | `/api/sources/{id}/start` | Start a source |
| POST | `/api/sources/{id}/stop` | Stop a source |
| PATCH | `/api/sources/{id}/config` | Update EPS / transport / HTTP settings |
| GET | `/api/config` | Get transport config |
| PUT | `/api/config` | Update config (live reload) |
| POST | `/api/certs/pfx` | Upload WEC client certificate (.pfx / PKCS#12) |
| GET | `/api/stats` | Aggregate statistics |
| GET | `/api/stats/stream` | SSE live stats (1s) |
| GET | `/api/logs/stream` | SSE live log tail |
| POST | `/api/control/start-all` | Start all sources |
| POST | `/api/control/stop-all` | Stop all sources |
| POST | `/api/control/reload` | Reload config from disk |
| GET | `/api/health` | Transport health checks |

## Development

```bash
# Run tests
cd xsiam-log-engine
pip install -r engine/requirements.txt
pytest --cov=engine --cov-report=term-missing

# Run engine locally (no Docker)
cd engine
uvicorn api.app:app --reload --port 8080

# Run GUI locally
cd gui
npm install && npm run dev
```

## Extending

See [docs/adding_a_source.md](docs/adding_a_source.md) for the single-file plugin guide.

## BrokerVM Setup

See [docs/brokervm_setup.md](docs/brokervm_setup.md) for port requirements and configuration.
