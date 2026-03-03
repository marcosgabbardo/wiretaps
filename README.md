# 🔌 wiretaps

**Agent observability platform. See everything your AI agents do.**

A transparent proxy + interceptor that captures every LLM call, shell command, and HTTP request from your AI agents. Auto-detects PII, credentials, and crypto wallet addresses.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

---

## Architecture

```
┌─────────────┐     ┌──────────────────────────────────────┐     ┌─────────────┐
│  AI Agent   │────▶│             wiretaps                 │────▶│   LLM API   │
│ (any agent) │     │                                      │     │ (OpenAI,..) │
└─────────────┘     │  ┌────────┐  ┌─────────┐  ┌──────┐  │     └─────────────┘
                    │  │ Proxy  │  │ Storage │  │  API │  │
                    │  │ :8080  │  │ SQLite  │  │ :8899│  │
                    │  └────────┘  └─────────┘  └──┬───┘  │
                    │  ┌─────────────────────┐     │      │
                    │  │   sitecustomize     │     │      │
                    │  │   (interceptor)     │─────┘      │
                    │  └─────────────────────┘            │
                    └──────────────────────────────────────┘
                                                   │
                                                   ▼
                                          ┌─────────────────┐
                                          │  Web Dashboard   │
                                          │  Next.js :3000   │
                                          │                  │
                                          │  Sessions list   │
                                          │  Event timeline  │
                                          │  Stats & charts  │
                                          └─────────────────┘
```

### How it works

1. **MitM Proxy** (`localhost:8080`) — sits between your agent and the LLM API, logging every request/response
2. **sitecustomize interceptor** — automatically hooks into Python subprocess calls and HTTP clients
3. **REST API** (`localhost:8899`) — serves captured data (agents, sessions, events, stats)
4. **Web Dashboard** (`localhost:3000`) — Next.js frontend to explore sessions, timelines, and stats

### Web Dashboard

```
┌──────────┬──────────────────────────────────────────────────┐
│          │  Sessions                                        │
│ 📡 Sess  │                                                  │
│ 📊 Stats │  ┌────────────────────────────────────────────┐  │
│          │  │ claude-agent         2m 30s      PII       │  │
│          │  │ 🤖 12 LLM  💻 5 shell  🌐 3 HTTP          │  │
│          │  ├────────────────────────────────────────────┤  │
│          │  │ gpt-worker           45s                   │  │
│          │  │ 🤖 8 LLM   💻 2 shell                     │  │
│          │  └────────────────────────────────────────────┘  │
│          │                                                  │
│ v2.0.0   │                                                  │
└──────────┴──────────────────────────────────────────────────┘
```

## Features

- **🔍 Full Visibility** — Log every prompt, response, shell command, and HTTP request
- **🚨 PII Detection** — Auto-detect emails, phone numbers, SSNs, credit cards, crypto addresses
- **🛡️ Redact Mode** — Mask PII before it reaches the LLM
- **🚫 Block Mode** — Reject requests that contain PII
- **📊 Web Dashboard** — Browse sessions, event timelines, and stats
- **🔌 Zero Code Changes** — Just set `OPENAI_BASE_URL` or use `wiretaps run`
- **🏠 Self-Hosted** — Your data never leaves your machine
- **📦 SQLite Default** — Zero dependencies, instant setup

## Quick Start

```bash
# Install
pip install wiretaps

# Start wiretaps (proxy + API + interceptor)
wiretaps run -- python my_agent.py

# Or start the daemon separately
wiretaps start

# Point your agent to the proxy
export OPENAI_BASE_URL=http://localhost:8080/v1
python my_agent.py
```

### Start the Dashboard

```bash
cd frontend
npm install
npm run dev
# Open http://localhost:3000
```

## Dashboard Pages

### Sessions List (`/sessions`)
Browse all captured agent sessions with event counts by type and PII alerts.

### Session Timeline (`/sessions/:id`)
Chronological timeline of every event in a session. Click any event to see the full payload — request/response for LLM calls, stdout/stderr for shell commands.

### Stats (`/stats`)
Dashboard with total sessions, events, tokens, PII alerts. Bar charts for events by day and breakdown by type.

## PII Detection

wiretaps automatically scans for sensitive data:

| Pattern | Example |
|---------|---------|
| Email | `user@example.com` |
| Phone | `+1 (555) 123-4567` |
| SSN | `123-45-6789` |
| Credit Card | `4111-1111-1111-1111` |
| CPF (Brazil) | `123.456.789-00` |
| BTC Address | `bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh` |
| ETH Address | `0x71C7656EC7ab88b098defB751B7401B5f6d8976F` |
| Private Key | `0x...` (64 hex chars) |
| Seed Phrase | 12/24 BIP-39 words |

## REST API

The API runs on port 8899 by default.

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /agents` | List agents |
| `GET /sessions` | List sessions (filter by `agent_id`) |
| `GET /sessions/:id` | Session details |
| `GET /sessions/:id/events` | Events for a session |
| `GET /events` | List events (filter by `type`, `session_id`, `pii_only`) |
| `GET /events/:id` | Event details |
| `GET /stats` | Overall statistics |
| `GET /stats/by-day` | Stats grouped by day |
| `GET /stats/by-type` | Stats grouped by event type |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WIRETAPS_URL` | `http://127.0.0.1:8899` | Backend API URL (used by interceptors) |
| `WIRETAPS_SESSION_ID` | *(auto)* | Session ID for the current run |
| `WIRETAPS_API_PORT` | `8899` | API server port |
| `WIRETAPS_PROXY_PORT` | `8080` | Proxy server port |
| `WIRETAPS_HOST` | `127.0.0.1` | Host to bind to |
| `WIRETAPS_TARGET` | `https://api.openai.com` | LLM API to forward requests to |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8899` | Frontend: API URL for the dashboard |

## Redact & Block Modes

```bash
# Redact: mask PII before sending to LLM
wiretaps start --redact

# Block: reject requests with PII entirely
wiretaps start --block
```

## Supported LLM APIs

- OpenAI (`api.openai.com`)
- Anthropic (`api.anthropic.com`)
- Azure OpenAI
- Google AI (Gemini)
- Local models (Ollama, vLLM, etc.)
- Any OpenAI-compatible API

## Project Structure

```
wiretaps/
├── frontend/              # Next.js web dashboard
│   ├── src/app/           # App Router pages
│   │   ├── sessions/      # Sessions list + timeline
│   │   └── stats/         # Stats dashboard
│   └── src/lib/           # API client & types
├── src/wiretaps/
│   ├── api/               # FastAPI REST API
│   │   ├── app.py         # App factory + CORS
│   │   ├── schemas.py     # Pydantic models
│   │   └── routes/        # Endpoint handlers
│   ├── interceptors/      # sitecustomize hook
│   ├── proxy.py           # MitM proxy server
│   ├── pii.py             # PII detection engine
│   ├── storage.py         # SQLite storage layer
│   ├── cli.py             # CLI commands
│   └── daemon.py          # Daemon process
├── tests/                 # Test suite
├── patterns/              # PII pattern definitions
└── pyproject.toml
```

## Contributing

```bash
git clone https://github.com/marcosgabbardo/wiretaps
cd wiretaps
pip install -e ".[dev]"
pytest
ruff check .
```

## License

MIT — use it however you want.

---

Built with 🔌 by [@marcosgabbardo](https://github.com/marcosgabbardo)
