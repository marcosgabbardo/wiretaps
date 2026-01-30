# 🔌 wiretaps

**See what your AI agents are sending to LLMs.**

A transparent MitM proxy for auditing AI agent traffic. Logs every prompt, response, and tool call. Auto-detects PII, credentials, and crypto wallet addresses.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

---

## Why?

AI agents have access to your emails, files, and credentials. But do you know what they're actually sending to OpenAI, Anthropic, or other LLM APIs?

**wiretaps** sits between your agent and the LLM, giving you complete visibility:

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  AI Agent   │────▶│   wiretaps   │────▶│   LLM API   │
│ (any agent) │     │              │     │ (OpenAI,..) │
└─────────────┘     └──────┬───────┘     └─────────────┘
                          │
                          ▼
                   📋 Audit Logs
                   🚨 PII Alerts
                   📊 Dashboard
```

### Live Dashboard

<p align="center">
  <img src="assets/dashboard.png" alt="wiretaps dashboard" width="800">
</p>

## Features

- **🔍 Full Visibility** — Log every prompt, response, and tool call
- **🚨 PII Detection** — Auto-detect emails, phone numbers, SSNs, credit cards
- **🛡️ Redact Mode** — Mask PII before it reaches the LLM
- **✅ Allowlist** — Let specific values pass through (your email, company domain)
- **₿ Crypto Detection** — Flag wallet addresses, private keys, seed phrases
- **📊 Live Dashboard** — Terminal UI to monitor traffic in real-time
- **🔌 Zero Code Changes** — Just set `OPENAI_BASE_URL` and go
- **🏠 Self-Hosted** — Your data never leaves your machine
- **📦 SQLite Default** — Zero dependencies, instant setup

## Quick Start

```bash
# Install
pip install wiretaps

# Start the proxy
wiretaps start

# Point your agent to the proxy
export OPENAI_BASE_URL=http://localhost:8080/v1

# Run your agent as usual
python my_agent.py

# View logs
wiretaps logs
```

## Dashboard

```bash
wiretaps dashboard
```

```
┌─────────────────────────────────────────────────────────────┐
│ wiretaps v0.1.0                          Requests: 1,234    │
├─────────────────────────────────────────────────────────────┤
│ 14:23:01 │ POST /chat/completions │ 1,200 tk │ ⚠️ PII: email │
│ 14:22:58 │ POST /chat/completions │ 856 tk   │ ✓ clean      │
│ 14:22:45 │ POST /chat/completions │ 2,100 tk │ ⚠️ PII: phone │
│ 14:22:30 │ POST /embeddings       │ 128 tk   │ ✓ clean      │
└─────────────────────────────────────────────────────────────┘
```

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

## Custom PII Patterns

Add your own patterns to detect company-specific sensitive data:

```bash
# Add a custom pattern
wiretaps patterns add --name "internal_id" --regex "INT-[0-9]{6}" --severity high

# Add another pattern
wiretaps patterns add -n "employee_id" -r "EMP[A-Z]{2}[0-9]{4}" -s critical

# List all custom patterns
wiretaps patterns list

# Remove a pattern
wiretaps patterns remove --name "internal_id"
```

Custom patterns are saved in `~/.wiretaps/config.yaml`:

```yaml
pii:
  custom:
    - name: internal_id
      regex: "INT-[0-9]{6}"
      severity: high
    - name: employee_id
      regex: "EMP[A-Z]{2}[0-9]{4}"
      severity: critical
```

## Redact Mode

Automatically mask PII **before** it reaches the LLM:

```bash
wiretaps start --redact
```

```
Original:  "My email is john@example.com and SSN is 123-45-6789"
Redacted:  "My email is [EMAIL] and SSN is [US_SSN]"
```

The LLM never sees the real data. Your audit logs still capture the original for compliance.

## Block Mode

Completely block requests that contain PII:

```bash
wiretaps start --block
```

When PII is detected, the request is rejected with HTTP 400:

```json
{
  "error": "Request blocked: PII detected",
  "pii_types": ["email", "phone"]
}
```

Your agent receives an error, and the sensitive data never leaves your network. Perfect for strict compliance environments.

## Export Logs

Export your audit logs to JSON or CSV for compliance reports:

```bash
# Export all logs to JSON
wiretaps export -f json -o logs.json

# Export to CSV
wiretaps export -f csv -o logs.csv

# Export only entries with PII detected
wiretaps export -f json -o pii-incidents.json --pii-only

# Export with date range
wiretaps export -f csv -o january.csv --since 2024-01-01 --until 2024-01-31

# Limit number of entries
wiretaps export -f json -o recent.json -n 100
```

## Allowlist

Allow specific values to pass through without being flagged as PII:

```bash
# Allow your own email
wiretaps allowlist add -t email -v "me@mycompany.com"

# Allow all emails from your company domain
wiretaps allowlist add -t email -p ".*@mycompany\.com"

# Allow a specific phone number
wiretaps allowlist add -t phone -v "+5511999999999"

# Allow all phone numbers (use with caution)
wiretaps allowlist add -t phone

# List all rules
wiretaps allowlist list

# Remove a rule
wiretaps allowlist remove -t email -v "me@mycompany.com"

# Clear all rules
wiretaps allowlist clear
```

Or configure in `~/.wiretaps/config.yaml`:

```yaml
pii:
  allowlist:
    # Exact value
    - type: email
      value: "ceo@company.com"
    
    # Regex pattern
    - type: email
      pattern: ".*@company\\.com"
    
    # Allow entire type
    - type: phone
```

## Usage Statistics

View usage statistics and PII detection metrics:

```bash
# Show overall stats
wiretaps stats

# Output as JSON (for scripts)
wiretaps stats --json

# Stats grouped by day
wiretaps stats --by-day

# Stats grouped by hour
wiretaps stats --by-hour

# Filter by API key (multi-tenant)
wiretaps stats --api-key sk-xxx
```

Example output:
```
📊 wiretaps Statistics

  Total Requests: 1,234
  Total Tokens: 456,789

  PII Detections: 23 (1.86%)
  Blocked: 5
  Redacted: 18
  Errors: 0

Top PII Types:
  - email: 15
  - phone: 8
  - us_ssn: 3
```

## REST API

Serve logs and stats via a REST API for dashboards and integrations:

```bash
# Start the API server
wiretaps api start --port 8081
```

**Endpoints:**

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /logs` | List logs with pagination |
| `GET /logs/:id` | Get log details |
| `GET /stats` | Usage statistics |

**Examples:**

```bash
# Health check
curl http://localhost:8081/health

# List logs (with pagination)
curl "http://localhost:8081/logs?limit=10&offset=0"

# Filter logs with PII only
curl "http://localhost:8081/logs?pii_only=true"

# Get specific log
curl http://localhost:8081/logs/123

# Get stats
curl http://localhost:8081/stats

# Get stats by day
curl "http://localhost:8081/stats?by_day=true"
```

## Webhook Alerts

Get notified when PII is detected:

```yaml
# ~/.wiretaps/config.yaml
alerts:
  webhook: https://hooks.slack.com/services/xxx/yyy/zzz
  on:
    - pii_detected
    - blocked
```

When PII is detected, wiretaps sends a POST request:

```json
{
  "timestamp": "2024-01-15T10:30:00.000000",
  "endpoint": "/v1/chat/completions",
  "pii_types": ["email", "phone"],
  "redacted": true,
  "blocked": false
}
```

Works with Slack, Discord, custom webhooks, or any HTTP endpoint.

## Multi-tenant Support

Track usage across multiple API keys (multi-tenant environments):

```bash
# View logs filtered by API key
wiretaps logs --api-key sk-xxx

# View stats filtered by API key
wiretaps stats --api-key sk-xxx

# API also supports filtering
curl "http://localhost:8081/logs?api_key=sk-xxx"
```

The dashboard shows masked API keys for each request (e.g., `sk-t...cdef`).

API keys are automatically extracted from the `Authorization: Bearer <key>` header.

## Supported LLM APIs

- ✅ OpenAI (`api.openai.com`)
- ✅ Anthropic (`api.anthropic.com`)
- ✅ Azure OpenAI
- ✅ Google AI (Gemini)
- ✅ Local models (Ollama, vLLM, etc.)
- ✅ Any OpenAI-compatible API

## Configuration

```bash
# Generate default config
wiretaps init

# Edit config
vim ~/.wiretaps/config.yaml
```

```yaml
# ~/.wiretaps/config.yaml
proxy:
  host: 127.0.0.1
  port: 8080

storage:
  type: sqlite  # or postgresql
  path: ~/.wiretaps/logs.db

pii:
  enabled: true
  patterns:
    - email
    - phone
    - credit_card
    - crypto_address
  
  # Auto-redact before sending to LLM (enterprise)
  redact: false

alerts:
  # Webhook on PII detection
  webhook: https://your-server.com/alerts
```

## Use Cases

### Compliance & Audit
Keep audit logs of all AI interactions for GDPR, LGPD, SOC2 compliance.

### Security Review  
Ensure your agents aren't leaking credentials, API keys, or sensitive data.

### Crypto/Fintech
Detect wallet addresses and private keys before they reach external APIs.

### Development
Debug exactly what your agent is sending without modifying code.

## Integrations

### Clawdbot

```yaml
# clawdbot.yaml
llm:
  baseUrl: http://localhost:8080/v1
```

### LangChain

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    base_url="http://localhost:8080/v1"
)
```

### Any OpenAI SDK

```python
import openai

client = openai.OpenAI(
    base_url="http://localhost:8080/v1"
)
```

## Enterprise

Self-hosted open source not enough? **wiretaps Enterprise** adds:

- 🌐 Web dashboard with auth
- 🔐 SSO (SAML, OIDC)
- 👥 RBAC (role-based access)
- 📊 Compliance reports (LGPD, GDPR, SOC2)
- 🔔 Alerts (Slack, email, webhook)
- ☁️ Managed hosting option

Contact: hello@wiretaps.ai

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
# Clone
git clone https://github.com/marcosgabbardo/wiretaps
cd wiretaps

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check .
```

## License

MIT — use it however you want.

---

Built with 🔌 by [@marcosgabbardo](https://github.com/marcosgabbardo)

**[wiretaps.ai](https://wiretaps.ai)**
