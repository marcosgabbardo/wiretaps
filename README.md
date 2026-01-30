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

## Features

- **🔍 Full Visibility** — Log every prompt, response, and tool call
- **🚨 PII Detection** — Auto-detect emails, phone numbers, SSNs, credit cards
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

Add custom patterns:

```yaml
# ~/.wiretaps/patterns.yaml
patterns:
  - name: internal_id
    regex: "INTERNAL-[A-Z]{3}-[0-9]{6}"
    severity: high
```

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
