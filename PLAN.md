# wiretaps - Product Plan

> See what your AI agents are sending to LLMs. MitM proxy for auditing, PII detection, and compliance.

**Website:** https://wiretaps.ai
**Repo:** https://github.com/marcosgabbardo/wiretaps
**Modelo:** Open-core (OSS gratuito + Enterprise pago)
**Status:** v0.7.0 - Block Mode + Export + Custom Patterns + Webhook + Stats + API + Multi-tenant ✅

---

## ✅ Concluído

### Core (v0.1.0)
- [x] Nome definido: **wiretaps**
- [x] Domínio registrado: **wiretaps.ai**
- [x] Repo GitHub criado
- [x] Estrutura inicial do projeto
- [x] Core proxy (aiohttp)
- [x] PII detection (regex patterns)
- [x] Crypto detection (BTC, ETH, private keys)
- [x] Storage SQLite
- [x] CLI básica (start, logs, scan, init)
- [x] Testes para PII detection
- [x] GitHub Actions CI
- [x] README completo

### PII Detection (v0.2.0 - v0.3.0)
- [x] US SSN, UK NIN, EU patterns
- [x] IBAN, AWS keys, GitHub tokens
- [x] Phone numbers (internacional)
- [x] IP addresses
- [x] Postal codes
- [x] Street addresses

### Dashboard TUI (v0.4.x)
- [x] Dashboard com Textual
- [x] Detail panel on row highlight
- [x] Cursor position preserved on refresh
- [x] Screenshot no README

### Redact Mode (v0.5.x)
- [x] Mask PII before sending to LLM
- [x] Track redacted status in storage
- [x] Show redacted indicator in dashboard
- [x] Testado com OpenAI e Anthropic APIs ✅

### Allowlist (v0.6.0)
- [x] Permitir valores específicos (ex: seu email pessoal)
- [x] Permitir padrões regex (ex: emails do domínio da empresa)
- [x] Permitir tipos inteiros (ex: todos os phones)
- [x] CLI: `wiretaps allowlist list|add|remove|clear`
- [x] Config via ~/.wiretaps/config.yaml

### Marketing
- [x] Landing page wiretaps.ai (Cloudflare Pages)
- [x] Mobile layout ajustado

### Block Mode (v0.7.0)
- [x] `--block` flag para rejeitar requests com PII
- [x] Retorna HTTP 400 com `{"error": "Request blocked: PII detected", "pii_types": [...]}`
- [x] Testes unitários
- [x] Documentação no README

### Export JSON/CSV (v0.7.0)
- [x] `wiretaps export --format json -o logs.json`
- [x] `wiretaps export --format csv -o logs.csv`
- [x] Filtros: `--since`, `--until`, `--pii-only`

### Custom PII Patterns (v0.7.0)
- [x] `wiretaps patterns add --name "internal_id" --regex "INT-[0-9]{6}" --severity high`
- [x] `wiretaps patterns list`
- [x] `wiretaps patterns remove --name "internal_id"`
- [x] Salvar em ~/.wiretaps/config.yaml

### Webhook Alerts (v0.7.0)
- [x] Config em ~/.wiretaps/config.yaml
- [x] POST JSON quando detectar PII
- [x] Eventos: pii_detected, blocked

### Stats (v0.7.0)
- [x] `wiretaps stats` - resumo
- [x] `wiretaps stats --json` - output JSON
- [x] Métricas: requests, tokens, PII detections, by day/hour

### REST API (v0.7.0)
- [x] `wiretaps api start --port 8081`
- [x] GET /logs, /logs/:id, /stats, /health

### Multi-tenant (v0.7.0)
- [x] Detectar API key do header Authorization
- [x] Separar logs por API key
- [x] Dashboard mostra key (mascarada)

---

## 🚀 Próximos Passos

### Publicação
- [x] Publicar no **PyPI** (`pip install wiretaps`) ✅
- [ ] Documentação (docs site com mkdocs?)

### Integração
- [x] ~~Integração Clawdbot~~ — não viável (Clawdbot não suporta baseUrl customizado)

### Launch
- [ ] Blog post técnico
- [ ] **Launch HN**
- [ ] Twitter thread
- [ ] Reddit communities (r/LocalLLaMA, r/MachineLearning)

---

## 📊 Métricas de Sucesso

### Launch
- [ ] 100+ stars GitHub
- [ ] 50+ pip installs
- [ ] Top 10 HN (idealmente front page)

### Mês 3
- [ ] 500+ stars
- [ ] 10+ contributors
- [ ] Primeiro enterprise lead

---

*Atualizado: 2026-01-30*
