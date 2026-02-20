# Bug Fixes - Wiretaps v0.7.0

**Análise realizada:** 2026-02-20  
**Testes:** 88/88 passando ✅  
**Ruff:** Lint clean ✅

---

## 🐛 Bugs Corrigidos

### 1. **Proxy Server - Graceful Shutdown Ausente** (Crítico)

**Arquivo:** `src/wiretaps/proxy.py`  
**Linha:** 272  
**Severidade:** Alta

**Problema:**
```python
async def run(self) -> None:
    runner = web.AppRunner(self.app)
    await runner.setup()
    site = web.TCPSite(runner, self.config.host, self.config.port)
    await site.start()
    
    while True:
        await asyncio.sleep(3600)  # ❌ Nunca faz cleanup
```

O servidor nunca executa cleanup ao parar (Ctrl+C). Resources (runner, site) não são liberados corretamente.

**Correção:**
```python
async def run(self) -> None:
    runner = web.AppRunner(self.app)
    await runner.setup()
    site = web.TCPSite(runner, self.config.host, self.config.port)
    await site.start()
    
    try:
        # Keep server running until interrupted
        while True:
            await asyncio.sleep(3600)
    finally:
        # Graceful shutdown
        await site.stop()
        await runner.cleanup()
```

**Impacto:** Agora o servidor para gracefully ao receber KeyboardInterrupt (Ctrl+C), fechando conexões e liberando resources.

---

### 2. **PII Detector - Lógica de Allowlist com Bug** (Médio)

**Arquivo:** `src/wiretaps/pii.py`  
**Linha:** 525-545  
**Severidade:** Média

**Problema:**

Quando uma regra de allowlist tem `type=None` (permitir qualquer tipo) mas especifica `value` ou `pattern`, a lógica original permitia incorretamente valores que não batiam.

```python
def _is_allowed(self, pii_type: str, value: str) -> bool:
    for rule_type, rule_pattern, rule_value in self._compiled_allowlist:
        if rule_type is not None:
            if pii_type != rule_type and not pii_type.startswith(f"{rule_type}_"):
                continue  # ❌ Se rule_type é None, não valida value/pattern corretamente
        
        if rule_value is not None and rule_value == value:
            return True
        # ... continua sem validar se value NÃO bater
```

**Exemplo de bug:**
```python
# Allowlist: {"type": None, "value": "specific@email.com"}
# Deveria permitir APENAS "specific@email.com" (qualquer tipo)
# Mas permitia QUALQUER email porque a validação falhava
```

**Correção:**
```python
def _is_allowed(self, pii_type: str, value: str) -> bool:
    for rule_type, rule_pattern, rule_value in self._compiled_allowlist:
        # Check type filter
        type_matches = False
        if rule_type is None:
            type_matches = True  # Match any type
        elif pii_type == rule_type or pii_type.startswith(f"{rule_type}_"):
            type_matches = True
        
        if not type_matches:
            continue
        
        # Check exact value match
        if rule_value is not None:
            if rule_value == value:
                return True
            else:
                continue  # ✅ Value specified but doesn't match - skip
        
        # Check pattern match
        if rule_pattern is not None:
            if rule_pattern.fullmatch(value):
                return True
            else:
                continue  # ✅ Pattern specified but doesn't match - skip
        
        # If only type specified (no value or pattern), allow all of that type
        if rule_value is None and rule_pattern is None:
            return True
    
    return False
```

**Impacto:** Allowlist agora funciona corretamente com regras genéricas (type=None) que especificam valores/patterns exatos.

---

### 3. **CLI - Falta Tratamento de Erro ao Carregar Config YAML** (Baixo)

**Arquivo:** `src/wiretaps/cli.py`  
**Linha:** 15-20  
**Severidade:** Baixa

**Problema:**
```python
def load_config() -> dict:
    config_file = Path.home() / ".wiretaps" / "config.yaml"
    if config_file.exists():
        with open(config_file) as f:
            return yaml.safe_load(f) or {}  # ❌ Crash se YAML inválido
    return {}
```

Se o arquivo `~/.wiretaps/config.yaml` existir mas tiver YAML mal formatado, `yaml.safe_load()` levanta `YAMLError` e o CLI crasheia.

**Correção:**
```python
def load_config() -> dict:
    config_file = Path.home() / ".wiretaps" / "config.yaml"
    if config_file.exists():
        try:
            with open(config_file) as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            console.print(f"[red]Error loading config: {e}[/red]")
            console.print("[yellow]Using default configuration.[/yellow]")
            return {}
    return {}
```

**Impacto:** CLI não crasheia mais com config inválido, mostra erro amigável e continua com configuração padrão.

---

### 4. **CLI - Comando allowlist/patterns crasheia se lista estiver vazia no YAML** (Baixo)

**Arquivo:** `src/wiretaps/cli.py`  
**Linhas:** 500, 578  
**Severidade:** Baixa

**Problema:**

Se o arquivo de config tiver `allowlist:` ou `custom:` sem itens (comentados ou vazios), YAML parseia como `None` ao invés de lista vazia. Comandos `wiretaps allowlist add` e `wiretaps patterns add` crasheiam com:

```
AttributeError: 'NoneType' object has no attribute 'append'
```

**Correção (allowlist):**
```python
# Antes
if "allowlist" not in config["pii"]:
    config["pii"]["allowlist"] = []
rules = config["pii"]["allowlist"]  # ❌ Pode ser None

# Depois
if "allowlist" not in config["pii"] or config["pii"]["allowlist"] is None:
    config["pii"]["allowlist"] = []
rules = config["pii"]["allowlist"]  # ✅ Sempre lista
```

**Correção (patterns):**
```python
# Mesma lógica aplicada a custom patterns
if "custom" not in config["pii"] or config["pii"]["custom"] is None:
    config["pii"]["custom"] = []
```

**Impacto:** Comandos `allowlist` e `patterns` funcionam corretamente mesmo com config vazio.

---

### 5. **PII Detector - Ordem de Patterns e API Key False Positives** (Crítico)

**Arquivos:** `src/wiretaps/pii.py`  
**Linhas:** 286-314 (patterns), 369-425 (pattern list)  
**Severidade:** Crítica

**Problema:**

Patterns genéricos (phones, IBAN) estavam sendo testados ANTES de patterns específicos (API keys, UK NIN), causando false positives:

1. **OpenAI keys quebradas por phone detection:**
   ```
   Input:  sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEF
   Output: sk-proj-abcdefghijklmnopqrstuvwxyz[PHONE_US]ABCDEF  ❌
   ```
   `PHONE_US` matchou `1234567890` dentro da API key.

2. **OpenAI pattern matchando Anthropic keys:**
   ```python
   OPENAI_KEY = r"\bsk-(?:proj-|org-)?[a-zA-Z0-9_-]{20,}\b"
   # Problema: (?:proj-|org-)? é opcional, match sk-ant-... também
   ```

3. **UK NIN matchando como IBAN:**
   ```
   Input: AB123456C  (valid UK NIN)
   Match: iban  ❌ (should be uk_nin)
   ```

**Correção:**

**1. Reordenar patterns por especificidade (mais específico primeiro):**
```python
self.patterns = [
    # API Keys (HIGHEST PRIORITY - most specific)
    ("anthropic_key", ...),  # sk-ant-... ANTES de sk-...
    ("openai_key", ...),
    ("github_token", ...),
    # Crypto (HIGH PRIORITY)
    ("btc_address", ...),
    # National IDs (BEFORE generic financial)
    ("uk_nin", ...),  # ANTES de IBAN
    ("us_ssn", ...),
    # Financial
    ("iban", ...),  # DEPOIS de UK_NIN
    # Generic numeric (LOWEST PRIORITY)
    ("phone_us", ...),  # POR ÚLTIMO
    ("us_zip", ...),
]
```

**2. Patterns API key mais específicos:**
```python
# Anthropic - mais específico (sk-ant-)
ANTHROPIC_KEY = re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{20,}\b")

# OpenAI - negative lookahead pra excluir sk-ant-
OPENAI_KEY = re.compile(r"\bsk-(?!ant-)(?:proj-|org-)?[a-zA-Z0-9_-]{20,}\b")
#                              ^^^^^^^^ exclui sk-ant-
```

**3. `_remove_overlaps` elimina matches sobrepostos:**
- API_KEY match pos 8-57
- PHONE_US match pos 11-21 (SOBREPÕE)
- `_remove_overlaps` mantém o maior (API_KEY) ✅

**Impacto:** 
- API keys não são mais quebradas por phone detection
- UK NIN detectado corretamente (não mais como IBAN)
- Anthropic keys distinguidas de OpenAI keys
- Redaction funciona perfeitamente com `[OPENAI_KEY]`, `[ANTHROPIC_KEY]`, etc.

**Testes:** 88/88 passando ✅

---

## 📊 Resumo

- **Bugs encontrados:** 5
- **Bugs corrigidos:** 5
- **Testes afetados:** 0 (todos continuam passando)
- **Breaking changes:** Nenhum

---

## ✅ Validação

```bash
# Testes
uv run pytest -v
# 88 passed, 5 warnings

# Linting
uv run ruff check .
# All checks passed!

# CLI funcional
uv run wiretaps --version
# wiretaps, version 0.7.0
```

---

## 📝 Recomendações Futuras

### Melhorias Sugeridas (não urgente):

1. **Deprecation Warnings (aiohttp 3.8+):**
   - 5 warnings sobre `@unittest_run_loop` em `tests/test_api.py`
   - Remover decorators desnecessários (aiohttp 3.8+ não precisa)

2. **Type Hints Inconsistentes:**
   - Usar `str | None` consistentemente ao invés de `Optional[str]` (Python 3.10+)
   - Adicionar return types em alguns métodos

3. **Teste de Integração:**
   - Adicionar teste E2E do proxy fazendo request real
   - Testar dashboard TUI (atualmente sem testes)

4. **Documentação:**
   - Adicionar docstrings nos métodos `_is_allowed`, `_send_webhook`
   - README poderia incluir troubleshooting section

---

**Última atualização:** 2026-02-20 07:30 GMT-3
