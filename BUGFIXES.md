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

## 📊 Resumo

- **Bugs encontrados:** 3
- **Bugs corrigidos:** 3
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
