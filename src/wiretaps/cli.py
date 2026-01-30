"""
CLI interface for wiretaps.
"""

from pathlib import Path

import click
import yaml
from rich.console import Console

from wiretaps import __version__

console = Console()


def load_config() -> dict:
    """Load configuration from ~/.wiretaps/config.yaml if it exists."""
    config_file = Path.home() / ".wiretaps" / "config.yaml"
    if config_file.exists():
        with open(config_file) as f:
            return yaml.safe_load(f) or {}
    return {}


def get_allowlist_from_config(config: dict) -> list[dict]:
    """Extract allowlist rules from config."""
    pii_config = config.get("pii", {})
    return pii_config.get("allowlist", [])


@click.group()
@click.version_option(version=__version__, prog_name="wiretaps")
def main() -> None:
    """🔌 wiretaps - See what your AI agents are sending to LLMs."""
    pass


@main.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", default=8080, help="Port to bind to")
@click.option("--target", default="https://api.openai.com", help="Target API URL")
@click.option("--redact", is_flag=True, help="Redact PII before sending to LLM")
def start(host: str, port: int, target: str, redact: bool) -> None:
    """Start the wiretaps proxy server."""
    import asyncio

    from wiretaps.proxy import WiretapsProxy

    # Load config for allowlist
    config = load_config()
    allowlist = get_allowlist_from_config(config)

    console.print(f"[bold green]🔌 wiretaps v{__version__}[/bold green]")
    console.print(f"   Proxy:  [cyan]http://{host}:{port}[/cyan]")
    console.print(f"   Target: [cyan]{target}[/cyan]")
    if redact:
        console.print(
            "   Mode:   [bold yellow]🛡️  REDACT MODE[/bold yellow] - PII will be masked before sending"
        )
    if allowlist:
        console.print(f"   Allowlist: [cyan]{len(allowlist)} rules[/cyan]")
    console.print()
    console.print("[dim]Set OPENAI_BASE_URL=http://{host}:{port}/v1 in your agent[/dim]")
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    console.print()

    proxy = WiretapsProxy(host=host, port=port, target=target, redact_mode=redact, allowlist=allowlist)

    try:
        asyncio.run(proxy.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down...[/yellow]")


@main.command()
@click.option("--limit", "-n", default=50, help="Number of entries to show")
@click.option("--pii-only", is_flag=True, help="Show only entries with PII detected")
def logs(limit: int, pii_only: bool) -> None:
    """View recent log entries."""
    from rich.table import Table

    from wiretaps.storage import Storage

    storage = Storage()
    entries = storage.get_logs(limit=limit, pii_only=pii_only)

    if not entries:
        console.print("[dim]No log entries found.[/dim]")
        return

    table = Table(title="Recent Requests")
    table.add_column("Time", style="dim")
    table.add_column("Endpoint")
    table.add_column("Tokens", justify="right")
    table.add_column("PII")

    for entry in entries:
        if entry.pii_types:
            if entry.redacted:
                pii_status = "[cyan]🛡️ " + ", ".join(entry.pii_types) + "[/cyan]"
            else:
                pii_status = "[red]⚠️ " + ", ".join(entry.pii_types) + "[/red]"
        else:
            pii_status = "[green]✓ clean[/green]"
        table.add_row(
            entry.timestamp.strftime("%H:%M:%S"),
            entry.endpoint,
            str(entry.tokens),
            pii_status,
        )

    console.print(table)


@main.command()
def dashboard() -> None:
    """Open the live dashboard (TUI)."""
    from wiretaps.dashboard import run_dashboard

    run_dashboard()


@main.command()
def init() -> None:
    """Initialize wiretaps configuration."""
    from pathlib import Path

    config_dir = Path.home() / ".wiretaps"
    config_file = config_dir / "config.yaml"

    if config_file.exists():
        console.print(f"[yellow]Config already exists:[/yellow] {config_file}")
        return

    config_dir.mkdir(parents=True, exist_ok=True)

    default_config = """# wiretaps configuration
proxy:
  host: 127.0.0.1
  port: 8080

storage:
  type: sqlite
  path: ~/.wiretaps/logs.db

pii:
  enabled: true
  patterns:
    - email
    - phone
    - credit_card
    - ssn
    - cpf
    - btc_address
    - eth_address
    - private_key
    - seed_phrase

  # Auto-redact PII before sending to LLM
  redact: false

  # Allowlist: PII that should NOT be flagged/redacted
  # Examples:
  allowlist:
    # Allow specific email address
    # - type: email
    #   value: "myemail@company.com"

    # Allow all emails from a domain (regex)
    # - type: email
    #   pattern: ".*@mycompany\\.com"

    # Allow a specific phone number
    # - type: phone
    #   value: "+5511999999999"

    # Allow all phone numbers (use with caution!)
    # - type: phone

  # Custom patterns to detect (in addition to built-in)
  custom: []

# Webhook for alerts (optional)
# alerts:
#   webhook: https://your-server.com/alerts
"""

    config_file.write_text(default_config)
    console.print(f"[green]✓ Created config:[/green] {config_file}")


@main.command()
@click.argument("text")
@click.option("--no-config", is_flag=True, help="Ignore config file (no allowlist)")
def scan(text: str, no_config: bool) -> None:
    """Scan text for PII (for testing patterns)."""
    from wiretaps.pii import PIIDetector

    allowlist = []
    if not no_config:
        config = load_config()
        allowlist = get_allowlist_from_config(config)
        if allowlist:
            console.print(f"[dim]Using {len(allowlist)} allowlist rules from config[/dim]")

    detector = PIIDetector(allowlist=allowlist)
    results = detector.scan(text)

    if not results:
        console.print("[green]✓ No PII detected[/green]")
        return

    console.print("[red]⚠️ PII Detected:[/red]")
    for match in results:
        console.print(f"  - [yellow]{match.pattern_name}[/yellow]: {match.matched_text}")


@main.command()
@click.argument("action", type=click.Choice(["list", "add", "remove", "clear"]))
@click.option("--type", "-t", "pii_type", help="PII type (email, phone, etc.)")
@click.option("--value", "-v", help="Exact value to allow")
@click.option("--pattern", "-p", help="Regex pattern to allow")
def allowlist(action: str, pii_type: str | None, value: str | None, pattern: str | None) -> None:
    """Manage PII allowlist rules.

    Examples:
        wiretaps allowlist list
        wiretaps allowlist add -t email -v "me@company.com"
        wiretaps allowlist add -t email -p ".*@company\\.com"
        wiretaps allowlist add -t phone -v "+5511999999999"
        wiretaps allowlist remove -t email -v "me@company.com"
        wiretaps allowlist clear
    """
    config_file = Path.home() / ".wiretaps" / "config.yaml"

    if not config_file.exists():
        console.print("[yellow]No config file found. Run 'wiretaps init' first.[/yellow]")
        return

    with open(config_file) as f:
        config = yaml.safe_load(f) or {}

    if "pii" not in config:
        config["pii"] = {}
    if "allowlist" not in config["pii"]:
        config["pii"]["allowlist"] = []

    rules = config["pii"]["allowlist"]

    if action == "list":
        if not rules:
            console.print("[dim]No allowlist rules configured.[/dim]")
            return
        console.print("[bold]Allowlist rules:[/bold]")
        for i, rule in enumerate(rules, 1):
            parts = []
            if rule.get("type"):
                parts.append(f"type={rule['type']}")
            if rule.get("value"):
                parts.append(f"value={rule['value']}")
            if rule.get("pattern"):
                parts.append(f"pattern={rule['pattern']}")
            console.print(f"  {i}. {', '.join(parts)}")

    elif action == "add":
        if not pii_type and not value and not pattern:
            console.print("[red]Specify at least --type, --value, or --pattern[/red]")
            return

        new_rule = {}
        if pii_type:
            new_rule["type"] = pii_type
        if value:
            new_rule["value"] = value
        if pattern:
            new_rule["pattern"] = pattern

        rules.append(new_rule)

        with open(config_file, "w") as f:
            yaml.dump(config, f, default_flow_style=False)

        console.print(f"[green]✓ Added rule:[/green] {new_rule}")

    elif action == "remove":
        if not pii_type and not value and not pattern:
            console.print("[red]Specify --type, --value, or --pattern to identify the rule[/red]")
            return

        original_count = len(rules)
        rules[:] = [
            r for r in rules
            if not (
                (pii_type is None or r.get("type") == pii_type) and
                (value is None or r.get("value") == value) and
                (pattern is None or r.get("pattern") == pattern)
            )
        ]

        removed = original_count - len(rules)
        if removed:
            with open(config_file, "w") as f:
                yaml.dump(config, f, default_flow_style=False)
            console.print(f"[green]✓ Removed {removed} rule(s)[/green]")
        else:
            console.print("[yellow]No matching rules found[/yellow]")

    elif action == "clear":
        if not rules:
            console.print("[dim]Allowlist already empty[/dim]")
            return

        if click.confirm(f"Remove all {len(rules)} allowlist rules?"):
            config["pii"]["allowlist"] = []
            with open(config_file, "w") as f:
                yaml.dump(config, f, default_flow_style=False)
            console.print("[green]✓ Allowlist cleared[/green]")


if __name__ == "__main__":
    main()
