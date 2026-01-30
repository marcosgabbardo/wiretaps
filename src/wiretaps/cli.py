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


def get_custom_patterns_from_config(config: dict) -> list[dict]:
    """Extract custom PII patterns from config."""
    pii_config = config.get("pii", {})
    return pii_config.get("custom", [])


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
@click.option("--block", is_flag=True, help="Block requests containing PII (returns 400)")
def start(host: str, port: int, target: str, redact: bool, block: bool) -> None:
    """Start the wiretaps proxy server."""
    import asyncio

    from wiretaps.proxy import WiretapsProxy

    # Load config for allowlist, custom patterns, and webhook
    config = load_config()
    allowlist = get_allowlist_from_config(config)
    custom_patterns = get_custom_patterns_from_config(config)

    # Get webhook config
    alerts_config = config.get("alerts", {})
    webhook_url = alerts_config.get("webhook")
    webhook_events = alerts_config.get("on", ["pii_detected", "blocked"])

    console.print(f"[bold green]🔌 wiretaps v{__version__}[/bold green]")
    console.print(f"   Proxy:  [cyan]http://{host}:{port}[/cyan]")
    console.print(f"   Target: [cyan]{target}[/cyan]")
    if block:
        console.print(
            "   Mode:   [bold red]🚫 BLOCK MODE[/bold red] - Requests with PII will be rejected"
        )
    elif redact:
        console.print(
            "   Mode:   [bold yellow]🛡️  REDACT MODE[/bold yellow] - PII will be masked before sending"
        )
    if allowlist:
        console.print(f"   Allowlist: [cyan]{len(allowlist)} rules[/cyan]")
    if custom_patterns:
        console.print(f"   Custom Patterns: [cyan]{len(custom_patterns)}[/cyan]")
    if webhook_url:
        console.print(f"   Webhook: [cyan]configured[/cyan] (events: {', '.join(webhook_events)})")
    console.print()
    console.print("[dim]Set OPENAI_BASE_URL=http://{host}:{port}/v1 in your agent[/dim]")
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    console.print()

    proxy = WiretapsProxy(
        host=host,
        port=port,
        target=target,
        redact_mode=redact,
        block_mode=block,
        allowlist=allowlist,
        custom_patterns=custom_patterns,
        webhook_url=webhook_url,
        webhook_events=webhook_events,
    )

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
@click.option("--format", "-f", "output_format", type=click.Choice(["json", "csv"]), default="json", help="Output format")
@click.option("--output", "-o", required=True, help="Output file path")
@click.option("--since", help="Start date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)")
@click.option("--until", help="End date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)")
@click.option("--pii-only", is_flag=True, help="Export only entries with PII detected")
@click.option("--limit", "-n", type=int, help="Maximum entries to export")
def export(output_format: str, output: str, since: str | None, until: str | None, pii_only: bool, limit: int | None) -> None:
    """Export logs to JSON or CSV file."""
    from datetime import datetime

    from wiretaps.storage import Storage

    storage = Storage()

    # Parse date filters
    start_time = None
    end_time = None

    if since:
        try:
            if " " in since:
                start_time = datetime.fromisoformat(since)
            else:
                start_time = datetime.fromisoformat(f"{since} 00:00:00")
        except ValueError:
            console.print(f"[red]Invalid date format: {since}[/red]")
            return

    if until:
        try:
            if " " in until:
                end_time = datetime.fromisoformat(until)
            else:
                end_time = datetime.fromisoformat(f"{until} 23:59:59")
        except ValueError:
            console.print(f"[red]Invalid date format: {until}[/red]")
            return

    if output_format == "json":
        count = storage.export_json(
            output,
            limit=limit,
            pii_only=pii_only,
            start_time=start_time,
            end_time=end_time,
        )
    else:
        count = storage.export_csv(
            output,
            limit=limit,
            pii_only=pii_only,
            start_time=start_time,
            end_time=end_time,
        )

    console.print(f"[green]✓ Exported {count} entries to {output}[/green]")


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
@click.option("--no-config", is_flag=True, help="Ignore config file (no allowlist/custom patterns)")
def scan(text: str, no_config: bool) -> None:
    """Scan text for PII (for testing patterns)."""
    from wiretaps.pii import PIIDetector

    allowlist = []
    custom_patterns = []
    if not no_config:
        config = load_config()
        allowlist = get_allowlist_from_config(config)
        custom_patterns = get_custom_patterns_from_config(config)
        if allowlist:
            console.print(f"[dim]Using {len(allowlist)} allowlist rules from config[/dim]")
        if custom_patterns:
            console.print(f"[dim]Using {len(custom_patterns)} custom patterns from config[/dim]")

    detector = PIIDetector(allowlist=allowlist, custom_patterns=custom_patterns)
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


@main.command()
@click.argument("action", type=click.Choice(["list", "add", "remove"]))
@click.option("--name", "-n", help="Pattern name (e.g., 'internal_id')")
@click.option("--regex", "-r", help="Regex pattern to match")
@click.option("--severity", "-s", type=click.Choice(["low", "medium", "high", "critical"]), default="medium", help="Pattern severity")
def patterns(action: str, name: str | None, regex: str | None, severity: str) -> None:
    """Manage custom PII patterns.

    Examples:
        wiretaps patterns list
        wiretaps patterns add --name "internal_id" --regex "INT-[0-9]{6}" --severity high
        wiretaps patterns add -n "employee_id" -r "EMP[A-Z]{2}[0-9]{4}" -s critical
        wiretaps patterns remove --name "internal_id"
    """
    import re

    config_file = Path.home() / ".wiretaps" / "config.yaml"

    if not config_file.exists():
        console.print("[yellow]No config file found. Run 'wiretaps init' first.[/yellow]")
        return

    with open(config_file) as f:
        config = yaml.safe_load(f) or {}

    if "pii" not in config:
        config["pii"] = {}
    if "custom" not in config["pii"]:
        config["pii"]["custom"] = []

    patterns_list = config["pii"]["custom"]

    if action == "list":
        if not patterns_list:
            console.print("[dim]No custom patterns configured.[/dim]")
            console.print("[dim]Add one with: wiretaps patterns add --name 'my_pattern' --regex 'MY-[0-9]+' --severity high[/dim]")
            return
        console.print("[bold]Custom PII patterns:[/bold]")
        for i, pattern in enumerate(patterns_list, 1):
            sev_color = {
                "low": "dim",
                "medium": "yellow",
                "high": "red",
                "critical": "bold red",
            }.get(pattern.get("severity", "medium"), "yellow")
            console.print(
                f"  {i}. [cyan]{pattern.get('name')}[/cyan]: "
                f"[{sev_color}]{pattern.get('severity', 'medium')}[/{sev_color}] "
                f"[dim]/{pattern.get('regex')}/[/dim]"
            )

    elif action == "add":
        if not name or not regex:
            console.print("[red]Both --name and --regex are required for adding a pattern[/red]")
            return

        # Validate regex
        try:
            re.compile(regex)
        except re.error as e:
            console.print(f"[red]Invalid regex pattern: {e}[/red]")
            return

        # Check for duplicate names
        if any(p.get("name") == name for p in patterns_list):
            console.print(f"[yellow]Pattern with name '{name}' already exists. Remove it first.[/yellow]")
            return

        new_pattern = {
            "name": name,
            "regex": regex,
            "severity": severity,
        }

        patterns_list.append(new_pattern)

        with open(config_file, "w") as f:
            yaml.dump(config, f, default_flow_style=False)

        console.print(f"[green]✓ Added custom pattern:[/green] {name} (severity: {severity})")

    elif action == "remove":
        if not name:
            console.print("[red]Specify --name to identify the pattern to remove[/red]")
            return

        original_count = len(patterns_list)
        patterns_list[:] = [p for p in patterns_list if p.get("name") != name]

        removed = original_count - len(patterns_list)
        if removed:
            with open(config_file, "w") as f:
                yaml.dump(config, f, default_flow_style=False)
            console.print(f"[green]✓ Removed pattern: {name}[/green]")
        else:
            console.print(f"[yellow]No pattern found with name '{name}'[/yellow]")


if __name__ == "__main__":
    main()
