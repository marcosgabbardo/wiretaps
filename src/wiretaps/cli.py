"""
CLI interface for wiretaps.
"""

import click
from rich.console import Console

from wiretaps import __version__

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="wiretaps")
def main() -> None:
    """🔌 wiretaps - See what your AI agents are sending to LLMs."""
    pass


@main.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", default=8080, help="Port to bind to")
@click.option("--target", default="https://api.openai.com", help="Target API URL")
def start(host: str, port: int, target: str) -> None:
    """Start the wiretaps proxy server."""
    import asyncio

    from wiretaps.proxy import WiretapsProxy

    console.print(f"[bold green]🔌 wiretaps v{__version__}[/bold green]")
    console.print(f"   Proxy:  [cyan]http://{host}:{port}[/cyan]")
    console.print(f"   Target: [cyan]{target}[/cyan]")
    console.print()
    console.print("[dim]Set OPENAI_BASE_URL=http://{host}:{port}/v1 in your agent[/dim]")
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    console.print()

    proxy = WiretapsProxy(host=host, port=port, target=target)

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
        pii_status = (
            "[red]⚠️ " + ", ".join(entry.pii_types) + "[/red]"
            if entry.pii_types
            else "[green]✓ clean[/green]"
        )
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

  # Custom patterns (optional)
  custom: []

  # Auto-redact PII before sending to LLM
  redact: false

# Webhook for alerts (optional)
# alerts:
#   webhook: https://your-server.com/alerts
"""

    config_file.write_text(default_config)
    console.print(f"[green]✓ Created config:[/green] {config_file}")


@main.command()
@click.argument("text")
def scan(text: str) -> None:
    """Scan text for PII (for testing patterns)."""
    from wiretaps.pii import PIIDetector

    detector = PIIDetector()
    results = detector.scan(text)

    if not results:
        console.print("[green]✓ No PII detected[/green]")
        return

    console.print("[red]⚠️ PII Detected:[/red]")
    for match in results:
        console.print(f"  - [yellow]{match.pattern_name}[/yellow]: {match.matched_text}")


if __name__ == "__main__":
    main()
