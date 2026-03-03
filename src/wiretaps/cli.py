"""
CLI interface for wiretaps.
"""

import os
import signal
import sys
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
        try:
            with open(config_file) as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            console.print(f"[red]Error loading config: {e}[/red]")
            console.print("[yellow]Using default configuration.[/yellow]")
            return {}
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
    """wiretaps - See what your AI agents are sending to LLMs."""
    pass


# ---------------------------------------------------------------------------
# V2 commands
# ---------------------------------------------------------------------------


@main.command()
@click.option("--port", default=8899, help="API port")
@click.option("--proxy-port", default=8080, help="Proxy port")
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--target", default="https://api.openai.com", help="Target API URL")
@click.option("--redact", is_flag=True, help="Redact PII before sending to LLM")
@click.option("--block", is_flag=True, help="Block requests containing PII")
def start(port: int, proxy_port: int, host: str, target: str, redact: bool, block: bool) -> None:
    """Start the wiretaps daemon (API + proxy)."""
    from wiretaps import daemon

    running, pid = daemon.is_running()
    if running:
        console.print(f"[yellow]Daemon already running (PID {pid})[/yellow]")
        return

    console.print(f"[bold green]wiretaps v{__version__}[/bold green]")
    console.print(f"   API:    [cyan]http://{host}:{port}[/cyan]")
    console.print(f"   Proxy:  [cyan]http://{host}:{proxy_port}[/cyan]")
    console.print(f"   Target: [cyan]{target}[/cyan]")
    if block:
        console.print("   Mode:   [bold red]BLOCK MODE[/bold red] - Requests with PII will be rejected")
    elif redact:
        console.print("   Mode:   [bold yellow]REDACT MODE[/bold yellow] - PII will be masked before sending")
    console.print()
    console.print(f"[dim]Set OPENAI_BASE_URL=http://{host}:{proxy_port}/v1 in your agent[/dim]")
    console.print("[dim]Press Ctrl+C to stop[/dim]")
    console.print()

    daemon.write_pidfile()
    try:
        daemon.run(
            api_port=port,
            proxy_port=proxy_port,
            host=host,
            target=target,
            redact=redact,
            block=block,
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down...[/yellow]")
    finally:
        daemon.remove_pidfile()


@main.command()
def stop() -> None:
    """Stop the wiretaps daemon."""
    from wiretaps import daemon

    running, pid = daemon.is_running()
    if not running:
        console.print("[dim]No daemon running.[/dim]")
        return

    try:
        os.kill(pid, signal.SIGTERM)  # type: ignore[arg-type]
        console.print(f"[green]Stopped daemon (PID {pid})[/green]")
    except OSError as e:
        console.print(f"[red]Failed to stop daemon: {e}[/red]")
    finally:
        daemon.remove_pidfile()


@main.command()
def status() -> None:
    """Show daemon status."""
    from wiretaps import daemon

    running, pid = daemon.is_running()
    if running:
        console.print(f"[green]Daemon running[/green] (PID {pid})")
    else:
        console.print("[dim]Daemon not running.[/dim]")


# ---------------------------------------------------------------------------
# Session commands
# ---------------------------------------------------------------------------


@main.group()
def session() -> None:
    """Manage monitoring sessions."""
    pass


@session.command("new")
@click.option("--agent", "-a", required=True, help="Agent name")
def session_new(agent: str) -> None:
    """Create a new session and print the session ID."""
    from wiretaps.storage import Storage

    storage = Storage()
    agent_obj = storage.get_or_create_agent(agent)
    sess = storage.create_session(agent_id=agent_obj.id, pid=os.getpid())
    console.print(sess.id)


@main.command("run")
@click.option("--agent", "-a", required=True, help="Agent name")
@click.argument("cmd", nargs=-1, required=True)
def run_cmd(agent: str, cmd: tuple) -> None:
    """Create a session and run a command with wiretaps env vars."""
    import subprocess

    from wiretaps.storage import Storage

    storage = Storage()
    agent_obj = storage.get_or_create_agent(agent)
    sess = storage.create_session(agent_id=agent_obj.id, pid=os.getpid())

    console.print(f"[dim]Session: {sess.id}[/dim]")
    console.print(f"[dim]Agent:   {agent_obj.name}[/dim]")
    console.print()

    env = os.environ.copy()
    env["WIRETAPS_SESSION_ID"] = sess.id

    # Add interceptor to PYTHONPATH for sitecustomize
    interceptors_dir = str(Path(__file__).parent / "interceptors")
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{interceptors_dir}:{existing_pythonpath}" if existing_pythonpath else interceptors_dir

    try:
        result = subprocess.run(list(cmd), env=env)
        sys.exit(result.returncode)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
    finally:
        from datetime import datetime
        storage.update_session(sess.id, ended_at=datetime.now().isoformat())


@main.command("sessions")
@click.option("--limit", "-n", default=20, help="Number of sessions to show")
@click.option("--agent", "-a", help="Filter by agent name")
def sessions_list(limit: int, agent: str | None) -> None:
    """List recent sessions."""
    from rich.table import Table

    from wiretaps.storage import Storage

    storage = Storage()
    agent_id = None
    if agent:
        agent_obj = storage.get_agent_by_name(agent)
        if not agent_obj:
            console.print(f"[red]Agent '{agent}' not found[/red]")
            return
        agent_id = agent_obj.id

    sessions = storage.list_sessions(agent_id=agent_id, limit=limit)
    if not sessions:
        console.print("[dim]No sessions found.[/dim]")
        return

    # Build agent name lookup
    agents = {a.id: a.name for a in storage.list_agents()}

    table = Table(title="Sessions")
    table.add_column("ID", style="dim", max_width=36)
    table.add_column("Agent")
    table.add_column("Started")
    table.add_column("Ended")
    table.add_column("PID", justify="right")

    for s in sessions:
        table.add_row(
            s.id[:12] + "...",
            agents.get(s.agent_id, "?"),
            s.started_at[:19],
            (s.ended_at or "running")[:19],
            str(s.pid or ""),
        )

    console.print(table)


@main.command("events")
@click.option("--session", "-s", "session_id", help="Filter by session ID")
@click.option("--type", "-t", "event_type", type=click.Choice(["llm_call", "shell_cmd", "http_request"]), help="Filter by type")
@click.option("--limit", "-n", default=50, help="Number of events to show")
def events_list(session_id: str | None, event_type: str | None, limit: int) -> None:
    """List captured events."""
    from rich.table import Table

    from wiretaps.storage import Storage

    storage = Storage()
    events = storage.list_events(session_id=session_id, event_type=event_type, limit=limit)

    if not events:
        console.print("[dim]No events found.[/dim]")
        return

    table = Table(title="Events")
    table.add_column("ID", justify="right")
    table.add_column("Type")
    table.add_column("Timestamp", style="dim")
    table.add_column("Duration", justify="right")
    table.add_column("PII")
    table.add_column("Status", justify="right")

    for e in events:
        pii_text = "[green]clean[/green]" if not e.pii_types else f"[red]{', '.join(e.pii_types)}[/red]"
        table.add_row(
            str(e.id),
            e.type,
            e.timestamp[:19],
            f"{e.duration_ms}ms",
            pii_text,
            str(e.status),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Legacy v1 commands (preserved for backward compat)
# ---------------------------------------------------------------------------


@main.command()
@click.option("--limit", "-n", default=50, help="Number of entries to show")
@click.option("--pii-only", is_flag=True, help="Show only entries with PII detected")
@click.option("--api-key", help="Filter by API key")
def logs(limit: int, pii_only: bool, api_key: str | None) -> None:
    """View recent log entries."""
    from rich.table import Table

    from wiretaps.storage import Storage

    storage = Storage()
    entries = storage.get_logs(limit=limit, pii_only=pii_only, api_key=api_key)

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
                pii_status = "[cyan]" + ", ".join(entry.pii_types) + "[/cyan]"
            else:
                pii_status = "[red]" + ", ".join(entry.pii_types) + "[/red]"
        else:
            pii_status = "[green]clean[/green]"
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

    safe_limit = None
    if limit is not None:
        safe_limit = min(limit, 1_000_000)
    elif limit is None:
        safe_limit = 100_000
        console.print(f"[dim]No limit specified, using safe default: {safe_limit:,} entries[/dim]")

    if output_format == "json":
        count = storage.export_json(
            output,
            limit=safe_limit,
            pii_only=pii_only,
            start_time=start_time,
            end_time=end_time,
        )
    else:
        count = storage.export_csv(
            output,
            limit=safe_limit,
            pii_only=pii_only,
            start_time=start_time,
            end_time=end_time,
        )

    console.print(f"[green]Exported {count} entries to {output}[/green]")


@main.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--by-day", is_flag=True, help="Show stats by day")
@click.option("--by-hour", is_flag=True, help="Show stats by hour")
@click.option("--api-key", help="Filter by API key")
def stats(as_json: bool, by_day: bool, by_hour: bool, api_key: str | None) -> None:
    """Show usage statistics."""
    import json

    from rich.table import Table

    from wiretaps.storage import Storage

    storage = Storage()

    if by_day:
        data = storage.get_stats_by_day(api_key=api_key)
        if as_json:
            console.print(json.dumps(data, indent=2))
            return

        table = Table(title="Stats by Day")
        table.add_column("Day", style="cyan")
        table.add_column("Requests", justify="right")
        table.add_column("Tokens", justify="right")
        table.add_column("PII Detections", justify="right", style="yellow")
        table.add_column("Blocked", justify="right", style="red")

        for row in data:
            table.add_row(
                row["day"],
                str(row["requests"]),
                f"{row['tokens']:,}",
                str(row["pii_detections"]),
                str(row["blocked"]),
            )
        console.print(table)
        return

    if by_hour:
        data = storage.get_stats_by_hour(api_key=api_key)
        if as_json:
            console.print(json.dumps(data, indent=2))
            return

        table = Table(title="Stats by Hour")
        table.add_column("Hour", style="cyan")
        table.add_column("Requests", justify="right")
        table.add_column("Tokens", justify="right")
        table.add_column("PII Detections", justify="right", style="yellow")
        table.add_column("Blocked", justify="right", style="red")

        for row in data:
            table.add_row(
                row["hour"],
                str(row["requests"]),
                f"{row['tokens']:,}",
                str(row["pii_detections"]),
                str(row["blocked"]),
            )
        console.print(table)
        return

    # Default: overall stats
    overall = storage.get_stats(api_key=api_key)
    top_pii = storage.get_top_pii_types(limit=5, api_key=api_key)

    if as_json:
        output = {
            "overall": overall,
            "top_pii_types": top_pii,
        }
        console.print(json.dumps(output, indent=2))
        return

    console.print(f"\n[bold cyan]wiretaps Statistics[/bold cyan]\n")

    console.print(f"  [bold]Total Requests:[/bold] {overall['total_requests']:,}")
    console.print(f"  [bold]Total Tokens:[/bold] {overall['total_tokens']:,}")
    console.print()

    pii_color = "red" if overall["pii_percentage"] > 10 else "yellow" if overall["pii_percentage"] > 0 else "green"
    console.print(f"  [bold]PII Detections:[/bold] [{pii_color}]{overall['requests_with_pii']:,}[/{pii_color}] ({overall['pii_percentage']}%)")
    console.print(f"  [bold]Blocked:[/bold] [red]{overall['blocked_requests']:,}[/red]")
    console.print(f"  [bold]Redacted:[/bold] [cyan]{overall['redacted_requests']:,}[/cyan]")
    console.print(f"  [bold]Errors:[/bold] {overall['errors']:,}")

    if top_pii:
        console.print("\n[bold]Top PII Types:[/bold]")
        for item in top_pii:
            console.print(f"  - {item['type']}: {item['count']}")

    console.print()


@main.command()
def init() -> None:
    """Initialize wiretaps configuration."""
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

api:
  host: 127.0.0.1
  port: 8899

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
  allowlist:
    # - type: email
    #   value: "myemail@company.com"
    # - type: email
    #   pattern: ".*@mycompany\\\\.com"
    # - type: phone
    #   value: "+5511999999999"

  # Custom patterns to detect (in addition to built-in)
  custom: []

# Webhook for alerts (optional)
# alerts:
#   webhook: https://your-server.com/alerts
"""

    config_file.write_text(default_config)
    console.print(f"[green]Created config:[/green] {config_file}")


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
        console.print("[green]No PII detected[/green]")
        return

    console.print("[red]PII Detected:[/red]")
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
    if "allowlist" not in config["pii"] or config["pii"]["allowlist"] is None:
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

        console.print(f"[green]Added rule:[/green] {new_rule}")

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
            console.print(f"[green]Removed {removed} rule(s)[/green]")
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
            console.print("[green]Allowlist cleared[/green]")


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
    if "custom" not in config["pii"] or config["pii"]["custom"] is None:
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

        try:
            re.compile(regex)
        except re.error as e:
            console.print(f"[red]Invalid regex pattern: {e}[/red]")
            return

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

        console.print(f"[green]Added custom pattern:[/green] {name} (severity: {severity})")

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
            console.print(f"[green]Removed pattern: {name}[/green]")
        else:
            console.print(f"[yellow]No pattern found with name '{name}'[/yellow]")


if __name__ == "__main__":
    main()
