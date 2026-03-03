"""
Daemon process for wiretaps.

Runs both the FastAPI REST API and the MitM proxy in a single process.
"""

import asyncio
import signal
import sys
from pathlib import Path

import yaml


def load_config() -> dict:
    """Load configuration from ~/.wiretaps/config.yaml if it exists."""
    config_file = Path.home() / ".wiretaps" / "config.yaml"
    if config_file.exists():
        try:
            with open(config_file) as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError:
            return {}
    return {}


def run(
    api_port: int = 8899,
    proxy_port: int = 8080,
    host: str = "127.0.0.1",
    target: str = "https://api.openai.com",
    redact: bool = False,
    block: bool = False,
) -> None:
    """Start the wiretaps daemon (API + proxy)."""
    import uvicorn

    from wiretaps.api.app import create_app
    from wiretaps.proxy import WiretapsProxy
    from wiretaps.storage import Storage

    config = load_config()
    pii_config = config.get("pii", {})
    alerts_config = config.get("alerts", {})

    storage = Storage()
    app = create_app(storage=storage)

    proxy = WiretapsProxy(
        host=host,
        port=proxy_port,
        target=target,
        redact_mode=redact,
        block_mode=block,
        storage=storage,
        allowlist=pii_config.get("allowlist", []),
        custom_patterns=pii_config.get("custom", []),
        webhook_url=alerts_config.get("webhook"),
        webhook_events=alerts_config.get("on", ["pii_detected", "blocked"]),
    )

    async def _run_all() -> None:
        # Start proxy
        proxy_runner = await proxy.start_background()

        # Start uvicorn
        uvi_config = uvicorn.Config(app, host=host, port=api_port, log_level="warning")
        server = uvicorn.Server(uvi_config)

        loop = asyncio.get_event_loop()
        stop_event = asyncio.Event()

        def _signal_handler() -> None:
            stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _signal_handler)

        server_task = asyncio.create_task(server.serve())

        # Wait for stop signal
        await stop_event.wait()

        # Graceful shutdown
        server.should_exit = True
        await server_task
        await proxy.stop_background(proxy_runner)

    asyncio.run(_run_all())


def write_pidfile() -> None:
    """Write PID to ~/.wiretaps/daemon.pid."""
    import os

    pid_dir = Path.home() / ".wiretaps"
    pid_dir.mkdir(parents=True, exist_ok=True)
    (pid_dir / "daemon.pid").write_text(str(os.getpid()))


def read_pidfile() -> int | None:
    """Read PID from pidfile, return None if not found."""
    pid_file = Path.home() / ".wiretaps" / "daemon.pid"
    if pid_file.exists():
        try:
            return int(pid_file.read_text().strip())
        except (ValueError, OSError):
            return None
    return None


def remove_pidfile() -> None:
    """Remove pidfile."""
    pid_file = Path.home() / ".wiretaps" / "daemon.pid"
    pid_file.unlink(missing_ok=True)


def is_running() -> tuple[bool, int | None]:
    """Check if daemon is running. Returns (is_running, pid)."""
    import os

    pid = read_pidfile()
    if pid is None:
        return False, None
    try:
        os.kill(pid, 0)
        return True, pid
    except OSError:
        remove_pidfile()
        return False, None
