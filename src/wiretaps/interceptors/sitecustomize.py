"""
Shell command interceptor for wiretaps.

Monkey-patches subprocess and os functions to capture shell commands
executed by AI agents. Only activates when WIRETAPS_SESSION_ID is set.

Sends captured events to the wiretaps daemon via fire-and-forget HTTP.
NEVER blocks the host process.

Usage:
    export WIRETAPS_SESSION_ID=<uuid>
    export PYTHONPATH=/path/to/wiretaps/src/wiretaps/interceptors:$PYTHONPATH
    python your_agent.py
"""

import functools
import os
import subprocess
import threading
import time
from datetime import datetime
from urllib.error import URLError
from urllib.request import Request, urlopen

_SESSION_ID = os.environ.get("WIRETAPS_SESSION_ID")
_WIRETAPS_URL = os.environ.get("WIRETAPS_URL", "http://127.0.0.1:8899")
_ENABLED = bool(_SESSION_ID)

# Original functions (saved before patching)
_original_subprocess_run = subprocess.run
_original_popen_init = subprocess.Popen.__init__
_original_os_system = os.system
_original_os_popen = os.popen


def _send_event(data: dict) -> None:
    """Fire-and-forget: send event to wiretaps daemon in a daemon thread."""
    import json

    def _post() -> None:
        try:
            payload = json.dumps(data).encode("utf-8")
            req = Request(
                f"{_WIRETAPS_URL}/events/ingest",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urlopen(req, timeout=2)
        except (URLError, OSError, Exception):
            pass  # Never block host process

    t = threading.Thread(target=_post, daemon=True)
    t.start()


def _build_event(
    command: str | list,
    stdout: str | None = None,
    stderr: str | None = None,
    exit_code: int | None = None,
    cwd: str | None = None,
    duration_ms: int = 0,
) -> dict:
    """Build a shell_cmd event payload."""
    if isinstance(command, list):
        args = command[1:] if len(command) > 1 else []
        cmd = command[0] if command else ""
    else:
        args = []
        cmd = str(command)

    return {
        "session_id": _SESSION_ID,
        "type": "shell_cmd",
        "timestamp": datetime.now().isoformat(),
        "duration_ms": duration_ms,
        "data": {
            "command": cmd,
            "args": args,
            "stdout": (stdout or "")[:10000],  # Truncate large outputs
            "stderr": (stderr or "")[:10000],
            "exit_code": exit_code,
            "cwd": cwd or os.getcwd(),
        },
        "pii_types": [],
        "status": exit_code or 0,
        "error": stderr[:500] if stderr and exit_code else None,
    }


def _patched_subprocess_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess:
    """Patched subprocess.run that captures command execution."""
    start = time.monotonic()
    result = _original_subprocess_run(*args, **kwargs)
    duration_ms = int((time.monotonic() - start) * 1000)

    cmd = args[0] if args else kwargs.get("args", "")

    stdout_text = None
    stderr_text = None
    if result.stdout is not None:
        stdout_text = result.stdout if isinstance(result.stdout, str) else result.stdout.decode("utf-8", errors="replace")
    if result.stderr is not None:
        stderr_text = result.stderr if isinstance(result.stderr, str) else result.stderr.decode("utf-8", errors="replace")

    event = _build_event(
        command=cmd,
        stdout=stdout_text,
        stderr=stderr_text,
        exit_code=result.returncode,
        cwd=kwargs.get("cwd"),
        duration_ms=duration_ms,
    )
    _send_event(event)
    return result


def _patched_popen_init(self: subprocess.Popen, *args: object, **kwargs: object) -> None:  # type: ignore[type-arg]
    """Patched Popen.__init__ that captures command start."""
    _original_popen_init(self, *args, **kwargs)

    cmd = args[0] if args else kwargs.get("args", "")
    event = _build_event(
        command=cmd,
        cwd=kwargs.get("cwd"),
    )
    _send_event(event)


def _patched_os_system(command: str) -> int:
    """Patched os.system that captures command execution."""
    start = time.monotonic()
    result = _original_os_system(command)
    duration_ms = int((time.monotonic() - start) * 1000)

    event = _build_event(
        command=command,
        exit_code=result,
        duration_ms=duration_ms,
    )
    _send_event(event)
    return result


def _patched_os_popen(cmd: str, mode: str = "r", buffering: int = -1) -> object:
    """Patched os.popen that captures command execution."""
    event = _build_event(command=cmd)
    _send_event(event)
    return _original_os_popen(cmd, mode, buffering)


def install() -> None:
    """Install monkey patches. Idempotent."""
    if not _ENABLED:
        return
    subprocess.run = _patched_subprocess_run  # type: ignore[assignment]
    subprocess.Popen.__init__ = _patched_popen_init  # type: ignore[assignment]
    os.system = _patched_os_system  # type: ignore[assignment]
    os.popen = _patched_os_popen  # type: ignore[assignment]


def uninstall() -> None:
    """Restore original functions."""
    subprocess.run = _original_subprocess_run
    subprocess.Popen.__init__ = _original_popen_init  # type: ignore[assignment]
    os.system = _original_os_system
    os.popen = _original_os_popen  # type: ignore[assignment]


# Auto-install when imported (sitecustomize behavior)
if _ENABLED:
    install()
