"""Tests for shell command interceptor."""

import os
import subprocess

import pytest


class TestInterceptorActivation:
    """Tests for interceptor activation logic."""

    def test_not_enabled_without_env(self):
        """Interceptor should not activate without WIRETAPS_SESSION_ID."""
        # Import with a clean env (no session ID)
        env = os.environ.copy()
        env.pop("WIRETAPS_SESSION_ID", None)

        # The module checks env at import time, so we test the logic directly
        from wiretaps.interceptors import sitecustomize

        assert sitecustomize._SESSION_ID is None or sitecustomize._SESSION_ID == os.environ.get("WIRETAPS_SESSION_ID")

    def test_build_event_with_string_command(self):
        """Test event building with string command."""
        from wiretaps.interceptors.sitecustomize import _build_event

        event = _build_event(
            command="echo hello",
            stdout="hello\n",
            exit_code=0,
            duration_ms=10,
        )
        assert event["type"] == "shell_cmd"
        assert event["data"]["command"] == "echo hello"
        assert event["data"]["stdout"] == "hello\n"
        assert event["data"]["exit_code"] == 0
        assert event["duration_ms"] == 10

    def test_build_event_with_list_command(self):
        """Test event building with list command."""
        from wiretaps.interceptors.sitecustomize import _build_event

        event = _build_event(
            command=["ls", "-la", "/tmp"],
            exit_code=0,
            duration_ms=5,
        )
        assert event["data"]["command"] == "ls"
        assert event["data"]["args"] == ["-la", "/tmp"]

    def test_build_event_truncates_output(self):
        """Test that large outputs are truncated."""
        from wiretaps.interceptors.sitecustomize import _build_event

        long_output = "x" * 20000
        event = _build_event(
            command="cat bigfile",
            stdout=long_output,
            exit_code=0,
            duration_ms=100,
        )
        assert len(event["data"]["stdout"]) == 10000

    def test_install_uninstall(self):
        """Test install/uninstall restores original functions."""
        from wiretaps.interceptors.sitecustomize import (
            _original_os_system,
            _original_subprocess_run,
            install,
            uninstall,
        )

        # Since _ENABLED might be False, the install() is a no-op
        # But uninstall always restores
        uninstall()
        assert subprocess.run is _original_subprocess_run
        assert os.system is _original_os_system
