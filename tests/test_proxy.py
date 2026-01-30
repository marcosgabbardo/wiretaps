"""Tests for proxy server functionality."""

import json

import pytest
from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase

from wiretaps.proxy import WiretapsProxy


class TestBlockMode:
    """Tests for block mode functionality."""

    def test_proxy_config_has_block_mode(self):
        """Test that proxy config includes block_mode."""
        proxy = WiretapsProxy(block_mode=True)
        assert proxy.config.block_mode is True

    def test_proxy_config_default_block_mode(self):
        """Test that block_mode defaults to False."""
        proxy = WiretapsProxy()
        assert proxy.config.block_mode is False


class TestProxyInit:
    """Tests for proxy initialization."""

    def test_proxy_default_values(self):
        """Test proxy initializes with default values."""
        proxy = WiretapsProxy()
        assert proxy.config.host == "127.0.0.1"
        assert proxy.config.port == 8080
        assert proxy.config.target == "https://api.openai.com"
        assert proxy.config.redact_mode is False
        assert proxy.config.block_mode is False

    def test_proxy_custom_values(self):
        """Test proxy accepts custom values."""
        proxy = WiretapsProxy(
            host="0.0.0.0",
            port=9090,
            target="https://api.anthropic.com",
            redact_mode=True,
            block_mode=False,
        )
        assert proxy.config.host == "0.0.0.0"
        assert proxy.config.port == 9090
        assert proxy.config.target == "https://api.anthropic.com"
        assert proxy.config.redact_mode is True

    def test_proxy_with_allowlist(self):
        """Test proxy accepts allowlist."""
        allowlist = [{"type": "email", "value": "test@example.com"}]
        proxy = WiretapsProxy(allowlist=allowlist)
        assert proxy.pii_detector is not None
        assert len(proxy.pii_detector.allowlist) == 1

    def test_proxy_webhook_config(self):
        """Test proxy accepts webhook configuration."""
        proxy = WiretapsProxy(
            webhook_url="https://hooks.example.com/webhook",
            webhook_events=["blocked"],
        )
        assert proxy.webhook_url == "https://hooks.example.com/webhook"
        assert proxy.webhook_events == ["blocked"]

    def test_proxy_default_webhook_events(self):
        """Test proxy has default webhook events."""
        proxy = WiretapsProxy(webhook_url="https://hooks.example.com/webhook")
        assert "pii_detected" in proxy.webhook_events
        assert "blocked" in proxy.webhook_events


class TestBlockModeResponse:
    """Tests for block mode response format."""

    def test_block_response_format(self):
        """Test that block response has correct format."""
        # The expected response when PII is blocked
        expected_keys = {"error", "pii_types"}
        response = {"error": "Request blocked: PII detected", "pii_types": ["email"]}
        assert set(response.keys()) == expected_keys
        assert response["error"] == "Request blocked: PII detected"
        assert isinstance(response["pii_types"], list)


class TestWebhookConfig:
    """Tests for webhook configuration."""

    def test_webhook_payload_format(self):
        """Test webhook payload has correct format."""
        from datetime import datetime

        # Expected payload format
        payload = {
            "timestamp": datetime.now().isoformat(),
            "endpoint": "/v1/chat/completions",
            "pii_types": ["email", "phone"],
            "redacted": True,
            "blocked": False,
        }

        assert "timestamp" in payload
        assert "endpoint" in payload
        assert "pii_types" in payload
        assert "redacted" in payload
        assert "blocked" in payload

    def test_webhook_events_filter(self):
        """Test webhook events filter works."""
        proxy = WiretapsProxy(
            webhook_url="https://hooks.example.com/webhook",
            webhook_events=["blocked"],  # Only blocked events
        )

        # pii_detected not in events
        assert "pii_detected" not in proxy.webhook_events
        assert "blocked" in proxy.webhook_events

    def test_webhook_default_events(self):
        """Test default webhook events include both types."""
        proxy = WiretapsProxy(
            webhook_url="https://hooks.example.com/webhook",
        )

        assert "pii_detected" in proxy.webhook_events
        assert "blocked" in proxy.webhook_events


class TestCustomPatterns:
    """Tests for custom patterns in proxy."""

    def test_proxy_with_custom_patterns(self):
        """Test proxy accepts custom patterns."""
        custom_patterns = [
            {"name": "internal_id", "regex": "INT-[0-9]{6}", "severity": "high"}
        ]
        proxy = WiretapsProxy(custom_patterns=custom_patterns)
        assert proxy.pii_detector is not None

        # Verify custom pattern is loaded
        matches = proxy.pii_detector.scan("Document INT-123456")
        internal_ids = [m for m in matches if m.pattern_name == "internal_id"]
        assert len(internal_ids) == 1
