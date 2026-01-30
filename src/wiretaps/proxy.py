"""
Core proxy server for wiretaps.

Intercepts requests to LLM APIs, logs them, and forwards to the target.
"""

import asyncio
import json
import time
from dataclasses import dataclass
from datetime import datetime

from aiohttp import ClientSession, ClientTimeout, web

from wiretaps.pii import PIIDetector
from wiretaps.storage import LogEntry, Storage


@dataclass
class ProxyConfig:
    """Proxy configuration."""

    host: str = "127.0.0.1"
    port: int = 8080
    target: str = "https://api.openai.com"
    timeout: int = 120
    pii_detection: bool = True
    redact_mode: bool = False  # If True, redact PII before sending to LLM
    block_mode: bool = False  # If True, block requests containing PII


class WiretapsProxy:
    """Transparent proxy for LLM API requests.

    Intercepts HTTP requests, logs them with PII detection,
    and forwards to the target API.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        target: str = "https://api.openai.com",
        pii_detection: bool = True,
        redact_mode: bool = False,
        block_mode: bool = False,
        allowlist: list[dict] | None = None,
        custom_patterns: list[dict] | None = None,
        webhook_url: str | None = None,
        webhook_events: list[str] | None = None,
    ):
        self.config = ProxyConfig(
            host=host,
            port=port,
            target=target.rstrip("/"),
            pii_detection=pii_detection,
            redact_mode=redact_mode,
            block_mode=block_mode,
        )
        self.webhook_url = webhook_url
        self.webhook_events = webhook_events or ["pii_detected", "blocked"]
        self.storage = Storage()
        self.pii_detector = PIIDetector(
            allowlist=allowlist,
            custom_patterns=custom_patterns,
        ) if pii_detection else None
        self.app = web.Application()
        self._setup_routes()

    def _setup_routes(self) -> None:
        """Setup proxy routes."""
        self.app.router.add_route("*", "/{path:.*}", self._proxy_handler)

    async def _proxy_handler(self, request: web.Request) -> web.Response:
        """Handle incoming requests and proxy to target."""
        start_time = time.time()

        path = request.match_info.get("path", "")
        target_url = f"{self.config.target}/{path}"
        if request.query_string:
            target_url += f"?{request.query_string}"

        # Extract API key from Authorization header
        api_key = self._extract_api_key(request)

        try:
            body = await request.read()
            body_text = body.decode("utf-8") if body else ""
        except Exception:
            body_text = ""

        # Original body for logging
        original_body_text = body_text

        pii_types = []
        redacted_body = None
        if self.pii_detector and body_text:
            pii_types = self.pii_detector.get_pii_types(body_text)

            # Block request if block_mode is enabled and PII was found
            if self.config.block_mode and pii_types:
                duration_ms = int((time.time() - start_time) * 1000)

                # Log the blocked request
                await self._log_request(
                    method=request.method,
                    endpoint=f"/{path}",
                    request_body=original_body_text,
                    response_body=json.dumps({"error": "Request blocked: PII detected", "pii_types": pii_types}),
                    status=400,
                    tokens=0,
                    duration_ms=duration_ms,
                    pii_types=pii_types,
                    blocked=True,
                    api_key=api_key,
                )

                # Send webhook if configured
                await self._send_webhook(
                    endpoint=f"/{path}",
                    pii_types=pii_types,
                    redacted=False,
                    blocked=True,
                )

                return web.Response(
                    text=json.dumps({"error": "Request blocked: PII detected", "pii_types": pii_types}),
                    status=400,
                    content_type="application/json",
                )

            # Redact PII if enabled and PII was found
            if self.config.redact_mode and pii_types:
                redacted_body = self.pii_detector.redact(body_text)
                body_text = redacted_body
                body = body_text.encode("utf-8")

        headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in ("host", "content-length", "transfer-encoding")
        }

        try:
            timeout = ClientTimeout(total=self.config.timeout)
            async with ClientSession(timeout=timeout) as session:
                async with session.request(
                    method=request.method,
                    url=target_url,
                    headers=headers,
                    data=body if body else None,
                ) as resp:
                    response_body = await resp.read()
                    response_headers = {
                        k: v
                        for k, v in resp.headers.items()
                        if k.lower()
                        not in ("content-encoding", "transfer-encoding", "content-length")
                    }

                    tokens = self._estimate_tokens(
                        body_text, response_body.decode("utf-8", errors="ignore")
                    )

                    duration_ms = int((time.time() - start_time) * 1000)

                    # Log original body (not redacted) for audit purposes
                    await self._log_request(
                        method=request.method,
                        endpoint=f"/{path}",
                        request_body=original_body_text,
                        response_body=response_body.decode("utf-8", errors="ignore"),
                        status=resp.status,
                        tokens=tokens,
                        duration_ms=duration_ms,
                        pii_types=pii_types,
                        redacted=redacted_body is not None,
                        api_key=api_key,
                    )

                    # Send webhook if PII was detected (and redacted/passed through)
                    if pii_types:
                        await self._send_webhook(
                            endpoint=f"/{path}",
                            pii_types=pii_types,
                            redacted=redacted_body is not None,
                            blocked=False,
                        )

                    return web.Response(
                        body=response_body,
                        status=resp.status,
                        headers=response_headers,
                    )

        except Exception as e:
            await self._log_request(
                method=request.method,
                endpoint=f"/{path}",
                request_body=body_text,
                response_body=str(e),
                status=500,
                tokens=0,
                duration_ms=int((time.time() - start_time) * 1000),
                pii_types=pii_types,
                error=str(e),
                api_key=api_key,
            )
            return web.Response(
                text=json.dumps({"error": str(e)}),
                status=502,
                content_type="application/json",
            )

    def _extract_api_key(self, request: web.Request) -> str | None:
        """Extract API key from Authorization header."""
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]  # Remove "Bearer " prefix
        return auth_header if auth_header else None

    def _estimate_tokens(self, request: str, response: str) -> int:
        """Rough token estimation (4 chars ≈ 1 token)."""
        try:
            resp_json = json.loads(response)
            if "usage" in resp_json:
                return resp_json["usage"].get("total_tokens", 0)
        except Exception:
            pass
        return (len(request) + len(response)) // 4

    async def _log_request(
        self,
        method: str,
        endpoint: str,
        request_body: str,
        response_body: str,
        status: int,
        tokens: int,
        duration_ms: int,
        pii_types: list,
        error: str | None = None,
        redacted: bool = False,
        blocked: bool = False,
        api_key: str | None = None,
    ) -> None:
        """Log request to storage."""
        entry = LogEntry(
            timestamp=datetime.now(),
            method=method,
            endpoint=endpoint,
            request_body=request_body,
            response_body=response_body,
            status=status,
            tokens=tokens,
            duration_ms=duration_ms,
            pii_types=pii_types,
            error=error,
            redacted=redacted,
            blocked=blocked,
            api_key=api_key,
        )
        self.storage.log(entry)

        if pii_types:
            if blocked:
                pii_status = f"🚫 BLOCKED: {', '.join(pii_types)}"
            elif redacted:
                pii_status = f"🛡️  REDACTED: {', '.join(pii_types)}"
            else:
                pii_status = f"⚠️  PII: {', '.join(pii_types)}"
        else:
            pii_status = "✓"
        print(
            f"{entry.timestamp.strftime('%H:%M:%S')} | {method} {endpoint} | {tokens} tk | {pii_status}"
        )

    async def _send_webhook(
        self,
        endpoint: str,
        pii_types: list[str],
        redacted: bool,
        blocked: bool,
    ) -> None:
        """Send webhook notification if configured."""
        if not self.webhook_url:
            return

        # Check if this event type is enabled
        event_type = "blocked" if blocked else "pii_detected"
        if event_type not in self.webhook_events:
            return

        payload = {
            "timestamp": datetime.now().isoformat(),
            "endpoint": endpoint,
            "pii_types": pii_types,
            "redacted": redacted,
            "blocked": blocked,
        }

        try:
            timeout = ClientTimeout(total=10)
            async with ClientSession(timeout=timeout) as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                ) as resp:
                    if resp.status >= 400:
                        print(f"⚠️  Webhook failed: {resp.status}")
        except Exception as e:
            print(f"⚠️  Webhook error: {e}")

    async def run(self) -> None:
        """Start the proxy server."""
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.config.host, self.config.port)
        await site.start()

        while True:
            await asyncio.sleep(3600)
