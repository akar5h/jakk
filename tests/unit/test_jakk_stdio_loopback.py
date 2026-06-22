"""Localhost-trust handling + stdio transport.

Localhost-trust: an auth "accept" over loopback is ambiguous (server may trust
localhost for dev), so it downgrades to `suggestive`, not `vulnerable`.

stdio: jakk can scan a spawned stdio server directly (no bridge); auth probes
are N/A and skipped.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import jakk.scanner as scanner
from jakk.library import load_library
from jakk.mcp_client import ToolDescriptor
from jakk.scanner import ScanConfig, _is_loopback_endpoint, _run_auth_case, run_scan

_LIBRARY = Path(__file__).resolve().parents[2] / "library" / "mcp"


def _auth_none_case():
    return next(
        c for c in load_library(_LIBRARY)
        if c.surface == "auth" and c.auth_override is not None and c.auth_override.mode == "none"
    )


def _accepting_client():
    """Fake client where the (bad-auth) handshake SUCCEEDS — i.e. the server
    accepted the connection."""
    class _C:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def list_tools(self):
            return [ToolDescriptor(name="t")]

    return _C


# ---------------------------------------------------------------------------
# Localhost-trust
# ---------------------------------------------------------------------------

def test_is_loopback_endpoint():
    for ep in ("http://127.0.0.1:8000/mcp", "http://localhost/mcp",
               "http://0.0.0.0:9/mcp", "http://[::1]:8/mcp/"):
        assert _is_loopback_endpoint(ep) is True, ep
    for ep in ("https://api.example.com/mcp", "http://10.0.0.5/mcp", "stdio:uvx x", None, ""):
        assert _is_loopback_endpoint(ep) is False, ep


def test_loopback_auth_accept_downgraded_to_suggestive(monkeypatch):
    monkeypatch.setattr(scanner, "MCPClient", _accepting_client())
    f = asyncio.run(_run_auth_case(_auth_none_case(), ScanConfig(endpoint="http://127.0.0.1:8000/mcp")))
    assert f.outcome == "suggestive"
    assert f.fired is False
    assert "loopback" in f.evidence.lower()


def test_remote_auth_accept_stays_vulnerable(monkeypatch):
    monkeypatch.setattr(scanner, "MCPClient", _accepting_client())
    f = asyncio.run(_run_auth_case(_auth_none_case(), ScanConfig(endpoint="https://api.example.com/mcp")))
    assert f.outcome == "vulnerable"
    assert f.fired is True


# ---------------------------------------------------------------------------
# stdio transport
# ---------------------------------------------------------------------------

def test_stdio_command_accepted_by_client():
    from jakk.mcp_client import MCPClient
    c = MCPClient(stdio_command="echo hi")
    assert c.stdio_command == "echo hi"
    assert c.endpoint is None  # endpoint optional in stdio mode


def test_stdio_scan_skips_auth_probes(monkeypatch):
    class _C:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def list_tools(self):
            return []

    monkeypatch.setattr(scanner, "MCPClient", _C)
    cases = [c for c in load_library(_LIBRARY) if c.surface in ("auth", "tool_call")]
    cfg = ScanConfig(endpoint="stdio:uvx x", stdio_command="uvx x")
    findings = asyncio.run(run_scan(cases, cfg))
    auth = [f for f in findings if f.test_id.startswith("mcp.auth.")]
    assert auth, "should have auth findings"
    assert all(f.outcome == "skipped" and "stdio" in (f.evidence or "").lower() for f in auth)


def test_http_scan_still_runs_auth(monkeypatch):
    """Regression: non-stdio scan still runs auth probes (not skipped)."""
    monkeypatch.setattr(scanner, "MCPClient", _accepting_client())
    cases = [c for c in load_library(_LIBRARY) if c.surface == "auth"]
    cfg = ScanConfig(endpoint="https://api.example.com/mcp")
    findings = asyncio.run(run_scan(cases, cfg))
    assert any(f.outcome == "vulnerable" for f in findings)  # ran, not skipped
