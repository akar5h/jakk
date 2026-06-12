"""Resilient shared client: a mid-scan transport drop must trigger a bounded
reconnect-and-retry, not void every remaining probe.

Surfaced by the 2026-06-12 benchmark: the supergateway bridge crashed mid-scan
on Python-FastMCP servers, and jakk's shared client then failed every remaining
call with `Client is not connected` → a flood of transport errors.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import jakk.scanner as scanner
from jakk.library import filter_cases, load_library
from jakk.mcp_client import CallResult, ToolDescriptor
from jakk.scanner import (
    ScanConfig,
    _MAX_RECONNECTS,
    _has_transport_drop,
    run_scan,
)

_LIBRARY = Path(__file__).resolve().parents[2] / "library" / "mcp"


def _tool_surface_cases():
    # Exclude auth/authz (own clients) so every case flows through the shared
    # client + _run_case path that the reconnect logic guards.
    return filter_cases(load_library(_LIBRARY), exclude_surfaces=["auth", "authz"])


def _make_factory(behaviors: list[str]):
    """Factory of fake MCPClients. ``behaviors`` is consumed one entry per
    client instance created (initial + each reconnect); the last entry repeats.
    Kinds: 'ok' (calls succeed), 'drop' (calls transport-error),
    'fail_connect' (__aenter__ raises)."""
    state = {"n": 0, "clients": []}

    class _FakeClient:
        def __init__(self, *a, **k):
            self.kind = behaviors[min(state["n"], len(behaviors) - 1)]
            state["n"] += 1
            state["clients"].append(self)

        async def __aenter__(self):
            if self.kind == "fail_connect":
                raise ConnectionRefusedError("All connection attempts failed")
            return self

        async def __aexit__(self, *a):
            return False

        async def list_tools(self):
            # A no-required-arg read tool so response.* probes match.
            return [ToolDescriptor(name="read_data", input_schema={"properties": {"q": {"type": "string"}}})]

        async def call_tool(self, name, args):
            if self.kind == "drop":
                return CallResult(
                    text="<call_tool error: RuntimeError: Client is not connected>",
                    is_error=True,
                    transport_error=True,
                )
            return CallResult(text="clean output", is_error=False)

    return _FakeClient, state


def test_has_transport_drop_helper():
    from jakk.findings import Finding

    drop = Finding(test_id="x", expected_signal="s", severity="high", surface="tool_call",
                   endpoint="e", fired=False, outcome="error", error="transport error: tool call did not complete")
    clean = Finding(test_id="y", expected_signal="s", severity="high", surface="tool_call",
                    endpoint="e", fired=False, outcome="pass")
    assert _has_transport_drop([clean, drop]) is True
    assert _has_transport_drop([clean]) is False


def test_transient_drop_reconnects_and_recovers(monkeypatch):
    """First client drops every call; reconnect to a healthy client → scan
    completes, no lingering transport errors."""
    factory, state = _make_factory(["drop", "ok"])
    monkeypatch.setattr(scanner, "MCPClient", factory)
    findings = asyncio.run(run_scan(_tool_surface_cases(), ScanConfig(endpoint="http://x/mcp")))
    assert state["n"] >= 2, "should have reconnected at least once"
    assert findings, "scan produced findings"
    assert not any(
        f.error and "transport" in f.error.lower() for f in findings
    ), "no transport errors should survive after recovery"


def test_hard_drop_then_failed_reconnect_marks_remaining_error(monkeypatch):
    """Client drops, reconnect can't re-handshake (endpoint gone) → remaining
    probes marked error, scan returns without crashing."""
    factory, state = _make_factory(["drop", "fail_connect"])
    monkeypatch.setattr(scanner, "MCPClient", factory)
    findings = asyncio.run(run_scan(_tool_surface_cases(), ScanConfig(endpoint="http://x/mcp")))
    assert state["n"] == 2
    assert any(f.outcome == "error" for f in findings)
    assert any("reconnect failed" in (f.evidence or "") for f in findings)


def test_reconnect_is_bounded(monkeypatch):
    """A server that drops on every call (even after reconnect) must stop after
    _MAX_RECONNECTS — no infinite loop."""
    factory, state = _make_factory(["drop"])  # every client drops
    monkeypatch.setattr(scanner, "MCPClient", factory)
    findings = asyncio.run(run_scan(_tool_surface_cases(), ScanConfig(endpoint="http://x/mcp")))
    # initial client + exactly _MAX_RECONNECTS reconnects, then give up
    assert state["n"] == _MAX_RECONNECTS + 1
    assert any(f.outcome == "error" for f in findings)


def test_healthy_path_no_reconnect(monkeypatch):
    """Regression: a healthy server runs all probes with no reconnect."""
    factory, state = _make_factory(["ok"])
    monkeypatch.setattr(scanner, "MCPClient", factory)
    findings = asyncio.run(run_scan(_tool_surface_cases(), ScanConfig(endpoint="http://x/mcp")))
    assert state["n"] == 1, "no reconnect on a healthy server"
    assert findings
    assert not any(f.error and "transport" in f.error.lower() for f in findings)
