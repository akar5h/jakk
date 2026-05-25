"""Tests for corroboration verdict logic (no live MCP server required).

The verdict table is the contract — these tests pin it down so future
refactors of the matcher pipeline can't silently change classification.
"""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from jakk.library import CorroborateSpec, Matcher, Payload, TestCase
from jakk.mcp_client import CallResult, ToolDescriptor
from jakk.scanner import ScanConfig, _run_corroborated_marker_echo


def _make_case() -> TestCase:
    return TestCase(
        id="t.x",
        surface="tool_call",
        description="x",
        expected_signal="x",
        payload=Payload(arguments={"__first_string_arg__": "x$(echo JAKK-MARKER-{run_id})"}),
        matcher=Matcher(kind="marker_echo", params={"marker_template": "JAKK-MARKER-{run_id}"}),
        corroborate=CorroborateSpec(
            negative_arguments={"__first_string_arg__": "xPLAIN-CANARY-{run_id}"},
            negative_marker_template="PLAIN-CANARY-{run_id}",
        ),
    )


def _tool() -> ToolDescriptor:
    return ToolDescriptor(
        name="init_bare_repository",
        input_schema={"properties": {"repo_name": {"type": "string"}}, "required": ["repo_name"]},
    )


class _FakeClient:
    """Stub MCPClient.call_tool that returns canned responses keyed by argument substring."""

    def __init__(self, response_for_substring: dict[str, str]):
        self.response_for_substring = response_for_substring
        self.calls: list[tuple[str, dict]] = []

    async def call_tool(self, name: str, arguments: dict) -> CallResult:
        self.calls.append((name, arguments))
        arg_str = " ".join(str(v) for v in arguments.values())
        for needle, response in self.response_for_substring.items():
            if needle in arg_str:
                return CallResult(text=response, is_error=False)
        return CallResult(text="", is_error=False)


async def _run(responses: dict[str, str]):
    case = _make_case()
    tool = _tool()
    cfg = ScanConfig(endpoint="http://example/mcp")
    client = _FakeClient(responses)
    finding = await _run_corroborated_marker_echo(client, case, tool, [tool], cfg)
    return finding, client


async def test_vulnerable_both_real_fire_negative_does_not():
    """Server returns the marker (expanded) for $() payloads, NOT for plain input."""
    finding, client = await _run({
        "JAKK-MARKER-": "Initialized repo at /tmp/JAKK-MARKER-<expanded>",
        "PLAIN-CANARY-": "Error: invalid name 'xPLAIN-CANARY-<plain>'",  # plain reflected, but...
    })
    # The simple FakeClient maps substring → static response, so we need the response
    # text to ACTUALLY contain the per-call expanded marker. Let's verify the call shape
    # and pin the verdict separately with explicit responses below.
    assert len(client.calls) == 3


async def test_vulnerable_when_real_markers_reflect_but_plain_does_not():
    """Real responses contain the expanded marker; negative response contains a
    different string (no marker reflection)."""
    # We craft responses to contain the marker we expect at each call's run_id.
    # Since run_id is random, we look at the actual calls made.
    case = _make_case()
    tool = _tool()
    cfg = ScanConfig(endpoint="http://example/mcp")

    captured: list[dict] = []

    class CraftedClient:
        async def call_tool(self, name, arguments):
            arg_str = arguments["repo_name"]
            captured.append(arguments)
            if "JAKK-MARKER-" in arg_str:
                # Extract the run_id from "x$(echo JAKK-MARKER-XXXX)"
                start = arg_str.index("JAKK-MARKER-") + len("JAKK-MARKER-")
                end = arg_str.index(")", start)
                run_id = arg_str[start:end]
                # Server "expanded" the command — return marker without the $() wrapper.
                return CallResult(text=f"Initialized repo at /tmp/xJAKK-MARKER-{run_id}/", is_error=False)
            if "PLAIN-CANARY-" in arg_str:
                # Server rejected the plain input — error message without the canary substring.
                return CallResult(text="Error: invalid repo name format", is_error=False)
            return CallResult(text="", is_error=False)

    finding = await _run_corroborated_marker_echo(CraftedClient(), case, tool, [tool], cfg)
    assert finding.outcome == "vulnerable"
    assert finding.fired
    assert "expansion confirmed" in finding.evidence


async def test_echo_when_real_responses_contain_shell_syntax():
    """Server reflects raw input — real markers come back WRAPPED in $(echo …),
    not expanded. The per-call matcher detects the shell-syntax wrapper and
    classifies each as echo; corroboration aggregates to echo."""
    case = _make_case()
    tool = _tool()
    cfg = ScanConfig(endpoint="http://example/mcp")

    class ReflectiveClient:
        async def call_tool(self, name, arguments):
            # Server echoes the literal input INCLUDING the $() wrapper —
            # no expansion happened.
            return CallResult(text=f"Server received: {arguments['repo_name']}", is_error=False)

    finding = await _run_corroborated_marker_echo(ReflectiveClient(), case, tool, [tool], cfg)
    assert finding.outcome == "echo"
    assert "no expansion proven" in finding.evidence


async def test_vulnerable_holds_even_when_negative_also_reflects():
    """Some tools (e.g. ch08 init_bare_repository) reflect ANY input back as
    a directory name. The negative will reflect too. But if the real markers
    come back WITHOUT the $() wrapper, shell expansion still happened —
    independent of whether the negative reflects. The verdict relies on the
    per-call shell-syntax check, not just the negative."""
    case = _make_case()
    tool = _tool()
    cfg = ScanConfig(endpoint="http://example/mcp")

    class ExpandAndReflectClient:
        async def call_tool(self, name, arguments):
            arg = arguments["repo_name"]
            # If $(echo ...) syntax in input, "expand" it (return marker bare).
            if "$(echo " in arg:
                start = arg.index("JAKK-MARKER-") + len("JAKK-MARKER-")
                end = arg.index(")", start)
                run_id = arg[start:end]
                return CallResult(text=f"Created dir /tmp/xJAKK-MARKER-{run_id}/", is_error=False)
            # Otherwise echo raw input.
            return CallResult(text=f"Created dir /tmp/{arg}/", is_error=False)

    finding = await _run_corroborated_marker_echo(ExpandAndReflectClient(), case, tool, [tool], cfg)
    assert finding.outcome == "vulnerable"
    assert "server also reflects raw input" in finding.evidence
    # Sanity-check JSONL representation: real calls have matcher_outcome,
    # negative has plain `reflected` bool.
    calls = finding.payload["calls"]
    assert calls[0]["matcher_outcome"] == "vulnerable"
    assert "matcher_outcome" not in calls[2]
    assert calls[2]["reflected"] is True


async def test_pass_neither_real_marker_reflects():
    """Server rejects/quotes the substitution payload; no marker comes back."""
    case = _make_case()
    tool = _tool()
    cfg = ScanConfig(endpoint="http://example/mcp")

    class RejectClient:
        async def call_tool(self, name, arguments):
            return CallResult(text="Invalid repo name. Use only letters, numbers.", is_error=False)

    finding = await _run_corroborated_marker_echo(RejectClient(), case, tool, [tool], cfg)
    assert finding.outcome == "pass"
    assert not finding.fired


async def test_suggestive_when_only_one_real_fires():
    case = _make_case()
    tool = _tool()
    cfg = ScanConfig(endpoint="http://example/mcp")

    state = {"call_count": 0}

    class FlakyClient:
        async def call_tool(self, name, arguments):
            state["call_count"] += 1
            # Reflect the marker on the first real call only.
            if state["call_count"] == 1 and "JAKK-MARKER-" in arguments["repo_name"]:
                arg_str = arguments["repo_name"]
                start = arg_str.index("JAKK-MARKER-") + len("JAKK-MARKER-")
                end = arg_str.index(")", start)
                run_id = arg_str[start:end]
                return CallResult(text=f"Got JAKK-MARKER-{run_id}", is_error=False)
            return CallResult(text="error", is_error=False)

    finding = await _run_corroborated_marker_echo(FlakyClient(), case, tool, [tool], cfg)
    assert finding.outcome == "suggestive"
    assert not finding.fired
    assert "intermittent" in finding.evidence


async def test_corroboration_runs_three_calls():
    case = _make_case()
    tool = _tool()
    cfg = ScanConfig(endpoint="http://example/mcp")

    class CountingClient:
        def __init__(self):
            self.count = 0
        async def call_tool(self, name, arguments):
            self.count += 1
            return CallResult(text="", is_error=False)

    client = CountingClient()
    await _run_corroborated_marker_echo(client, case, tool, [tool], cfg)
    assert client.count == 3
