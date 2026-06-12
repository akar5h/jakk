"""Tests for scanner-internal helpers (no MCP server required)."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import jakk.scanner as scanner
from jakk.library import load_library
from jakk.matchers import MatcherResult
from jakk.mcp_client import CallResult, ToolDescriptor
from jakk.scanner import (
    ScanConfig,
    _UnresolvedFirstStringArg,
    _UnresolvedTargetArg,
    _UnsatisfiedRequiredArgs,
    _is_transport_failure,
    _resolve_arguments,
    _resolve_outcome,
    _run_auth_case,
    _run_authz_case,
)

_LIBRARY = Path(__file__).resolve().parents[2] / "library" / "mcp"


def _tool(props: dict, required: list[str] | None = None, name: str = "t") -> ToolDescriptor:
    schema: dict = {"properties": props}
    if required is not None:
        schema["required"] = required
    return ToolDescriptor(name=name, input_schema=schema)


def _tool_with_first_string(arg_name: str = "repo_name", required: bool = False) -> ToolDescriptor:
    return _tool(
        {arg_name: {"type": "string"}},
        required=[arg_name] if required else [],
    )


def _tool_no_string_args() -> ToolDescriptor:
    return _tool({"count": {"type": "integer"}}, required=[])


def _github_like_get_file_contents() -> ToolDescriptor:
    """Canonical multi-required-arg signature: position 0 is `owner`, but the
    path payload must land in `path`. owner+repo+path all required."""
    return _tool(
        {
            "owner": {"type": "string"},
            "repo": {"type": "string"},
            "path": {"type": "string"},
            "ref": {"type": "string"},
        },
        required=["owner", "repo", "path"],
        name="get_file_contents",
    )


# ---------------------------------------------------------------------------
# Resolution mechanics (tools with no required args, to isolate the mechanic)
# ---------------------------------------------------------------------------

def test_resolve_arguments_substitutes_first_string_arg():
    out = _resolve_arguments({"__first_string_arg__": "value-{run_id}"},
                             _tool_with_first_string("name", required=True), "abc123")
    assert out == {"name": "value-abc123"}


def test_resolve_arguments_run_id_substitution_works_for_explicit_keys():
    out = _resolve_arguments({"q": "marker-{run_id}"}, _tool({"q": {"type": "string"}}, []), "abc123")
    assert out == {"q": "marker-abc123"}


def test_resolve_arguments_raises_when_no_string_arg_available():
    """Bug B: previously silently dropped the key. Now raises so the scanner
    emits an explicit skipped finding."""
    with pytest.raises(_UnresolvedFirstStringArg):
        _resolve_arguments({"__first_string_arg__": "anything"}, _tool_no_string_args(), "abc123")


def test_resolve_arguments_with_no_tool_passes_through_literal_keys():
    out = _resolve_arguments({"q": "marker-{run_id}", "other": 42}, None, "deadbeef")
    assert out == {"q": "marker-deadbeef", "other": 42}


def test_resolve_arguments_non_string_values_passthrough():
    tool = _tool({"count": {"type": "integer"}, "items": {"type": "array"}, "flag": {"type": "boolean"}}, [])
    out = _resolve_arguments({"count": 5, "items": ["a", "b"], "flag": True}, tool, "xx")
    assert out == {"count": 5, "items": ["a", "b"], "flag": True}


# ---------------------------------------------------------------------------
# __target_arg__ — C+ kind-based resolution
# ---------------------------------------------------------------------------

def test_target_arg_resolves_to_kind_matched_arg_not_first():
    """The whole point of C+: __target_arg__ lands in the semantically-correct
    field. Supply owner+repo so required args are satisfied and we isolate the
    selection behavior."""
    out = _resolve_arguments(
        {"__target_arg__": "/etc/passwd", "owner": "o", "repo": "r"},
        _github_like_get_file_contents(), "abc123", "path",
    )
    assert out == {"path": "/etc/passwd", "owner": "o", "repo": "r"}


def test_first_string_arg_would_pick_the_wrong_field():
    """Contrast: __first_string_arg__ picks `owner` (position 0) — the bug C+ fixes.
    Use a no-required variant so we isolate the selection, not the required check."""
    tool = _tool(
        {"owner": {"type": "string"}, "repo": {"type": "string"}, "path": {"type": "string"}},
        required=[],
        name="get_file_contents",
    )
    out = _resolve_arguments({"__first_string_arg__": "/etc/passwd"}, tool, "abc123")
    assert out == {"owner": "/etc/passwd"}


def test_target_arg_with_run_id_template():
    out = _resolve_arguments(
        {"__target_arg__": "/canary-{run_id}/file", "owner": "o", "repo": "r"},
        _github_like_get_file_contents(), "deadbeef", "path",
    )
    assert out["path"] == "/canary-deadbeef/file"


def test_target_arg_raises_when_kind_not_set():
    with pytest.raises(_UnresolvedTargetArg, match="target_arg_kind is not set"):
        _resolve_arguments({"__target_arg__": "anything"}, _github_like_get_file_contents(), "abc123", None)


def test_target_arg_raises_when_no_arg_of_kind():
    no_path_tool = _tool({"owner": {"type": "string"}, "repo": {"type": "string"}})
    with pytest.raises(_UnresolvedTargetArg, match="no argument matching"):
        _resolve_arguments({"__target_arg__": "anything"}, no_path_tool, "abc123", "path")


def test_target_arg_and_other_keys_coexist():
    out = _resolve_arguments(
        {"__target_arg__": "/canary", "owner": "test-user", "repo": "test-repo", "ref": "main-{run_id}"},
        _github_like_get_file_contents(), "xx", "path",
    )
    assert out == {"path": "/canary", "owner": "test-user", "repo": "test-repo", "ref": "main-xx"}


# ---------------------------------------------------------------------------
# Context args (--arg) — the multi-required-arg fix
# ---------------------------------------------------------------------------

def test_context_args_fill_required_args():
    """The GitHub coverage gap: __target_arg__ fills `path`, context args fill
    owner+repo, so the call is complete and reaches the code path under test."""
    out = _resolve_arguments(
        {"__target_arg__": "../../etc/passwd"},
        _github_like_get_file_contents(), "abc123", "path",
        context_args={"owner": "octocat", "repo": "Hello-World"},
    )
    assert out == {"path": "../../etc/passwd", "owner": "octocat", "repo": "Hello-World"}


def test_context_args_only_fill_tool_declared_args():
    """Context args for args the tool doesn't have are ignored — we never send
    a parameter the tool doesn't accept."""
    out = _resolve_arguments(
        {"__target_arg__": "/x"},
        _github_like_get_file_contents(), "r1", "path",
        context_args={"owner": "o", "repo": "r", "not_a_real_arg": "ignored"},
    )
    assert "not_a_real_arg" not in out
    assert out == {"path": "/x", "owner": "o", "repo": "r"}


def test_probe_value_wins_over_context_arg():
    """If the probe explicitly sets an arg, the context value does not override it."""
    out = _resolve_arguments(
        {"__target_arg__": "/x", "owner": "probe-owner"},
        _github_like_get_file_contents(), "r1", "path",
        context_args={"owner": "context-owner", "repo": "r"},
    )
    assert out["owner"] == "probe-owner"


def test_unsatisfied_required_args_raises_with_names():
    """When required args remain unfilled after target + context, raise with the
    missing names so the scanner can tell the operator which --arg to supply."""
    with pytest.raises(_UnsatisfiedRequiredArgs) as exc_info:
        _resolve_arguments(
            {"__target_arg__": "/x"},
            _github_like_get_file_contents(), "r1", "path",
            context_args={"owner": "o"},  # repo still missing
        )
    assert exc_info.value.missing == ["repo"]


def test_no_required_args_no_context_needed():
    """A tool with no required args runs fine without context."""
    tool = _tool({"q": {"type": "string"}}, required=[])
    out = _resolve_arguments({"q": "hello"}, tool, "r1")
    assert out == {"q": "hello"}


# ---------------------------------------------------------------------------
# Outcome resolution — a secure rejection must not read as `vulnerable`
#
# Regression: mcp.path.prefix_bypass used a `regex` matcher that fired on the
# attacked path. A hardened server's access-denied error echoes that path back
# ("path outside allowed directories: /app/files/safe_files_sensitive"), so the
# regex matched the DENIAL and the scanner reported `vulnerable` — jakk crying
# wolf on a server that did the right thing. Found by scanning the real
# @modelcontextprotocol/server-filesystem (2026-05-27).
# ---------------------------------------------------------------------------

def test_regex_hit_inside_error_is_downgraded_to_echo():
    denial = (
        "Access denied - path outside allowed directories: "
        "/app/files/safe_files_sensitive not in /srv/root"
    )
    result = MatcherResult(True, denial, "vulnerable")
    outcome, evidence, error_note = _resolve_outcome(
        result, CallResult(text=denial, is_error=True), "regex"
    )
    assert outcome == "echo"  # NOT vulnerable: the path was reflected in a denial
    assert error_note is None
    assert "reflect" in evidence.lower()


def test_regex_hit_on_success_response_stays_vulnerable():
    """Regression guard for the true positive: a real bypass returns the
    protected listing in a SUCCESS response (is_error=False) — keep vulnerable."""
    listing = "Listing for /app/files/safe_files_sensitive:\nsecret.txt"
    result = MatcherResult(True, listing, "vulnerable")
    outcome, _, _ = _resolve_outcome(
        result, CallResult(text=listing, is_error=False), "regex"
    )
    assert outcome == "vulnerable"


def test_secret_leak_inside_error_stays_vulnerable():
    """A content-leak matcher (secret_pattern/cloud_metadata) firing even inside
    an error is a real leak — an error that returns /etc/passwd is still a leak."""
    leak = "Operation failed, but: root:x:0:0:root:/root:/bin/bash"
    result = MatcherResult(True, leak, "vulnerable")
    outcome, _, _ = _resolve_outcome(
        result, CallResult(text=leak, is_error=True), "secret_pattern"
    )
    assert outcome == "vulnerable"


def test_no_hit_inside_error_is_safe_rejection_pass():
    result = MatcherResult(False, "", "pass")
    outcome, evidence, _ = _resolve_outcome(
        result, CallResult(text="Access denied", is_error=True), "secret_pattern"
    )
    assert outcome == "pass"
    assert "rejected input (no leak)" in evidence


def test_transport_error_is_error_outcome():
    result = MatcherResult(False, "", "pass")
    outcome, _evidence, error_note = _resolve_outcome(
        result, CallResult(text="boom", transport_error=True), "regex"
    )
    assert outcome == "error"
    assert error_note


# ---------------------------------------------------------------------------
# Fix 2 — --canary-path overrides the path-kind target arg
#
# Path probes hardcode the breach-to-fix lab layout
# (/app/files/safe_files_sensitive/...). On a real server that path doesn't
# exist, so the probe can't exercise the traversal. --canary-path lets the
# operator retarget the path-kind arg at a real sensitive path.
# ---------------------------------------------------------------------------

def test_canary_path_overrides_path_target_arg():
    out = _resolve_arguments(
        {"__target_arg__": "/app/files/safe_files_sensitive/secret.txt"},
        _github_like_get_file_contents(), "r1", "path",
        context_args={"owner": "o", "repo": "r"},
        canary_path="/etc/passwd",
    )
    assert out["path"] == "/etc/passwd"


def test_canary_path_ignored_when_target_kind_not_path():
    """A non-path injection point (first-string-arg command probe) must NOT be
    retargeted by --canary-path."""
    out = _resolve_arguments(
        {"__first_string_arg__": "x-{run_id}"},
        _tool_with_first_string("cmd", required=False), "r1",
        canary_path="/etc/passwd",
    )
    assert out == {"cmd": "x-r1"}


def test_no_canary_path_keeps_yaml_default():
    out = _resolve_arguments(
        {"__target_arg__": "/app/files/safe_files_sensitive/secret.txt"},
        _github_like_get_file_contents(), "r1", "path",
        context_args={"owner": "o", "repo": "r"},
    )
    assert out["path"] == "/app/files/safe_files_sensitive/secret.txt"


# ---------------------------------------------------------------------------
# Fix 3 — auth-probe transport-failure classification
#
# _run_auth_case must not record an unreachable endpoint (connection refused,
# DNS, TLS, timeout) as `pass` ("server rejected bad auth") — that labels a
# dead endpoint as hardened. Connectivity failures → error; a real 401/403
# rejection (server is up) → pass.
# ---------------------------------------------------------------------------

def test_is_transport_failure_by_type_name():
    assert _is_transport_failure(ConnectionRefusedError("refused")) is True
    assert _is_transport_failure(OSError("connect call failed")) is True


def test_is_transport_failure_by_message_marker():
    assert _is_transport_failure(Exception("All connection attempts failed")) is True
    assert _is_transport_failure(Exception("Request timed out after 15s")) is True


def test_auth_rejection_is_not_transport_failure():
    """A 401/403 surfaced as an HTTP error means the server is up and rejecting
    — that's the secure `pass` outcome, not a transport failure."""
    assert _is_transport_failure(
        Exception("Client error '401 Unauthorized' for url 'http://x/mcp'")
    ) is False


def test_is_transport_failure_walks_cause_chain():
    root = OSError("connect call failed")
    wrapper = RuntimeError("handshake failed")
    wrapper.__cause__ = root
    assert _is_transport_failure(wrapper) is True


# ---------------------------------------------------------------------------
# Fix 1 + Fix 3 — full-path wiring through _run_authz_case / _run_auth_case
# (no live server: monkeypatch the MCPClient with a fake).
# ---------------------------------------------------------------------------


def _authz_case():
    return next(c for c in load_library(_LIBRARY) if c.surface == "authz")


def _auth_case(mode: str):
    return next(
        c for c in load_library(_LIBRARY)
        if c.surface == "auth" and c.auth_override is not None and c.auth_override.mode == mode
    )


def _fake_client_factory(call_results):
    """Build a fake MCPClient class that returns queued CallResults / raises."""
    class _FakeClient:
        def __init__(self, *a, **k):
            self._queue = list(call_results)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def call_tool(self, name, args):
            return self._queue.pop(0)

        async def list_tools(self):
            return []

    return _FakeClient


def test_authz_regex_hit_inside_denial_is_echo(monkeypatch):
    """Fix 1: phase-B denied but echoes the tenant tag in its rejection → echo,
    not the cry-wolf `vulnerable`."""
    case = _authz_case()
    results = [
        CallResult(text='{"tenant":"tenant_alpha","id":"CRM-1001"}', is_error=False),  # phase A ok
        CallResult(text='Access denied for "tenant":"tenant_alpha"', is_error=True),   # phase B denial echoes tag
    ]
    monkeypatch.setattr(scanner, "MCPClient", _fake_client_factory(results))
    cfg = ScanConfig(endpoint="http://x/mcp", cred_a="a", cred_b="b", foreign_id="CRM-1001")
    finding = asyncio.run(_run_authz_case(case, cfg))
    assert finding.outcome == "echo"


def test_authz_hit_on_success_is_vulnerable(monkeypatch):
    """Fix 1 regression guard: a genuine cross-tenant read (B gets A's object in a
    SUCCESS response) stays vulnerable."""
    case = _authz_case()
    results = [
        CallResult(text='{"tenant":"tenant_alpha","id":"CRM-1001"}', is_error=False),  # phase A ok
        CallResult(text='{"tenant":"tenant_alpha","id":"CRM-1001"}', is_error=False),  # phase B leaks A's object
    ]
    monkeypatch.setattr(scanner, "MCPClient", _fake_client_factory(results))
    cfg = ScanConfig(endpoint="http://x/mcp", cred_a="a", cred_b="b", foreign_id="CRM-1001")
    finding = asyncio.run(_run_authz_case(case, cfg))
    assert finding.outcome == "vulnerable"


def test_auth_transport_failure_is_error(monkeypatch):
    """Fix 3: an unreachable endpoint → error (inconclusive), not pass."""
    case = _auth_case("none")

    class _DeadClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            raise ConnectionRefusedError("All connection attempts failed")

        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr(scanner, "MCPClient", _DeadClient)
    cfg = ScanConfig(endpoint="http://127.0.0.1:1/mcp")
    finding = asyncio.run(_run_auth_case(case, cfg))
    assert finding.outcome == "error"
    assert finding.fired is False


def test_auth_rejection_is_pass(monkeypatch):
    """Fix 3 regression guard: server up and rejecting bad auth → pass."""
    case = _auth_case("none")

    class _RejectingClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def list_tools(self):
            raise Exception("Client error '401 Unauthorized' for url 'http://x/mcp'")

    monkeypatch.setattr(scanner, "MCPClient", _RejectingClient)
    cfg = ScanConfig(endpoint="http://x/mcp")
    finding = asyncio.run(_run_auth_case(case, cfg))
    assert finding.outcome == "pass"


# ---------------------------------------------------------------------------
# Hardening — a failed shared tool-surface client must not crash the scan.
#
# Real: scanning the auth-gated github-mcp-server crashed jakk with an uncaught
# httpx 401 from the shared client's list_tools() (2026-06-12). The tool-surface
# probes must instead degrade to per-probe skipped/error with a reason.
# ---------------------------------------------------------------------------

def _tool_surface_cases():
    return [c for c in load_library(_LIBRARY) if c.surface not in ("auth", "authz")]


def test_run_scan_auth_wall_skips_tool_surface(monkeypatch):
    cases = _tool_surface_cases()

    class _AuthWall:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def list_tools(self):
            raise Exception("Client error '401 Unauthorized' for url 'http://x/mcp'")

    monkeypatch.setattr(scanner, "MCPClient", _AuthWall)
    findings = asyncio.run(scanner.run_scan(cases, ScanConfig(endpoint="http://x/mcp")))
    assert len(findings) == len(cases)  # no crash; every probe accounted for
    assert all(f.outcome == "skipped" for f in findings)
    assert all("requires auth" in f.evidence.lower() for f in findings)


def test_run_scan_unreachable_tool_surface_is_error(monkeypatch):
    cases = _tool_surface_cases()

    class _Dead:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            raise ConnectionRefusedError("All connection attempts failed")

        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr(scanner, "MCPClient", _Dead)
    findings = asyncio.run(scanner.run_scan(cases, ScanConfig(endpoint="http://127.0.0.1:1/mcp")))
    assert len(findings) == len(cases)
    assert all(f.outcome == "error" for f in findings)


def test_run_scan_healthy_server_still_works(monkeypatch):
    """Regression guard: hardening must not change the happy path. A server
    that lists tools normally still runs probes (here: no tools → all skipped
    with the normal 'no compatible tool' reason, not the surface-failure one)."""
    cases = _tool_surface_cases()

    class _Healthy:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def list_tools(self):
            return []  # healthy handshake, no tools exposed

    monkeypatch.setattr(scanner, "MCPClient", _Healthy)
    findings = asyncio.run(scanner.run_scan(cases, ScanConfig(endpoint="http://x/mcp")))
    assert findings  # scan completed, not crashed
    assert all(f.outcome in ("pass", "skipped") for f in findings)
    assert not any("requires auth" in (f.evidence or "").lower() for f in findings)
