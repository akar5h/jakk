"""Tests for MCPClient header/auth resolution (no live MCP server required)."""
from __future__ import annotations

import pytest

from jakk.mcp_client import MCPClient


def _resolve(**kw):
    return MCPClient("http://example/mcp", **kw)._resolve_transport_kwargs()


def test_bearer_only():
    kw = _resolve(bearer="abc123")
    assert kw["auth"] == "abc123"
    assert kw["headers"] in (None, {})  # no custom headers


def test_custom_headers_passed_through():
    kw = _resolve(bearer="abc", headers={"X-Api-Key": "k", "X-Tenant": "t"})
    assert kw["auth"] == "abc"
    assert kw["headers"]["X-Api-Key"] == "k"
    assert kw["headers"]["X-Tenant"] == "t"


def test_auth_override_none_strips_bearer_and_authorization_header():
    kw = _resolve(
        bearer="abc",
        headers={"Authorization": "Bearer xyz", "X-Other": "keep"},
        auth_override="none",
    )
    assert kw["auth"] is None
    assert kw["headers"] is not None
    assert "Authorization" not in kw["headers"]
    assert "authorization" not in kw["headers"]
    assert kw["headers"]["X-Other"] == "keep"


def test_auth_override_garbage_sets_random_bearer():
    kw = _resolve(bearer="abc", auth_override="garbage")
    assert kw["auth"] is None
    assert kw["headers"]["Authorization"].startswith("Bearer garbage-")
    # 16 hex chars after the prefix
    suffix = kw["headers"]["Authorization"].split("garbage-")[1]
    assert len(suffix) == 16


def test_auth_override_garbage_works_without_bearer():
    """garbage mode doesn't depend on the user supplying a real bearer."""
    kw = _resolve(auth_override="garbage")
    assert kw["headers"]["Authorization"].startswith("Bearer garbage-")


def test_auth_override_wrong_prefix_strips_bearer_scheme():
    kw = _resolve(bearer="my-real-token", auth_override="wrong_prefix")
    assert kw["auth"] is None
    assert kw["headers"]["Authorization"] == "my-real-token"  # raw, no "Bearer "


def test_auth_override_wrong_prefix_without_bearer_raises():
    """Without a bearer to mutate, this override cannot run."""
    with pytest.raises(ValueError, match="requires a bearer token"):
        _resolve(auth_override="wrong_prefix")


def test_auth_override_unknown_mode_raises():
    with pytest.raises(ValueError, match="unknown auth_override"):
        _resolve(auth_override="not_a_real_mode")


def test_no_auth_no_override_returns_clean():
    kw = _resolve()
    assert kw["auth"] is None
    assert kw["headers"] in (None, {})


# ---------------------------------------------------------------------------
# transport-error vs tool-error classification (drives error-vs-pass outcomes)
# ---------------------------------------------------------------------------

def test_is_tool_error_recognizes_fastmcp_toolerror():
    from fastmcp.exceptions import ToolError
    from jakk.mcp_client import _is_tool_error
    assert _is_tool_error(ToolError("the tool returned an error result"))


def test_is_tool_error_rejects_transport_exceptions():
    from jakk.mcp_client import _is_tool_error
    # Connection / protocol / timeout style exceptions are NOT tool errors.
    assert not _is_tool_error(ConnectionError("connection refused"))
    assert not _is_tool_error(TimeoutError("timed out"))
    assert not _is_tool_error(RuntimeError("client failed to connect"))


def test_is_tool_error_name_fallback():
    """If the import path ever moves, the class-name fallback still classifies."""
    from jakk.mcp_client import _is_tool_error
    class ToolError(Exception):
        pass
    assert _is_tool_error(ToolError("shadowed local class with the right name"))
