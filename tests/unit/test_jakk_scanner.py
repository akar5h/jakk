"""Tests for scanner-internal helpers (no MCP server required)."""
from __future__ import annotations

import pytest

from jakk.mcp_client import ToolDescriptor
from jakk.scanner import (
    _UnresolvedFirstStringArg,
    _UnresolvedTargetArg,
    _UnsatisfiedRequiredArgs,
    _resolve_arguments,
)


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
