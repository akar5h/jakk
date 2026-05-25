"""Tests for the ARG_KINDS registry — schema-aware semantic-role resolution.

These tests pin the per-kind name/description regex behavior so future
refactors of the registry can't silently change which arg a probe lands on.
The behavior matters at scan time against real MCP servers — getting it
wrong means probes either skip valid targets (false negatives) or fire into
the wrong field (false errors).
"""
from __future__ import annotations

import pytest

from jakk.applies import ARG_KINDS, find_arg_of_kind, matches
from jakk.library import AppliesTo
from jakk.mcp_client import ToolDescriptor


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _tool(name: str, props: dict | None = None, required: list | None = None) -> ToolDescriptor:
    schema: dict = {"properties": props or {}}
    if required is not None:
        schema["required"] = required
    return ToolDescriptor(name=name, description="", input_schema=schema)


# ---------------------------------------------------------------------------
# Registry shape
# ---------------------------------------------------------------------------


def test_registry_has_expected_kinds():
    assert set(ARG_KINDS.keys()) == {"path", "query", "id", "url", "text"}


def test_registry_does_NOT_define_command_kind():
    """Intentional design choice: shell-injection probes have no schema
    clue, so they keep __first_string_arg__ semantics. Adding a `command`
    kind here without a clear heuristic would cause regression."""
    assert "command" not in ARG_KINDS


def test_unknown_kind_raises():
    t = _tool("foo", {"x": {"type": "string"}})
    with pytest.raises(ValueError, match="unknown target_arg_kind"):
        find_arg_of_kind(t, "definitely_not_a_kind")


# ---------------------------------------------------------------------------
# path kind — name-match cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "arg_name",
    [
        "path",           # bare "path"
        "file_path",      # snake_case
        "filepath",       # no separator
        "file",           # bare "file"
        "filename",       # filename
        "target_file",    # composed
        "src",            # source/src abbreviations
        "source",
        "directory",
        "dir",
        "full_path",      # ch02's list_directory_contents arg — regressed once, pinned here
        "dir_path",       # other *_path compositions
        "absolute_path",
        "relative_path",
    ],
)
def test_path_kind_matches_by_name(arg_name: str):
    t = _tool("read_anything", {arg_name: {"type": "string"}})
    assert find_arg_of_kind(t, "path") == arg_name, (
        f"expected path kind to match arg name {arg_name!r}"
    )


def test_path_kind_picks_path_over_non_string_arg_named_path():
    # An int-typed "path" arg (rare, but) should NOT match — we only fill
    # string-typed args.
    t = _tool(
        "x",
        {
            "owner": {"type": "string"},
            "repo": {"type": "string"},
            "path": {"type": "integer"},  # not a string
        },
    )
    # First two are strings but their names don't match; the third matches
    # but isn't a string. Result: no match.
    assert find_arg_of_kind(t, "path") is None


def test_path_kind_real_world_github_get_file_contents():
    """GitHub MCP's get_file_contents — the canonical test of why C+ matters.
    Position 0 is `owner`, which is NOT what we want to inject into."""
    t = _tool(
        "get_file_contents",
        {
            "owner": {"type": "string"},
            "repo": {"type": "string"},
            "path": {"type": "string"},
            "ref": {"type": "string"},
        },
        required=["owner", "repo", "path"],
    )
    assert find_arg_of_kind(t, "path") == "path"
    # Sanity: position-based resolution would pick owner, which is the bug
    # this design exists to avoid.
    assert t.first_string_arg() == "owner"


def test_path_kind_real_world_breach_to_fix_read_file_contents():
    """ch02's read_file_contents(file_path) — different name, same kind."""
    t = _tool(
        "read_file_contents",
        {"file_path": {"type": "string"}},
        required=["file_path"],
    )
    assert find_arg_of_kind(t, "path") == "file_path"


# ---------------------------------------------------------------------------
# path kind — description-fallback cases
# ---------------------------------------------------------------------------


def test_path_kind_falls_back_to_description():
    """When the arg name doesn't match any path keyword, the description
    can still tell us this is a path-shaped arg."""
    t = _tool(
        "weird_tool",
        {
            "q": {"type": "string", "description": "the search query"},
            "f": {"type": "string", "description": "absolute path to the file to read"},
        },
    )
    # Neither "q" nor "f" matches the path name regex; description match
    # picks "f".
    assert find_arg_of_kind(t, "path") == "f"


def test_path_kind_name_match_beats_description_match():
    """If two args match — one by name, one by description — the name pass
    wins (more confident signal)."""
    t = _tool(
        "x",
        {
            "needle": {"type": "string", "description": "absolute path to read"},
            "path": {"type": "string", "description": "unused"},
        },
    )
    assert find_arg_of_kind(t, "path") == "path"


# ---------------------------------------------------------------------------
# path kind — negative cases
# ---------------------------------------------------------------------------


def test_path_kind_returns_none_when_no_match():
    t = _tool("x", {"owner": {"type": "string"}, "repo": {"type": "string"}})
    assert find_arg_of_kind(t, "path") is None


def test_path_kind_skips_empty_properties():
    t = _tool("x", {})
    assert find_arg_of_kind(t, "path") is None


# ---------------------------------------------------------------------------
# Other kinds — sanity checks
# ---------------------------------------------------------------------------


def test_query_kind_basic():
    t = _tool("search_code", {"q": {"type": "string"}, "owner": {"type": "string"}})
    assert find_arg_of_kind(t, "query") == "q"


def test_id_kind_matches_underscore_id_suffix():
    t = _tool(
        "get_issue",
        {
            "owner": {"type": "string"},
            "repo": {"type": "string"},
            "issue_number": {"type": "integer"},  # not a string
            "issue_id": {"type": "string"},
        },
    )
    assert find_arg_of_kind(t, "id") == "issue_id"


def test_url_kind_basic():
    t = _tool("fetch", {"url": {"type": "string"}})
    assert find_arg_of_kind(t, "url") == "url"


def test_text_kind_matches_body_or_message():
    t = _tool(
        "send_message",
        {"channel": {"type": "string"}, "body": {"type": "string"}},
    )
    assert find_arg_of_kind(t, "text") == "body"


# ---------------------------------------------------------------------------
# Integration with applies.matches() — filter aspect
# ---------------------------------------------------------------------------


def test_matches_filters_out_tool_lacking_required_kind():
    """A tool that matches the name regex but has no path-shaped arg should
    be filtered out by applies.matches(), so the probe is `skipped` rather
    than producing `error` at scan time."""
    a = AppliesTo(tool_name_regex=r"^get_", target_arg_kind="path")
    has_path = _tool("get_file_contents", {"path": {"type": "string"}, "owner": {"type": "string"}})
    no_path = _tool("get_repo", {"owner": {"type": "string"}, "repo": {"type": "string"}})
    assert matches(a, has_path)
    assert not matches(a, no_path)


def test_matches_passes_without_target_arg_kind():
    """Backwards compat: existing probes without target_arg_kind continue
    to match on name regex alone."""
    a = AppliesTo(tool_name_regex=r"^get_")
    assert matches(a, _tool("get_repo", {"owner": {"type": "string"}}))
