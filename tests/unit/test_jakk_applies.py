"""Tests for the applies_to compatibility filter."""
from __future__ import annotations

from jakk.applies import matches, select_tools
from jakk.library import AppliesTo, Matcher, Payload, TestCase
from jakk.mcp_client import ToolDescriptor


def _tool(name: str, props: dict | None = None) -> ToolDescriptor:
    schema = {"properties": props or {}}
    return ToolDescriptor(name=name, description="", input_schema=schema)


def _case(applies_to: AppliesTo) -> TestCase:
    return TestCase(
        id="t.x",
        surface="tool_call",
        description="x",
        expected_signal="x",
        applies_to=applies_to,
        payload=Payload(arguments={}),
        matcher=Matcher(kind="substring", params={"needle": "x"}),
    )


def test_exact_tool_name_match():
    a = AppliesTo(tool_name="init_bare_repository")
    assert matches(a, _tool("init_bare_repository", {"repo_name": {"type": "string"}}))
    assert not matches(a, _tool("list_repositories"))


def test_regex_tool_name_match():
    a = AppliesTo(tool_name_regex="(?i)^init_")
    assert matches(a, _tool("init_bare_repository", {"repo_name": {"type": "string"}}))
    assert not matches(a, _tool("list_repositories"))


def test_min_string_args():
    a = AppliesTo(min_string_args=1)
    assert matches(a, _tool("foo", {"x": {"type": "string"}}))
    assert not matches(a, _tool("foo", {}))


def test_none_means_no_tools_selected():
    a = AppliesTo(none=True)
    assert not matches(a, _tool("anything"))
    assert select_tools(_case(a), [_tool("anything")]) == []


def test_first_string_arg():
    t = _tool(
        "foo",
        {"count": {"type": "integer"}, "name": {"type": "string"}, "tag": {"type": "string"}},
    )
    assert t.first_string_arg() == "name"
    assert t.string_arg_count() == 2


def test_require_no_required_args_filter():
    # Tool with a required arg should be filtered out when the flag is set.
    schema_with_required = {
        "properties": {"x": {"type": "string"}},
        "required": ["x"],
    }
    t_required = ToolDescriptor(name="needs_arg", description="", input_schema=schema_with_required)
    t_no_required = _tool("zero_arg", {})

    a = AppliesTo(require_no_required_args=True)
    assert not matches(a, t_required)
    assert matches(a, t_no_required)

    # Without the flag, both match.
    a2 = AppliesTo()
    assert matches(a2, t_required)
    assert matches(a2, t_no_required)


def test_require_no_required_args_with_empty_required_list():
    # A schema that explicitly sets required: [] should still match.
    schema = {"properties": {"x": {"type": "string"}}, "required": []}
    t = ToolDescriptor(name="x", description="", input_schema=schema)
    assert matches(AppliesTo(require_no_required_args=True), t)
