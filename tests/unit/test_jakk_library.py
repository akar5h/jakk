"""Tests for the YAML attack-library loader."""
from __future__ import annotations

from pathlib import Path

import pytest

from jakk.library import TestCase, filter_cases, load_library

LIBRARY_DIR = Path(__file__).resolve().parents[2] / "library" / "mcp"

EXPECTED_IDS = {
    "mcp.command.shell_marker",
    "mcp.command.secret_file_read",
    "mcp.path.prefix_bypass",
    "mcp.path.canary_file_read",
    "mcp.response.secret_overshare",
    "mcp.response.directive_passthrough",
    "mcp.schema.description_smuggling",
    "mcp.auth.no_credential",
    "mcp.auth.invalid_token",
    "mcp.auth.wrong_prefix",
    "mcp.authz.cross_tenant_read",
    "mcp.ssrf.cloud_metadata",
    "mcp.sql.error_based",
}

SAFE_IDS = {
    "mcp.response.secret_overshare",
    "mcp.response.directive_passthrough",
    "mcp.schema.description_smuggling",
    "mcp.auth.no_credential",
    "mcp.auth.invalid_token",
    "mcp.auth.wrong_prefix",
    "mcp.authz.cross_tenant_read",
    "mcp.ssrf.cloud_metadata",
}


def test_library_dir_present():
    assert LIBRARY_DIR.is_dir(), f"missing library dir: {LIBRARY_DIR}"


def test_loads_all_six_tests():
    cases = load_library(LIBRARY_DIR)
    ids = {c.id for c in cases}
    assert ids == EXPECTED_IDS, f"unexpected ids: {ids - EXPECTED_IDS} / missing: {EXPECTED_IDS - ids}"


def test_each_case_has_required_fields():
    cases = load_library(LIBRARY_DIR)
    for case in cases:
        assert case.id
        assert case.description
        assert case.expected_signal
        assert case.surface in {
            "tool_call",
            "tool_list",
            "resource_list",
            "prompt_list",
            "auth",
            "authz",
        }
        if case.surface == "auth":
            assert case.auth_override is not None
            assert case.auth_override.mode in {"none", "garbage", "wrong_prefix"}
        elif case.surface == "authz":
            assert case.phase_a is not None and case.phase_b is not None
            assert case.matcher is not None
        else:
            assert case.matcher is not None
            assert case.matcher.kind


def test_filter_cases_by_select():
    cases = load_library(LIBRARY_DIR)
    only = filter_cases(cases, select="mcp.command.shell_marker")
    assert [c.id for c in only] == ["mcp.command.shell_marker"]


def test_filter_cases_by_owasp():
    cases = load_library(LIBRARY_DIR)
    mcp05 = filter_cases(cases, owasp="MCP05")
    ids = {c.id for c in mcp05}
    assert "mcp.command.shell_marker" in ids
    assert "mcp.command.secret_file_read" in ids
    assert "mcp.schema.description_smuggling" not in ids


def test_filter_cases_safe_only():
    cases = load_library(LIBRARY_DIR)
    safe = filter_cases(cases, safe_only=True)
    ids = {c.id for c in safe}
    assert ids == SAFE_IDS, f"safe-only filter returned unexpected set: {ids ^ SAFE_IDS}"
    for c in safe:
        assert c.side_effect == "safe"


def test_safe_only_excludes_command_probes():
    """Command-injection probes must never be classified safe — they create directories
    and run shell commands."""
    cases = load_library(LIBRARY_DIR)
    safe = filter_cases(cases, safe_only=True)
    safe_ids = {c.id for c in safe}
    for unsafe_id in (
        "mcp.command.shell_marker",
        "mcp.command.secret_file_read",
        "mcp.path.prefix_bypass",
        "mcp.path.canary_file_read",
    ):
        assert unsafe_id not in safe_ids, f"{unsafe_id} must not be in --safe set"


def test_unique_ids_in_library():
    cases = load_library(LIBRARY_DIR)
    ids = [c.id for c in cases]
    assert len(ids) == len(set(ids))


def test_missing_directory_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_library(tmp_path / "does-not-exist")


def test_malformed_yaml_raises(tmp_path: Path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: bad\nsurface: tool_call\n# missing required matcher + description\n")
    with pytest.raises(ValueError) as exc_info:
        load_library(tmp_path)
    assert "bad.yaml" in str(exc_info.value)


def test_duplicate_ids_raise(tmp_path: Path):
    common = (
        "id: dup.case\n"
        "surface: tool_call\n"
        "description: x\n"
        "expected_signal: x\n"
        "matcher:\n"
        "  kind: substring\n"
        "  params:\n"
        "    needle: x\n"
    )
    (tmp_path / "a.yaml").write_text(common)
    (tmp_path / "b.yaml").write_text(common)
    with pytest.raises(ValueError, match="duplicate"):
        load_library(tmp_path)


def test_invalid_regex_caught_at_load_time(tmp_path: Path):
    """Bug A: invalid regex in applies_to.tool_name_regex must raise at load_library,
    not later when the scanner tries to use it."""
    bad = tmp_path / "bad_regex.yaml"
    bad.write_text(
        "id: bad.regex\n"
        "surface: tool_call\n"
        "description: x\n"
        "expected_signal: x\n"
        "applies_to:\n"
        "  tool_name_regex: '(unclosed'\n"
        "payload:\n"
        "  arguments: {}\n"
        "matcher:\n"
        "  kind: substring\n"
        "  params:\n"
        "    needle: x\n"
    )
    with pytest.raises(ValueError) as exc_info:
        load_library(tmp_path)
    msg = str(exc_info.value)
    assert "bad_regex.yaml" in msg
    assert "tool_name_regex" in msg


def test_id_must_be_dotted_slug():
    with pytest.raises(Exception):
        TestCase(
            id="bad id with space",
            surface="tool_call",
            description="x",
            expected_signal="x",
            matcher={"kind": "substring", "params": {"needle": "x"}},
        )


def test_auth_surface_requires_auth_override():
    """A surface=auth probe without auth_override should fail validation."""
    with pytest.raises(Exception) as exc_info:
        TestCase(
            id="bad.auth",
            surface="auth",
            description="x",
            expected_signal="x",
        )
    assert "auth_override" in str(exc_info.value)


def test_non_auth_surface_requires_matcher():
    """A surface=tool_call probe without matcher should fail validation."""
    with pytest.raises(Exception) as exc_info:
        TestCase(
            id="bad.tool_call",
            surface="tool_call",
            description="x",
            expected_signal="x",
        )
    assert "matcher" in str(exc_info.value)


def test_auth_surface_with_valid_auth_override_loads():
    """Happy path: surface=auth + auth_override = valid TestCase."""
    case = TestCase(
        id="ok.auth",
        surface="auth",
        description="x",
        expected_signal="x",
        auth_override={"mode": "none", "expect_success": "vulnerable"},
    )
    assert case.auth_override is not None
    assert case.auth_override.mode == "none"
    assert case.matcher is None


def test_authz_surface_requires_phases_and_matcher():
    """surface=authz needs phase_a, phase_b, AND matcher."""
    with pytest.raises(Exception, match="phase_a and phase_b"):
        TestCase(
            id="bad.authz",
            surface="authz",
            description="x",
            expected_signal="x",
            matcher={"kind": "substring", "params": {"needle": "x"}},
        )

    with pytest.raises(Exception, match="matcher"):
        TestCase(
            id="bad.authz.nomatch",
            surface="authz",
            description="x",
            expected_signal="x",
            phase_a={"tool": "t", "arguments": {}},
            phase_b={"tool": "t", "arguments": {}},
        )


def test_authz_surface_happy_path_loads():
    case = TestCase(
        id="ok.authz",
        surface="authz",
        description="x",
        expected_signal="x",
        phase_a={"tool": "fetch", "arguments": {"id": "{foreign_id}", "cred": "{cred_a}"}},
        phase_b={"tool": "fetch", "arguments": {"id": "{foreign_id}", "cred": "{cred_b}"}},
        matcher={"kind": "substring", "params": {"needle": "tenant_alpha"}},
    )
    assert case.phase_a.tool == "fetch"
    assert case.phase_b.arguments["cred"] == "{cred_b}"
