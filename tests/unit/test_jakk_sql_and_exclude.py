"""Tests for the sql_error matcher + SQL probe, and --exclude-surface filtering."""
from __future__ import annotations

from pathlib import Path

from jakk.library import filter_cases, load_library
from jakk.matchers import run_matcher
from jakk.mcp_client import CallResult
from jakk.matchers import MatcherResult
from jakk.scanner import _resolve_outcome

_LIBRARY = Path(__file__).resolve().parents[2] / "library" / "mcp"


# ---------------------------------------------------------------------------
# sql_error matcher
# ---------------------------------------------------------------------------

def test_sql_error_fires_on_postgres_syntax_error():
    resp = 'ERROR:  syntax error at or near "\'" LINE 1: SELECT * FROM t WHERE q=\'jakkab12\''
    r = run_matcher("sql_error", {}, resp, {})
    assert r.fired and r.outcome == "vulnerable"


def test_sql_error_fires_on_sqlite_error():
    r = run_matcher("sql_error", {}, 'sqlite3.OperationalError: unrecognized token: "\'"', {})
    assert r.fired and r.outcome == "vulnerable"


def test_sql_error_fires_on_mysql_error():
    r = run_matcher("sql_error", {}, "You have an error in your SQL syntax near ''' at line 1", {})
    assert r.fired and r.outcome == "vulnerable"


def test_sql_error_passes_on_clean_response():
    r = run_matcher("sql_error", {}, '{"results": [{"id": 1, "name": "acme"}]}', {})
    assert not r.fired and r.outcome == "pass"


def test_sql_error_passes_on_generic_non_sql_error():
    """A generic error with no engine signature must NOT fire — low-FP design."""
    r = run_matcher("sql_error", {}, "Error: record not found", {})
    assert not r.fired


def test_sql_error_extra_patterns():
    r = run_matcher("sql_error", {"patterns": [r"MyOrmError"]}, "boom: MyOrmError happened", {})
    assert r.fired


def test_sql_error_stays_vulnerable_inside_tool_error():
    """Content-class: a SQL error is normally RETURNED as an error result. It
    must stay `vulnerable` (not be downgraded to echo like reflection matchers)."""
    err = "ERROR: syntax error at or near \"'\""
    result = MatcherResult(True, err, "vulnerable")
    outcome, _, _ = _resolve_outcome(result, CallResult(text=err, is_error=True), "sql_error")
    assert outcome == "vulnerable"


# ---------------------------------------------------------------------------
# SQL probe loads from the shipped library
# ---------------------------------------------------------------------------

def test_sql_probe_in_library():
    cases = {c.id: c for c in load_library(_LIBRARY)}
    assert "mcp.sql.error_based" in cases
    probe = cases["mcp.sql.error_based"]
    assert probe.matcher is not None and probe.matcher.kind == "sql_error"
    assert probe.applies_to.target_arg_kind == "query"


# ---------------------------------------------------------------------------
# --exclude-surface filtering
# ---------------------------------------------------------------------------

def test_exclude_surface_drops_auth():
    cases = load_library(_LIBRARY)
    assert any(c.surface == "auth" for c in cases)  # precondition
    filtered = filter_cases(cases, exclude_surfaces=["auth"])
    assert not any(c.surface == "auth" for c in filtered)
    assert len(filtered) < len(cases)


def test_exclude_surface_multiple():
    cases = load_library(_LIBRARY)
    filtered = filter_cases(cases, exclude_surfaces=["auth", "authz"])
    assert not any(c.surface in ("auth", "authz") for c in filtered)


def test_exclude_surface_none_is_noop():
    cases = load_library(_LIBRARY)
    assert len(filter_cases(cases, exclude_surfaces=None)) == len(cases)
    assert len(filter_cases(cases, exclude_surfaces=[])) == len(cases)


def test_exclude_surface_composes_with_safe():
    cases = load_library(_LIBRARY)
    filtered = filter_cases(cases, safe_only=True, exclude_surfaces=["auth"])
    assert all(c.side_effect == "safe" for c in filtered)
    assert all(c.surface != "auth" for c in filtered)
