"""Tests for authz scanner template expansion (no live MCP server required)."""
from __future__ import annotations

from jakk.scanner import ScanConfig, _expand_authz_template


def test_expand_substitutes_all_known_tokens():
    cfg = ScanConfig(
        endpoint="http://example/mcp",
        cred_a="alpha-key",
        cred_b="bravo-key",
        foreign_id="CRM-1001",
    )
    out = _expand_authz_template(
        "id={foreign_id} a={cred_a} b={cred_b} r={run_id}", cfg, "deadbeef"
    )
    assert out == "id=CRM-1001 a=alpha-key b=bravo-key r=deadbeef"


def test_expand_missing_creds_substitutes_empty():
    """If a cred isn't supplied, template substitutes empty string. The scanner's
    skip-check (presence of cfg.cred_a etc.) should fire BEFORE this is reached;
    the empty-string fallback is just defensive."""
    cfg = ScanConfig(endpoint="http://example/mcp")
    out = _expand_authz_template("a={cred_a} b={cred_b}", cfg, "r1")
    assert out == "a= b="


def test_expand_non_string_passthrough():
    cfg = ScanConfig(endpoint="x", cred_a="a", cred_b="b", foreign_id="i")
    assert _expand_authz_template(42, cfg, "r1") == 42
    assert _expand_authz_template(None, cfg, "r1") is None
    assert _expand_authz_template(["x"], cfg, "r1") == ["x"]
