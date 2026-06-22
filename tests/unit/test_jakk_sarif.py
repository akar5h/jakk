"""Tests for SARIF output used by GitHub code scanning."""
from __future__ import annotations

import json

from jakk.findings import Finding, to_sarif, write_sarif


def _finding(**overrides):
    base = dict(
        test_id="mcp.response.secret_overshare",
        expected_signal="response.secret_leak",
        severity="high",
        surface="tool_call",
        endpoint="http://127.0.0.1:8000/mcp",
        fired=True,
        outcome="vulnerable",
        tool_name="get_settings",
        evidence='token="sk-test12345678901234567890"',
        owasp=["MCP02"],
        atlas=["AML.T0051"],
        payload={"tool": "get_settings", "arguments": {}},
    )
    base.update(overrides)
    return Finding(**base)


def test_to_sarif_emits_fired_findings_only():
    sarif = to_sarif([
        _finding(),
        _finding(test_id="mcp.auth.no_credential", fired=False, outcome="pass"),
    ])

    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "jakk"
    assert [r["ruleId"] for r in run["results"]] == ["mcp.response.secret_overshare"]
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["mcp.response.secret_overshare"]


def test_to_sarif_maps_severity_and_properties():
    result = to_sarif([_finding(severity="critical")])["runs"][0]["results"][0]
    rule = to_sarif([_finding(severity="critical")])["runs"][0]["tool"]["driver"]["rules"][0]

    assert result["level"] == "error"
    assert result["ruleId"] == "mcp.response.secret_overshare"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "jakk-mcp-scan"
    assert result["properties"]["endpoint"] == "http://127.0.0.1:8000/mcp"
    assert result["properties"]["payload"]["tool"] == "get_settings"
    assert "partialFingerprints" in result
    assert rule["properties"]["security-severity"] == "9.0"
    assert "MCP02" in rule["properties"]["tags"]


def test_write_sarif_round_trips_json(tmp_path):
    out = tmp_path / "findings.sarif"
    write_sarif([_finding()], out)

    data = json.loads(out.read_text())
    assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert data["runs"][0]["results"][0]["message"]["text"].startswith("vulnerable:")
