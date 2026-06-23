"""CLI behavior that matters for CI gating."""
from __future__ import annotations

from pathlib import Path

import jakk.cli as cli
from jakk.findings import Finding


def _finding(outcome: str) -> Finding:
    return Finding(
        test_id=f"mcp.test.{outcome}",
        expected_signal="test.signal",
        severity="high",
        surface="tool_call",
        endpoint="http://example.test/mcp",
        fired=outcome in ("vulnerable", "echo"),
        outcome=outcome,
        tool_name="test_tool",
    )


def _patch_scan(monkeypatch, findings: list[Finding]) -> None:
    monkeypatch.setattr(cli, "load_library", lambda _path: [object()])
    monkeypatch.setattr(cli, "filter_cases", lambda cases, **_kwargs: cases)

    async def _run_scan(_selected, _cfg):
        return findings

    monkeypatch.setattr(cli, "run_scan", _run_scan)
    monkeypatch.setattr(cli, "render_console", lambda *_args, **_kwargs: None)


def _argv(tmp_path: Path) -> list[str]:
    return [
        "mcp",
        "scan",
        "--endpoint",
        "http://example.test/mcp",
        "--library",
        str(tmp_path),
        "--exit-nonzero-on-fired",
    ]


def test_exit_nonzero_on_fired_blocks_vulnerable(monkeypatch, tmp_path):
    _patch_scan(monkeypatch, [_finding("vulnerable")])

    assert cli.main(_argv(tmp_path)) == 2


def test_exit_nonzero_on_fired_does_not_block_echo(monkeypatch, tmp_path):
    _patch_scan(monkeypatch, [_finding("echo")])

    assert cli.main(_argv(tmp_path)) == 0
