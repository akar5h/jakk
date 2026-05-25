"""Finding model + JSONL writer + console renderer."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.markup import escape as _rich_escape
from rich.table import Table


@dataclass
class Finding:
    test_id: str
    expected_signal: str
    severity: str
    surface: str
    endpoint: str
    fired: bool
    outcome: str = "pass"  # vulnerable | echo | pass | skipped | error
    tool_name: Optional[str] = None
    evidence: str = ""
    owasp: list[str] = field(default_factory=list)
    atlas: list[str] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def write_jsonl(findings: list[Finding], path: Path | str) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for f in findings:
            fh.write(json.dumps(f.to_dict(), ensure_ascii=False) + "\n")


_SEV_COLOR = {
    "info": "cyan",
    "low": "blue",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
}

_OUTCOME_STYLE = {
    "vulnerable": "bold red",
    "echo": "yellow",
    "suggestive": "dim yellow",
    "pass": "green",
    "skipped": "dim",
    "error": "magenta",
}


def render_console(findings: list[Finding], endpoint: str, console: Optional[Console] = None) -> None:
    console = console or Console()
    vulnerable = [f for f in findings if f.outcome == "vulnerable"]
    echo_only = [f for f in findings if f.outcome == "echo"]
    console.rule(f"[bold]jakk scan[/bold] :: {endpoint}")
    table = Table(title=f"Probe results ({len(findings)})", show_lines=False)
    table.add_column("outcome")
    table.add_column("severity")
    table.add_column("test id")
    table.add_column("signal")
    table.add_column("tool")
    table.add_column("evidence", overflow="fold")
    for f in findings:
        sev_style = _SEV_COLOR.get(f.severity, "white")
        out_style = _OUTCOME_STYLE.get(f.outcome, "white")
        # SECURITY: evidence and tool_name are attacker-controlled (they come
        # from the scanned server's responses / tool list). Rich INTERPRETS
        # markup like [red] / [/] / [link=...] in strings passed to add_row, so
        # an unescaped value lets a hostile server corrupt the operator's
        # terminal (or worse, exploit Rich markup features). escape() neutralises
        # the markup; the \n->⏎ replace keeps multi-line evidence on one row.
        evidence = _rich_escape((f.evidence or "").replace("\n", " ⏎ ")[:200])
        tool_name = _rich_escape(f.tool_name or "-")
        table.add_row(
            f"[{out_style}]{f.outcome}[/{out_style}]",
            f"[{sev_style}]{f.severity}[/{sev_style}]",
            _rich_escape(f.test_id),
            _rich_escape(f.expected_signal),
            tool_name,
            evidence,
        )
    console.print(table)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.outcome] = counts.get(f.outcome, 0) + 1
    summary = "  ".join(
        f"[{_OUTCOME_STYLE.get(k, 'white')}]{k}={v}[/{_OUTCOME_STYLE.get(k, 'white')}]"
        for k, v in sorted(counts.items())
    )
    console.print(f"[dim]Tests run: {len(findings)}[/dim]  {summary}")
    if vulnerable:
        console.print(
            f"[bold red]{len(vulnerable)} vulnerability {'finding' if len(vulnerable)==1 else 'findings'}[/bold red]"
            + (f"  +{len(echo_only)} echo-only" if echo_only else "")
        )
