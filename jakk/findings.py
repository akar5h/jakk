"""Finding model + JSONL/SARIF writers + console renderer."""
from __future__ import annotations

import hashlib
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


_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_SARIF_SECURITY_SEVERITY = {
    "critical": "9.0",
    "high": "8.0",
    "medium": "5.0",
    "low": "2.0",
    "info": "0.0",
}


def _sarif_rule(findings_for_rule: list[Finding]) -> dict[str, Any]:
    sample = findings_for_rule[0]
    tags = sorted({*sample.owasp, *sample.atlas, sample.expected_signal, sample.surface})
    return {
        "id": sample.test_id,
        "name": sample.test_id,
        "shortDescription": {"text": sample.expected_signal},
        "fullDescription": {
            "text": (
                f"jakk probe {sample.test_id} detects {sample.expected_signal} "
                f"on the MCP {sample.surface} surface."
            )
        },
        "defaultConfiguration": {
            "level": _SARIF_LEVEL.get(sample.severity, "warning"),
        },
        "properties": {
            "precision": "high",
            "problem.severity": sample.severity,
            "security-severity": _SARIF_SECURITY_SEVERITY.get(sample.severity, "0.0"),
            "tags": [t for t in tags if t],
        },
    }


def _sarif_fingerprint(finding: Finding) -> str:
    basis = {
        "test_id": finding.test_id,
        "endpoint": finding.endpoint,
        "tool_name": finding.tool_name,
        "outcome": finding.outcome,
        "expected_signal": finding.expected_signal,
    }
    raw = json.dumps(basis, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _sarif_result(finding: Finding) -> dict[str, Any]:
    tool = f" via tool {finding.tool_name}" if finding.tool_name else ""
    message = (
        f"{finding.outcome}: {finding.test_id}{tool} on {finding.endpoint}. "
        f"Evidence: {finding.evidence or '<none>'}"
    )
    return {
        "ruleId": finding.test_id,
        "level": _SARIF_LEVEL.get(finding.severity, "warning"),
        "message": {"text": message[:4000]},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        # MCP findings are target-level rather than source-line
                        # findings. Use a synthetic relative artifact URI so
                        # GitHub code scanning can ingest and group the alert
                        # while JSONL carries the full per-call record.
                        "uri": "jakk-mcp-scan",
                    }
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": _sarif_fingerprint(finding),
        },
        "properties": {
            "endpoint": finding.endpoint,
            "tool_name": finding.tool_name,
            "surface": finding.surface,
            "severity": finding.severity,
            "outcome": finding.outcome,
            "expected_signal": finding.expected_signal,
            "owasp": finding.owasp,
            "atlas": finding.atlas,
            "payload": finding.payload,
            "evidence": finding.evidence,
        },
    }


def to_sarif(findings: list[Finding]) -> dict[str, Any]:
    """Convert fired findings to SARIF 2.1.0.

    JSONL remains the complete scan transcript. SARIF intentionally contains
    only actionable fired findings, so GitHub code scanning does not fill with
    pass/skipped/error noise.
    """
    fired = [f for f in findings if f.fired]
    by_rule: dict[str, list[Finding]] = {}
    for finding in fired:
        by_rule.setdefault(finding.test_id, []).append(finding)
    rules = [_sarif_rule(by_rule[k]) for k in sorted(by_rule)]
    results = [_sarif_result(f) for f in fired]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "jakk",
                        "informationUri": "https://github.com/akar5h/jakk",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(findings: list[Finding], path: Path | str) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(to_sarif(findings), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


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
