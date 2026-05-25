"""Security-regression tests for jakk's own attack surface.

These pin the hardening from the 2026-05-23 self-audit: jakk consumes
UNTRUSTED data from the servers it scans (tool responses, tool names,
schemas). A scanned server must not be able to corrupt the operator's
terminal or exhaust scanner memory.
"""
from __future__ import annotations

from jakk.findings import Finding, render_console
from jakk.mcp_client import _MAX_RESPONSE_CHARS, _flatten_content


# ---------------------------------------------------------------------------
# Rich-markup injection — a hostile server's response/tool-name must not be
# interpreted as terminal markup when rendered.
# ---------------------------------------------------------------------------

class _FakeContentBlock:
    def __init__(self, text):
        self.text = text
        self.data = None


class _FakeResult:
    def __init__(self, text):
        self.content = [_FakeContentBlock(text)]
        self.data = None
        self.structuredContent = None
        self.isError = False


def test_render_escapes_markup_in_evidence(capsys):
    """Evidence containing Rich markup must be escaped, not interpreted."""
    finding = Finding(
        test_id="t.x", expected_signal="x", severity="high", surface="tool_call",
        endpoint="http://e", fired=True, outcome="vulnerable",
        tool_name="benign_tool",
        evidence="[red]PWNED[/red] [link=file:///etc/passwd]click[/link]",
    )
    render_console([finding], "http://e", console=None)
    out = capsys.readouterr().out
    # The literal markup characters survive (escaped), i.e. the bracket text is
    # shown rather than consumed as a style directive.
    assert "PWNED" in out
    # The escaped form keeps the brackets visible somewhere in the output.
    assert "[red]" in out or "\\[red]" in out


def test_render_escapes_markup_in_tool_name(capsys):
    """Tool names come from the server's tool list — also untrusted."""
    finding = Finding(
        test_id="t.x", expected_signal="x", severity="high", surface="tool_call",
        endpoint="http://e", fired=True, outcome="vulnerable",
        tool_name="[bold red]evil_tool[/bold red]",
        evidence="ok",
    )
    render_console([finding], "http://e", console=None)
    out = capsys.readouterr().out
    assert "evil_tool" in out


def test_render_does_not_crash_on_unbalanced_markup(capsys):
    """A server returning unbalanced/garbage markup must not raise."""
    finding = Finding(
        test_id="t.x", expected_signal="x", severity="low", surface="tool_call",
        endpoint="http://e", fired=False, outcome="pass",
        tool_name="t", evidence="[/][/][unclosed value=[[[",
    )
    render_console([finding], "http://e", console=None)  # must not raise


# ---------------------------------------------------------------------------
# Response-size cap — a hostile server returning a huge body must not OOM us.
# ---------------------------------------------------------------------------

def test_flatten_content_caps_oversized_response():
    huge = "A" * (5 * 1024 * 1024)  # 5 MiB
    out = _flatten_content(_FakeResult(huge))
    assert len(out) <= _MAX_RESPONSE_CHARS + 64  # cap + truncation marker
    assert "truncated by jakk" in out


def test_flatten_content_preserves_small_response():
    out = _flatten_content(_FakeResult("small body"))
    assert out == "small body"


def test_flatten_content_cap_is_configurable():
    out = _flatten_content(_FakeResult("X" * 1000), max_chars=100)
    assert len(out) <= 100 + 64
    assert out.startswith("X" * 100)


def test_flatten_content_truncates_early_content_block():
    """Even a single oversized content block is capped (early secrets/markers
    still survive within the first MiB)."""
    body = "MARKER-AT-START " + ("B" * (3 * 1024 * 1024))
    out = _flatten_content(_FakeResult(body))
    assert out.startswith("MARKER-AT-START ")
    assert len(out) <= _MAX_RESPONSE_CHARS + 64


# ---------------------------------------------------------------------------
# Credential redaction — operator secrets must not land in stored findings.
# ---------------------------------------------------------------------------

def test_redact_args_masks_known_credentials():
    from jakk.scanner import ScanConfig, _redact_args
    cfg = ScanConfig(endpoint="http://e", bearer="ghp_realtoken", cred_a="alpha-key", cred_b="bravo-key")
    args = {"api_key": "alpha-key", "project_id": "CRM-1001", "token": "ghp_realtoken"}
    out = _redact_args(args, cfg)
    assert out == {"api_key": "<cred_a>", "project_id": "CRM-1001", "token": "<bearer>"}


def test_redact_args_noop_when_no_secrets():
    from jakk.scanner import ScanConfig, _redact_args
    cfg = ScanConfig(endpoint="http://e")
    args = {"owner": "octocat", "repo": "Hello-World"}
    assert _redact_args(args, cfg) == args


def test_redact_args_leaves_nonmatching_values():
    from jakk.scanner import ScanConfig, _redact_args
    cfg = ScanConfig(endpoint="http://e", cred_a="secret123")
    args = {"x": "not-the-secret", "y": "secret123"}
    out = _redact_args(args, cfg)
    assert out == {"x": "not-the-secret", "y": "<cred_a>"}
