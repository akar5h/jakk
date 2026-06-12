"""Matchers — decide whether a probe response indicates the test fired.

Each matcher consumes:
- the probe payload that was sent (so it can resolve ``{run_id}``/marker expansions),
- the response text (a single flattened string of the tool result), and
- an optional context dict (e.g. tool schema for schema_field).

Each returns a :class:`MatcherResult` with ``fired: bool`` and a short
``evidence`` snippet that lands in the finding.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Optional


Outcome = str  # "vulnerable" | "echo" | "pass" | "skipped" | "error"


@dataclass
class MatcherResult:
    fired: bool
    evidence: str = ""
    outcome: Outcome = "pass"
    """Refined verdict beyond fired/not-fired:
       - ``vulnerable``: probe produced evidence that exceeds simple input reflection
         (file contents, expanded shell substitution, schema directives, ...).
       - ``echo``: marker appears in response but the surrounding payload syntax was
         reflected unchanged — server echoed input but did not interpret it.
       - ``pass``: no signal.
       - ``skipped``: not applicable to this server.
       - ``error``: probe could not be evaluated (transport error, etc.).
    """


MatcherFn = Callable[[dict[str, Any], str, dict[str, Any]], MatcherResult]


_REGISTRY: dict[str, MatcherFn] = {}


def register(kind: str) -> Callable[[MatcherFn], MatcherFn]:
    def deco(fn: MatcherFn) -> MatcherFn:
        _REGISTRY[kind] = fn
        return fn
    return deco


def get_matcher(kind: str) -> MatcherFn:
    if kind not in _REGISTRY:
        raise KeyError(f"no matcher registered for kind={kind!r}")
    return _REGISTRY[kind]


def _snippet(text: str, needle: str, radius: int = 60) -> str:
    idx = text.find(needle)
    if idx < 0:
        return text[: 2 * radius]
    start = max(0, idx - radius)
    end = min(len(text), idx + len(needle) + radius)
    return text[start:end]


# ---------------------------------------------------------------------------
# Built-in matchers
# ---------------------------------------------------------------------------


@register("substring")
def _substring(params: dict[str, Any], response: str, ctx: dict[str, Any]) -> MatcherResult:
    needle = params.get("needle", "")
    if not needle:
        return MatcherResult(False, "substring matcher: empty needle", "error")
    fired = needle in response
    return MatcherResult(
        fired,
        _snippet(response, needle) if fired else "",
        "vulnerable" if fired else "pass",
    )


@register("regex")
def _regex(params: dict[str, Any], response: str, ctx: dict[str, Any]) -> MatcherResult:
    pattern = params.get("pattern", "")
    if not pattern:
        return MatcherResult(False, "regex matcher: empty pattern", "error")
    flags = re.IGNORECASE if params.get("ignore_case", False) else 0
    m = re.search(pattern, response, flags)
    if not m:
        return MatcherResult(False, "", "pass")
    return MatcherResult(True, _snippet(response, m.group(0)), "vulnerable")


# Shell metacharacter literals that, if echoed back alongside the marker,
# indicate the server reflected the raw payload rather than interpreting it.
_SHELL_ECHO_TELLS: tuple[str, ...] = ("$(", "${", "`echo", "; cat", "&& cat", "| cat")


@register("marker_echo")
def _marker_echo(params: dict[str, Any], response: str, ctx: dict[str, Any]) -> MatcherResult:
    """Decide if a unique per-run marker appears in the response, and classify the outcome.

    Outcome rules:

    - ``pass``     — marker absent.
    - ``echo``     — marker present AND payload-shaped shell metacharacters (e.g.
      ``$(echo ...)``) also present near the marker. The server reflected the raw
      input but did not interpret it. NOT a command-injection finding by itself;
      may indicate a separate output-reflection issue.
    - ``vulnerable`` — marker present without the surrounding payload syntax.
      Implies shell expansion happened: the substituted command ran and its
      output was used by the host command.
    """
    marker: str = params.get("marker", "")
    if not marker:
        return MatcherResult(False, "marker_echo: no marker resolved", "error")
    if marker not in response:
        return MatcherResult(False, "", "pass")

    # Look at a window around the marker for echo-tells.
    window = _snippet(response, marker, radius=80)
    tell_hit = next((t for t in _SHELL_ECHO_TELLS if t in window), None)
    if tell_hit is not None:
        return MatcherResult(True, f"[echo-only] {window}", "echo")
    return MatcherResult(True, _snippet(response, marker), "vulnerable")


_DEFAULT_SECRET_PATTERNS: tuple[str, ...] = (
    # File contents that should never appear in a normal tool response.
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"root:x:0:0:",                          # /etc/passwd first line
    r"\bFLAG\{[^}]+\}",                       # CTF flag style (ch08 canary)
    # Token-shaped strings near a key=value assignment.
    r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}",
    r"AKIA[0-9A-Z]{16}",                      # AWS access-key id
    r"ghp_[A-Za-z0-9]{30,}",                  # GitHub PAT
    r"sk-[A-Za-z0-9]{20,}",                   # OpenAI-style key
)


@register("secret_pattern")
def _secret_pattern(params: dict[str, Any], response: str, ctx: dict[str, Any]) -> MatcherResult:
    extra = tuple(params.get("patterns", ()))
    for pat in (*_DEFAULT_SECRET_PATTERNS, *extra):
        m = re.search(pat, response)
        if m:
            return MatcherResult(True, _snippet(response, m.group(0)), "vulnerable")
    return MatcherResult(False, "", "pass")


# ---------------------------------------------------------------------------
# cloud_metadata — SSRF success detector
# ---------------------------------------------------------------------------
#
# This matcher decides whether an SSRF probe SUCCEEDED, by looking for the
# distinctive shape of a cloud instance-metadata response in the tool's reply.
#
# Background — why this is the SSRF signal:
#   An SSRF (Server-Side Request Forgery) bug is "the server will fetch any
#   URL you give it, from its own network position." The single most damaging
#   target is the cloud metadata endpoint at the link-local address
#   169.254.169.254, reachable ONLY from inside the instance. It hands out the
#   instance's IAM/role credentials — temporary AWS keys, GCP OAuth tokens,
#   Azure tokens. If a tool fetches that URL and returns the body, the caller
#   gets cloud credentials = full account pivot. BlueRock found 36.7% of 7,000
#   scanned MCP servers vulnerable to exactly this (May 2026).
#
# Why a DEDICATED matcher (not just secret_pattern):
#   We want PRECISE, low-false-positive evidence that what came back is a
#   metadata response specifically — not just "something secret-shaped." The
#   patterns below match the documented response *structure* of each cloud's
#   metadata service, so a `vulnerable` here means "we pulled an actual
#   metadata document," which is unambiguous and directly reportable.
#
# Coverage notes:
#   - AWS IMDSv1 is the primary, most-reachable target: a plain GET to
#     /latest/meta-data/iam/security-credentials/<role> needs NO special
#     headers, so any naive URL-fetch reaches it. This is what the shipped
#     probe aims at.
#   - GCP and Azure metadata require request headers (Metadata-Flavor: Google /
#     Metadata: true) that a naive fetch usually won't add — so they're less
#     reachable via pure-URL SSRF, but we still detect their response shapes
#     in case a server proxies headers through.
_CLOUD_METADATA_PATTERNS: tuple[tuple[str, str], ...] = (
    # ---- AWS EC2 Instance Metadata Service (IMDS) -----------------------
    # The IAM security-credentials document. These four keys appear together
    # in the JSON returned by .../iam/security-credentials/<role>. Matching
    # AccessKeyId + SecretAccessKey is already conclusive.
    (r'"AccessKeyId"\s*:\s*"', "AWS IMDS: AccessKeyId field"),
    (r'"SecretAccessKey"\s*:\s*"', "AWS IMDS: SecretAccessKey field"),
    # Temporary STS credentials (what IMDS hands out) always start ASIA.
    # (Long-lived keys start AKIA — also worth flagging if they leak here.)
    (r"\bASIA[0-9A-Z]{16}\b", "AWS temporary access key id (ASIA...)"),
    # The success envelope IMDS wraps creds in.
    (r'"Code"\s*:\s*"Success"', "AWS IMDS: Code:Success envelope"),

    # ---- GCP Compute metadata -------------------------------------------
    # The token endpoint returns an OAuth2 access token. GCP access tokens
    # carry the distinctive ya29. prefix.
    (r'"access_token"\s*:\s*"ya29\.', "GCP metadata: ya29. access token"),
    # GCP requires this header on requests; servers that echo it confirm reach.
    (r"(?i)Metadata-Flavor:\s*Google", "GCP metadata: Metadata-Flavor header echo"),

    # ---- Azure Instance Metadata Service (IMDS) -------------------------
    # Azure token responses pair an access_token with a client_id; the
    # /metadata/instance/compute document carries vmId + subscriptionId.
    (r'"access_token"\s*:\s*"[^"]+"\s*,\s*"client_id"', "Azure IMDS: token + client_id"),
    (r'"subscriptionId"\s*:\s*"[0-9a-fA-F-]{36}"', "Azure IMDS: subscriptionId GUID"),
)


@register("cloud_metadata")
def _cloud_metadata(params: dict[str, Any], response: str, ctx: dict[str, Any]) -> MatcherResult:
    """Fire ``vulnerable`` when the response looks like a cloud metadata document.

    Used by SSRF probes: the probe sends the server a metadata-endpoint URL
    (e.g. ``http://169.254.169.254/latest/meta-data/iam/security-credentials/``)
    as a tool argument; if the server fetched it and returned the body, the
    body will match one of the cloud-specific shapes below and we report the
    SSRF as exploited.

    Outcome:
      - ``vulnerable`` — a metadata-response shape matched (credentials reached
        the caller).
      - ``pass`` — no metadata shape present (server blocked the fetch, refused
        the link-local address, or isn't running in that cloud).

    Operators can pass extra ``params.patterns`` (list of regex strings) to
    cover bespoke internal-metadata services beyond the big-three clouds.
    """
    extra_patterns = tuple(params.get("patterns", ()))
    # Built-in (regex, label) pairs first, then any operator-supplied bare regexes.
    for pat, label in _CLOUD_METADATA_PATTERNS:
        m = re.search(pat, response)
        if m:
            return MatcherResult(True, f"{label}: {_snippet(response, m.group(0))}", "vulnerable")
    for pat in extra_patterns:
        m = re.search(pat, response)
        if m:
            return MatcherResult(True, _snippet(response, m.group(0)), "vulnerable")
    return MatcherResult(False, "", "pass")


_DIRECTIVE_PATTERNS: tuple[str, ...] = (
    # Case-SENSITIVE uppercase SYSTEM: — the prompt-injection convention. A
    # lowercase `system:` is an extremely common benign doc/field label (e.g.
    # "Returns:\n  system: the OS name"), so matching it case-insensitively
    # cry-wolfed on normal tool descriptions (found scanning memory-shell-mcp,
    # 2026-06-12). The imperative patterns below carry the real detection.
    r"(?m)^\s*SYSTEM\s*[:>]",
    r"(?im)ignore (all )?previous (instructions|messages|prompts)",
    r"(?im)disregard (the )?(above|prior|previous)",
    r"(?im)^\s*<\s*system\s*>",
    r"(?im)you are now (a|an|the) ",
    r"(?im)forget (everything|all) (you|previous)",
    r"(?im)new instructions?\s*[:>]",
)


@register("directive_passthrough")
def _directive_passthrough(
    params: dict[str, Any], response: str, ctx: dict[str, Any]
) -> MatcherResult:
    extra = tuple(params.get("patterns", ()))
    for pat in (*_DIRECTIVE_PATTERNS, *extra):
        m = re.search(pat, response)
        if m:
            return MatcherResult(True, _snippet(response, m.group(0)), "vulnerable")
    return MatcherResult(False, "", "pass")


# Database-engine syntax-error signatures. These strings only surface when
# attacker-controlled input reached the SQL parser as code (string
# concatenation) rather than as a bound parameter. A parameterised query treats
# an injected quote as data and never emits these — so a hit is a low-false-
# positive signal that the arg is SQL-injectable. Engine-specific on purpose:
# generic "error" would over-match.
_SQL_ERROR_PATTERNS: tuple[str, ...] = (
    r"(?i)syntax error at or near ",                 # PostgreSQL
    r"(?i)unterminated quoted string",               # PostgreSQL
    r"(?i)(psycopg2?|asyncpg)\.[A-Za-z]*Error",      # PostgreSQL drivers
    r"(?i)you have an error in your sql syntax",      # MySQL / MariaDB
    r"(?i)SQLSTATE\[",                                # PDO / JDBC
    r"(?i)sqlite3?\.(OperationalError|Warning)",      # SQLite (python)
    r"(?i)SQL logic error",                           # SQLite
    r"(?i)unrecognized token:",                       # SQLite
    r"(?i)near \"[^\"]*\": syntax error",             # SQLite
    r"(?i)\bORA-\d{5}\b",                             # Oracle
    r"(?i)unclosed quotation mark after the character string",  # MS SQL Server
    r"(?i)microsoft.*odbc.*sql server",              # MS SQL Server
)


@register("sql_error")
def _sql_error(params: dict[str, Any], response: str, ctx: dict[str, Any]) -> MatcherResult:
    """Fire ``vulnerable`` when the response carries a database-engine syntax
    error — the error-based SQL-injection signal.

    The probe injects an unbalanced quote into a data-shaped argument. If the
    server concatenates that arg into a SQL string, the parser breaks and emits
    an engine-specific syntax error (matched below). A server using bound
    parameters treats the quote as data → no error → ``pass``.

    This is a content-class signal, NOT a reflection-class one: the error text
    IS the finding, so it stays ``vulnerable`` even inside an ``isError`` tool
    result (a SQL error is normally returned as an error). Operators can pass
    extra ``params.patterns`` for bespoke ORMs/wrappers.

    Caveat: tools that take RAW SQL by design (e.g. ``execute_sql(sql=...)``)
    will also error on a lone quote; the shipped probe targets ``query``-kind
    args to avoid those, but a raw-SQL tool named with a data-shaped arg could
    still produce a benign-by-design hit. Triage against the tool's intent.
    """
    extra = tuple(params.get("patterns", ()))
    for pat in (*_SQL_ERROR_PATTERNS, *extra):
        m = re.search(pat, response)
        if m:
            return MatcherResult(True, _snippet(response, m.group(0)), "vulnerable")
    return MatcherResult(False, "", "pass")


@register("schema_field")
def _schema_field(params: dict[str, Any], response: str, ctx: dict[str, Any]) -> MatcherResult:
    """Inspect tool schemas/descriptions (passed via ctx['tools']) for hidden content.

    Looks for directive-style language in tool descriptions or in JSON-schema
    ``description`` fields — the canonical 'tool poisoning via description'
    pattern from the Invariant Labs writeup.
    """
    tools = ctx.get("tools") or []
    patterns: list[str] = list(params.get("patterns", []))
    if not patterns:
        patterns = list(_DIRECTIVE_PATTERNS)
    for tool in tools:
        haystack_parts: list[str] = []
        for key in ("description", "instructions"):
            val = tool.get(key)
            if isinstance(val, str):
                haystack_parts.append(val)
        schema = tool.get("inputSchema") or tool.get("input_schema") or {}
        # Walk schema for description fields.
        for _key, val in _walk_strings(schema):
            haystack_parts.append(val)
        haystack = "\n".join(haystack_parts)
        for pat in patterns:
            m = re.search(pat, haystack)
            if m:
                name = tool.get("name", "<anonymous>")
                return MatcherResult(
                    True,
                    f"tool={name} :: {_snippet(haystack, m.group(0))}",
                    "vulnerable",
                )
    return MatcherResult(False, "", "pass")


def _walk_strings(obj: Any) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                out.append((k, v))
            else:
                out.extend(_walk_strings(v))
    elif isinstance(obj, list):
        for item in obj:
            out.extend(_walk_strings(item))
    return out


def run_matcher(
    kind: str,
    params: dict[str, Any],
    response: str,
    ctx: Optional[dict[str, Any]] = None,
) -> MatcherResult:
    return get_matcher(kind)(params or {}, response or "", ctx or {})
