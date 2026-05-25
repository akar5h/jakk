"""Attack-library loader.

A jakk library is a directory of YAML files, one per test. Each file
parses into a :class:`TestCase`. Loaders are deliberately strict — a
malformed file fails fast with the file path in the error.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable, Literal, Optional

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator


class AppliesTo(BaseModel):
    """Selector that decides which tools on a server the test fires against."""

    tool_name: Optional[str] = None
    """Exact tool name. Mutually compatible with tool_name_regex (both must match)."""

    tool_name_regex: Optional[str] = None
    """Python regex matched against tool name (re.search). Compiled at load time."""

    min_string_args: int = 0
    """Only fire if the tool's input schema has at least N string-typed args."""

    require_no_required_args: bool = False
    """If True, only match tools whose ``inputSchema.required`` is empty/absent.

    Useful for probes that intentionally call with empty arguments (the
    ``response.*`` family). Without this filter, those probes match
    args-required tools by name and then fail with ``isError=True``,
    producing noisy ``error`` outcomes that aren't a vulnerability signal.
    """

    none: bool = False
    """If True, do not call any tool — test inspects schema/listing only."""

    target_arg_kind: Optional[Literal["path", "query", "id", "url", "text"]] = None
    """Semantic role of the argument the probe wants to inject into.

    When set, the probe only fires on tools that expose an argument of the
    given role (regardless of what the server calls it). Resolution lives in
    ``applies.find_arg_of_kind`` — see the ``ARG_KINDS`` registry there for
    the per-kind name/description heuristics.

    Used together with the ``__target_arg__`` payload key (see
    :class:`Payload`). Without this field, payloads can still use
    ``__first_string_arg__`` for position-based resolution; with this field,
    they should use ``__target_arg__`` so the value lands in the right
    semantic slot, not just the leftmost string slot.

    Intentionally NO ``command`` kind: shell-injection probes target tools
    where the bug is "this arg gets interpolated into a shell command" — no
    semantic clue in the schema. Those keep ``__first_string_arg__``.
    """

    @field_validator("tool_name_regex")
    @classmethod
    def _validate_regex(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            re.compile(v)
        except re.error as exc:
            raise ValueError(f"invalid tool_name_regex {v!r}: {exc}") from exc
        return v


class Payload(BaseModel):
    """What to send to the tool. Templates like ``{run_id}`` are expanded at scan time."""

    tool: Optional[str] = None
    """Explicit tool name. If absent, scanner uses the matched tool from applies_to."""

    arguments: dict[str, Any] = Field(default_factory=dict)
    """Argument map. String values may use ``{run_id}`` and ``{first_string_arg}`` markers.

    Two reserved keys for position-blind argument resolution:

    - ``__first_string_arg__`` — assigns the value to whatever the FIRST
      string-typed parameter of the matched tool is. Useful when a probe has
      no semantic clue about which arg matters (e.g. shell-injection probes:
      "any string field that reaches a shell").
    - ``__target_arg__`` — assigns the value to the arg that matched
      ``applies_to.target_arg_kind``. Useful when a probe DOES have a
      semantic role (e.g. path-traversal: "fill the path-shaped arg").
      Errors at scan time if ``target_arg_kind`` is not set on the same probe.
    """


class Matcher(BaseModel):
    """How to decide if the probe fired."""

    kind: Literal[
        "substring",
        "regex",
        "marker_echo",
        "secret_pattern",
        "directive_passthrough",
        "schema_field",
        "cloud_metadata",
    ]
    params: dict[str, Any] = Field(default_factory=dict)


class AuthzPhase(BaseModel):
    """A single phase (call) of a two-credential authz probe."""

    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class CorroborateSpec(BaseModel):
    """Corroboration: differential + negative-canary for marker_echo probes.

    When set on a TestCase with ``matcher.kind == "marker_echo"``, the scanner
    runs three calls per matched tool instead of one:

      1. ``real_1``    — the configured payload, marker A
      2. ``real_2``    — the configured payload again, marker B (fresh run_id)
      3. ``negative``  — ``negative_arguments`` (no shell metacharacters), marker C

    Aggregate verdict:

      - real_1 fires + real_2 fires + negative does NOT fire → ``vulnerable`` (strong)
      - real_1 fires + real_2 fires + negative ALSO fires    → ``echo`` (server reflects all input)
      - exactly one of real_1 / real_2 fires                 → ``suggestive`` (intermittent)
      - neither real fires                                    → ``pass``
    """

    negative_arguments: dict[str, Any] = Field(default_factory=dict)
    """Payload with no shell metacharacters. Should look like the real payload
    but with safe content. ``{run_id}`` expanded at call time."""

    negative_marker_template: str
    """High-entropy marker template for the negative call. ``{run_id}`` is
    expanded at call time. The substring should appear in the response only
    if the server reflects raw input — that's the signal we use to classify
    echo vs vulnerable."""


class AuthOverride(BaseModel):
    """Auth state to use for a single probe instead of the scan-wide credentials.

    Used by auth-misconfig probes (``surface: auth``) to deliberately
    mis-authenticate and check whether the server accepts the request.
    """

    mode: Literal["none", "garbage", "wrong_prefix"]
    """- ``none``         — connect with no Authorization header.
       - ``garbage``      — send ``Authorization: Bearer garbage-<rand>``.
       - ``wrong_prefix`` — send the scan-wide bearer token *without* the ``Bearer `` prefix.
         Probe is skipped if the user did not provide a bearer to mutate.
    """

    expect_success: Literal["vulnerable", "pass"] = "vulnerable"
    """What it means if the probe *succeeds* (i.e. list_tools returned tools).
       Default ``vulnerable``: a server that accepts misauth is misconfigured.
       Operators can flip to ``pass`` for read-public-by-design servers."""


class TestCase(BaseModel):
    """One probe in the jakk attack library."""

    # Prevent pytest from trying to collect this Pydantic model as a test class.
    __test__ = False

    id: str
    """Dotted identifier, e.g. ``mcp.command.shell_marker``."""

    surface: Literal[
        "tool_call", "tool_list", "resource_list", "prompt_list", "auth", "authz"
    ]
    """Which MCP surface the test exercises.

    ``auth``  — opens a fresh connection with overridden credentials and
    classifies based on handshake success/failure. No matcher.

    ``authz`` — two-credential probe. Runs ``phase_a`` (sanity-check: A can
    read its own object) then ``phase_b`` (B attempts the same read). The
    matcher is applied to ``phase_b``'s response. Skipped if the operator
    didn't provide ``--cred-a`` / ``--cred-b`` / ``--foreign-id``.
    """

    description: str

    owasp: list[str] = Field(default_factory=list)
    """OWASP-for-MCP codes (e.g. MCP05). Free-form strings, not validated against a fixed enum."""

    atlas: list[str] = Field(default_factory=list)
    """MITRE ATLAS technique IDs (e.g. AML.T0051)."""

    severity: Literal["info", "low", "medium", "high", "critical"] = "medium"

    side_effect: Literal["safe", "unsafe"] = "unsafe"
    """Whether running this probe can mutate server state.

    - ``safe``   — read-only / schema-only probes. Safe to run unconditionally,
      including against production servers.
    - ``unsafe`` — may create / modify / send. Default for conservative reasons:
      a probe with no annotation must be assumed unsafe until reviewed.

    The ``--safe`` CLI flag filters the library to ``safe`` probes only.
    """

    expected_signal: str
    """Stable class label emitted on the finding (e.g. ``input.command_injection``)."""

    applies_to: AppliesTo = Field(default_factory=AppliesTo)
    payload: Payload = Field(default_factory=Payload)
    auth_override: Optional[AuthOverride] = None
    """Required for ``surface: auth`` probes; ignored otherwise."""
    phase_a: Optional[AuthzPhase] = None
    phase_b: Optional[AuthzPhase] = None
    """Required for ``surface: authz`` probes; ignored otherwise."""
    matcher: Optional[Matcher] = None
    """Required for tool_call / tool_list / authz surfaces; ignored for ``auth``."""
    corroborate: Optional[CorroborateSpec] = None
    """Optional. When set on a ``marker_echo`` probe, scanner runs 3 calls per
    matched tool (real_1 + real_2 + negative) and produces a single aggregated
    finding. Ignored on non-``marker_echo`` matchers."""

    @field_validator("id")
    @classmethod
    def _id_must_be_dotted(cls, v: str) -> str:
        if not v or " " in v or "/" in v:
            raise ValueError("id must be a dotted slug with no spaces or slashes")
        return v

    def model_post_init(self, _ctx: Any) -> None:
        """Cross-field validation: surface determines which fields are required."""
        if self.surface == "auth":
            if self.auth_override is None:
                raise ValueError(
                    f"TestCase {self.id!r}: surface=auth requires auth_override"
                )
            return
        if self.surface == "authz":
            if self.phase_a is None or self.phase_b is None:
                raise ValueError(
                    f"TestCase {self.id!r}: surface=authz requires phase_a and phase_b"
                )
            if self.matcher is None:
                raise ValueError(
                    f"TestCase {self.id!r}: surface=authz requires a matcher (applied to phase_b response)"
                )
            return
        # tool_call / tool_list / resource_list / prompt_list
        if self.matcher is None:
            raise ValueError(
                f"TestCase {self.id!r}: surface={self.surface} requires a matcher"
            )


def load_library(path: Path | str) -> list[TestCase]:
    """Load every ``*.yaml`` file in ``path`` into a list of :class:`TestCase`.

    Raises :class:`ValueError` with the offending file path if any document
    fails schema validation. Duplicate ids across files are an error.
    """
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"library directory does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"library path is not a directory: {root}")

    cases: list[TestCase] = []
    seen: dict[str, Path] = {}
    for yaml_path in sorted(root.glob("*.yaml")):
        try:
            data = yaml.safe_load(yaml_path.read_text())
        except yaml.YAMLError as exc:
            raise ValueError(f"YAML parse error in {yaml_path}: {exc}") from exc
        if data is None:
            raise ValueError(f"empty YAML document: {yaml_path}")
        try:
            case = TestCase(**data)
        except ValidationError as exc:
            raise ValueError(f"schema error in {yaml_path}: {exc}") from exc
        if case.id in seen:
            raise ValueError(
                f"duplicate test id {case.id!r}: {seen[case.id]} and {yaml_path}"
            )
        seen[case.id] = yaml_path
        cases.append(case)
    return cases


def filter_cases(
    cases: Iterable[TestCase],
    select: Optional[str] = None,
    owasp: Optional[str] = None,
    safe_only: bool = False,
) -> list[TestCase]:
    """Filter by ``--select`` (exact id), ``--owasp`` (membership in owasp list),
    and ``--safe`` (only ``side_effect: safe`` probes)."""
    out = list(cases)
    if select:
        out = [c for c in out if c.id == select]
    if owasp:
        owasp_upper = owasp.upper()
        out = [c for c in out if any(o.upper() == owasp_upper for o in c.owasp)]
    if safe_only:
        out = [c for c in out if c.side_effect == "safe"]
    return out
