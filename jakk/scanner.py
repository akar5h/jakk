"""Scan orchestration."""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any, Optional

from .applies import select_tools
from .findings import Finding
from .library import TestCase
from .matchers import MatcherResult, run_matcher
from .mcp_client import CallResult, MCPClient, ToolDescriptor


@dataclass
class ScanConfig:
    endpoint: str
    timeout_s: float = 15.0
    bearer: Optional[str] = None
    headers: Optional[dict[str, str]] = None
    cred_a: Optional[str] = None
    cred_b: Optional[str] = None
    foreign_id: Optional[str] = None
    context_args: Optional[dict[str, str]] = None
    """Operator-supplied values for non-target tool arguments (``--arg k=v``).

    Many production tools take several required args, only one of which is the
    injection target (e.g. ``get_file_contents(owner, repo, path)`` — we inject
    into ``path`` but ``owner``/``repo`` must be valid for the call to run).
    These fill any tool-declared arg the probe didn't set, so the call reaches
    the code path under test instead of erroring on a missing parameter."""
    canary_path: Optional[str] = None
    """Operator-supplied path for path-traversal probes (``--canary-path``).

    The path probes default to the breach-to-fix lab layout
    (``/app/files/safe_files_sensitive/...``), which only exists in the lab. On a
    real target that path doesn't exist, so the probe can't actually exercise the
    traversal. When set, this overrides the path-kind target arg with a path the
    operator knows is sensitive / out-of-scope on the real server (e.g.
    ``/etc/passwd``). Unset → the YAML's lab default is used unchanged."""


def _run_id() -> str:
    return secrets.token_hex(4)


def _redact_args(args: dict[str, Any], cfg: "ScanConfig") -> dict[str, Any]:
    """Mask operator secrets in a payload dict before it's stored in a Finding.

    SECURITY: findings (esp. JSONL) get committed, shared, attached to bug
    reports, ingested by CI. The actual tool call uses the real values; only
    the STORED/DISPLAYED copy is masked. Replaces any string arg whose value
    exactly equals a known secret (--bearer / --cred-a / --cred-b) with a
    placeholder, so credentials never land in output files.
    """
    secrets_map: dict[str, str] = {}
    if cfg.bearer:
        secrets_map[cfg.bearer] = "<bearer>"
    if cfg.cred_a:
        secrets_map[cfg.cred_a] = "<cred_a>"
    if cfg.cred_b:
        secrets_map[cfg.cred_b] = "<cred_b>"
    if not secrets_map:
        return args
    return {
        k: (secrets_map.get(v, v) if isinstance(v, str) else v)
        for k, v in args.items()
    }


def _skip_evidence(prefix: str, exc: Exception) -> str:
    """Actionable skip evidence. For unsatisfied required args, tell the
    operator exactly which ``--arg`` values to supply."""
    if isinstance(exc, _UnsatisfiedRequiredArgs):
        hint = " ".join(f"--arg {name}=<value>" for name in exc.missing)
        return (
            f"{prefix}: tool needs required arg(s) {exc.missing} not satisfied by "
            f"the probe or context. Supply: {hint}"
        )
    return f"{prefix}: {exc}"


class _UnresolvedFirstStringArg(Exception):
    """Raised when a payload uses ``__first_string_arg__`` but the matched tool exposes no string-typed arg."""


class _UnresolvedTargetArg(Exception):
    """Raised when a payload uses ``__target_arg__`` but either
    ``target_arg_kind`` isn't set on the probe, or no arg of that kind exists
    on the matched tool. In practice ``applies.matches()`` already filters
    out tools missing the kind, so this surfaces only on misconfigured YAML."""


class _UnsatisfiedRequiredArgs(Exception):
    """Raised when, after filling the target arg + payload args + context args,
    the tool still has required arguments with no value. Carries the missing
    names so the scanner can emit an actionable ``skipped`` finding telling the
    operator which ``--arg k=v`` values to supply — instead of firing a doomed
    call that the server rejects with a generic 'missing parameter' error."""

    def __init__(self, missing: list[str]):
        self.missing = missing
        super().__init__("missing required args: " + ", ".join(missing))


def _resolve_arguments(
    arguments: dict[str, Any],
    tool: Optional[ToolDescriptor],
    run_id: str,
    target_arg_kind: Optional[str] = None,
    context_args: Optional[dict[str, str]] = None,
    canary_path: Optional[str] = None,
) -> dict[str, Any]:
    """Expand template strings, position-blind keys, and operator context args.

    Resolution order:
      1. ``__first_string_arg__`` → first string-typed arg on the tool. Errors
         if the tool has no string args.
      2. ``__target_arg__`` → arg matching the probe's ``target_arg_kind`` via
         :func:`applies.find_arg_of_kind`. Errors if the kind isn't set or no
         arg matches.
      3. Explicit payload args (with ``{run_id}`` expansion).
      4. **Context args** (``--arg k=v``): fill any arg the TOOL declares that
         the probe didn't already set. Scoped to tool-declared args so we never
         send a parameter the tool doesn't accept.
      5. **Required-arg check**: if the tool still has unfilled required args,
         raise :class:`_UnsatisfiedRequiredArgs` so the scanner emits an
         actionable ``skipped`` ("supply --arg owner=...").

    Each error path produces an explicit ``skipped`` finding upstream rather
    than silently sending the tool an incomplete argument map.
    """
    # Local import to avoid a circular: applies imports from library, scanner
    # imports from applies, library imports nothing from scanner.
    from .applies import find_arg_of_kind

    resolved: dict[str, Any] = {}
    first_arg = tool.first_string_arg() if tool else None

    target_arg: Optional[str] = None
    if tool is not None and target_arg_kind is not None:
        target_arg = find_arg_of_kind(tool, target_arg_kind)

    # Steps 1-3: probe-supplied args (target + explicit).
    for key, value in arguments.items():
        if key == "__first_string_arg__":
            if first_arg is None:
                raise _UnresolvedFirstStringArg(
                    f"tool {tool.name if tool else '<none>'} has no string-typed argument"
                )
            key = first_arg
        elif key == "__target_arg__":
            if target_arg_kind is None:
                raise _UnresolvedTargetArg(
                    "__target_arg__ used in payload but applies_to.target_arg_kind is not set"
                )
            if target_arg is None:
                raise _UnresolvedTargetArg(
                    f"tool {tool.name if tool else '<none>'} has no argument matching "
                    f"target_arg_kind={target_arg_kind!r}"
                )
            key = target_arg
            # Operator override: when scanning a real server, the YAML's lab
            # default path doesn't exist. Replace the path-kind target value
            # with the operator-supplied --canary-path so the probe exercises
            # THIS server. Scoped to path-kind args so we never retarget a
            # non-path injection point.
            if canary_path is not None and target_arg_kind == "path":
                value = canary_path
        if isinstance(value, str):
            value = value.replace("{run_id}", run_id)
        resolved[key] = value

    # Step 4: context args fill tool-declared args the probe didn't set.
    if tool is not None and context_args:
        for k, v in context_args.items():
            if k in resolved:
                continue  # probe's value wins over context
            if tool.has_arg(k):
                resolved[k] = v.replace("{run_id}", run_id) if isinstance(v, str) else v

    # Step 5: required-arg satisfaction check.
    if tool is not None:
        missing = [r for r in tool.required_args() if r not in resolved]
        if missing:
            raise _UnsatisfiedRequiredArgs(missing)

    return resolved


def _resolve_matcher_params(params: dict[str, Any], run_id: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in params.items():
        if isinstance(v, str):
            v = v.replace("{run_id}", run_id)
        out[k] = v
    # Convenience: if a marker_template is provided, expose it as ``marker`` resolved.
    if "marker_template" in out and "marker" not in out:
        out["marker"] = str(out["marker_template"]).replace("{run_id}", run_id)
    return out


async def run_scan(cases: list[TestCase], cfg: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []

    # Auth probes don't use the shared client (they need overridden credentials);
    # run them first against fresh per-probe connections.
    auth_cases = [c for c in cases if c.surface == "auth"]
    authz_cases = [c for c in cases if c.surface == "authz"]
    other_cases = [c for c in cases if c.surface not in ("auth", "authz")]

    for case in auth_cases:
        findings.append(await _run_auth_case(case, cfg))

    for case in authz_cases:
        findings.append(await _run_authz_case(case, cfg))

    if other_cases:
        client = MCPClient(
            cfg.endpoint,
            timeout_s=cfg.timeout_s,
            bearer=cfg.bearer,
            headers=cfg.headers,
        )
        try:
            await client.__aenter__()
        except Exception as exc:
            # Handshake/connection failed before we could probe anything.
            outcome, reason = _shared_client_failure(exc)
            findings.extend(_surface_findings(other_cases, cfg, outcome, reason))
            return findings
        try:
            try:
                tools = await client.list_tools()
            except Exception as exc:
                # Couldn't enumerate the tool surface (auth wall, server error).
                # Emit a skip/error PER probe instead of aborting the whole scan.
                outcome, reason = _shared_client_failure(exc)
                findings.extend(_surface_findings(other_cases, cfg, outcome, reason))
                return findings
            tools_ctx = [t.to_dict() for t in tools]
            cases = list(other_cases)
            reconnects = 0
            idx = 0
            while idx < len(cases):
                case = cases[idx]
                case_findings = await _run_case(client, case, tools, tools_ctx, cfg)
                # If the transport dropped mid-scan (server/bridge died, session
                # lost), the shared client is dead and EVERY remaining probe would
                # error against it. Reconnect once and retry this probe instead of
                # silently voiding the rest of the scan. Bounded by _MAX_RECONNECTS
                # so a server that drops on every call can't loop forever.
                if _has_transport_drop(case_findings) and reconnects < _MAX_RECONNECTS:
                    reconnects += 1
                    client, ok = await _reconnect_client(client, cfg)
                    if ok:
                        continue  # retry the same probe on the fresh client
                    # Reconnect failed — the endpoint is gone. Mark this probe and
                    # everything after it as error, with a reason, and stop.
                    findings.extend(
                        _surface_findings(
                            cases[idx:], cfg, "error",
                            "transport dropped mid-scan; reconnect failed — "
                            "remaining tool-surface probes not run",
                        )
                    )
                    return findings
                findings.extend(case_findings)
                idx += 1
        finally:
            try:
                await client.__aexit__(None, None, None)
            except Exception:
                pass
    return findings


def _expand_authz_template(value: Any, cfg: ScanConfig, run_id: str) -> Any:
    """Expand {cred_a} / {cred_b} / {foreign_id} / {run_id} in string values."""
    if not isinstance(value, str):
        return value
    return (
        value.replace("{cred_a}", cfg.cred_a or "")
        .replace("{cred_b}", cfg.cred_b or "")
        .replace("{foreign_id}", cfg.foreign_id or "")
        .replace("{run_id}", run_id)
    )


async def _run_corroborated_marker_echo(
    client: MCPClient,
    case: TestCase,
    tool: ToolDescriptor,
    all_tools: list[ToolDescriptor],
    cfg: ScanConfig,
) -> Finding:
    """3-call corroboration for a marker_echo probe. Real_1 + real_2 + negative."""
    assert case.matcher is not None and case.matcher.kind == "marker_echo"
    assert case.corroborate is not None

    target = case.payload.tool or tool.name
    real_template = case.matcher.params.get("marker_template", "")
    neg_template = case.corroborate.negative_marker_template

    # Three independent run_ids → three independent markers.
    calls: list[dict[str, Any]] = []
    for label, args_src, marker_template in (
        ("real_1", case.payload.arguments, real_template),
        ("real_2", case.payload.arguments, real_template),
        ("negative", case.corroborate.negative_arguments, neg_template),
    ):
        run_id = _run_id()
        try:
            args = _resolve_arguments(
                args_src, tool, run_id, case.applies_to.target_arg_kind,
                cfg.context_args, cfg.canary_path,
            )
        except (_UnresolvedFirstStringArg, _UnresolvedTargetArg, _UnsatisfiedRequiredArgs) as exc:
            return Finding(
                test_id=case.id,
                expected_signal=case.expected_signal,
                severity=case.severity,
                surface=case.surface,
                endpoint=cfg.endpoint,
                fired=False,
                outcome="skipped",
                tool_name=target,
                evidence=_skip_evidence(f"corroborate phase {label}", exc),
                owasp=list(case.owasp),
                atlas=list(case.atlas),
            )
        marker = marker_template.replace("{run_id}", run_id)
        call = await client.call_tool(target, args)
        result = run_matcher("marker_echo", {"marker": marker}, call.text, {})
        entry: dict[str, Any] = {
            "label": label,
            "args": _redact_args(args, cfg),
            "marker": marker,
            "fired": result.fired,
            "evidence": result.evidence,
            "response": call.text,
            "is_error": call.is_error,
        }
        # matcher_outcome distinguishes vulnerable/echo/pass for the REAL calls
        # (the matcher's shell-syntax check tells us if the response wraps the
        # marker in `$(echo …)`). For the NEGATIVE call the payload has no
        # shell syntax to begin with, so matcher_outcome is uninformative
        # there — we omit it and report a plain `reflected` boolean instead.
        if label == "negative":
            entry["reflected"] = result.fired
        else:
            entry["matcher_outcome"] = result.outcome
        calls.append(entry)

    real_1, real_2, neg = calls[0], calls[1], calls[2]

    # The per-call matcher already classifies vulnerable vs echo by checking
    # whether shell metacharacters appear in the response window around the
    # marker (see matchers._SHELL_ECHO_TELLS). We trust that per-call signal
    # for the real payloads and use the negative for additional context.
    r1, r2 = real_1["matcher_outcome"], real_2["matcher_outcome"]
    neg_reflects = neg["reflected"]  # if the negative marker appears, server reflects raw input

    if r1 == "vulnerable" and r2 == "vulnerable":
        outcome = "vulnerable"
        extra = " (server also reflects raw input)" if neg_reflects else ""
        evidence = (
            f"both real markers reflected without shell-syntax wrapper — expansion confirmed{extra}.\n"
            f"real_1 evidence: {real_1['evidence'][:160]}"
        )
    elif r1 == "echo" and r2 == "echo":
        outcome = "echo"
        evidence = (
            "both real markers reflected alongside the shell-syntax wrapper — "
            "server reflects input, no expansion proven.\n"
            f"real_1 evidence: {real_1['evidence'][:160]}"
        )
    elif r1 == "pass" and r2 == "pass":
        outcome = "pass"
        evidence = "neither real marker reflected"
    elif r1 != r2:
        # The two real calls disagreed — likely intermittent or stateful behavior.
        outcome = "suggestive"
        evidence = (
            f"intermittent: real_1={r1}, real_2={r2}. Rerun to disambiguate "
            "(network, caching, race)."
        )
    else:
        # Defensive: any other combination is unexpected.
        outcome = "suggestive"
        evidence = f"unusual corroboration state: real_1={r1}, real_2={r2}, negative_reflects={neg_reflects}"

    fired = outcome in ("vulnerable", "echo")
    return Finding(
        test_id=case.id,
        expected_signal=case.expected_signal,
        severity=case.severity,
        surface=case.surface,
        endpoint=cfg.endpoint,
        fired=fired,
        outcome=outcome,
        tool_name=target,
        evidence=evidence[:400],
        owasp=list(case.owasp),
        atlas=list(case.atlas),
        payload={
            "tool": target,
            "corroborated": True,
            "calls": [
                # Keep keys that exist (matcher_outcome only on real calls,
                # reflected only on negative).
                {k: c[k] for k in ("label", "args", "marker", "fired", "matcher_outcome", "reflected") if k in c}
                for c in calls
            ],
        },
    )


async def _run_authz_case(case: TestCase, cfg: ScanConfig) -> Finding:
    """Two-credential cross-tenant probe."""
    # Skip cleanly if the operator didn't supply the required identities.
    missing: list[str] = []
    if not cfg.cred_a:
        missing.append("--cred-a")
    if not cfg.cred_b:
        missing.append("--cred-b")
    if not cfg.foreign_id:
        missing.append("--foreign-id")
    if missing:
        return Finding(
            test_id=case.id,
            expected_signal=case.expected_signal,
            severity=case.severity,
            surface=case.surface,
            endpoint=cfg.endpoint,
            fired=False,
            outcome="skipped",
            evidence=f"authz probe requires {' / '.join(missing)}",
            owasp=list(case.owasp),
            atlas=list(case.atlas),
        )

    run_id = _run_id()
    phase_a = case.phase_a
    phase_b = case.phase_b
    assert phase_a is not None and phase_b is not None  # validated at load time
    a_args = {k: _expand_authz_template(v, cfg, run_id) for k, v in phase_a.arguments.items()}
    b_args = {k: _expand_authz_template(v, cfg, run_id) for k, v in phase_b.arguments.items()}

    async with MCPClient(
        cfg.endpoint,
        timeout_s=cfg.timeout_s,
        bearer=cfg.bearer,
        headers=cfg.headers,
    ) as client:
        call_a = await client.call_tool(phase_a.tool, a_args)
        # Sanity check: A should be able to read its own object. If not, the
        # foreign_id is wrong or A's credential is invalid — emit error rather
        # than misclassify a probe-config bug as "not vulnerable".
        if call_a.is_error:
            return Finding(
                test_id=case.id,
                expected_signal=case.expected_signal,
                severity=case.severity,
                surface=case.surface,
                endpoint=cfg.endpoint,
                fired=False,
                outcome="error",
                tool_name=phase_a.tool,
                evidence=f"phase_a (identity A) failed — check --cred-a and --foreign-id: {call_a.text[:200]}",
                owasp=list(case.owasp),
                atlas=list(case.atlas),
                payload={"phase_a": {"tool": phase_a.tool, "arguments": _redact_args(a_args, cfg)}},
            )

        call_b = await client.call_tool(phase_b.tool, b_args)

    # Run the matcher against B's response. The matcher's params may reference
    # ``{run_id}`` and template tokens; expand those.
    assert case.matcher is not None
    params = {k: _expand_authz_template(v, cfg, run_id) for k, v in case.matcher.params.items()}
    result = run_matcher(case.matcher.kind, params, call_b.text, {})

    # Refine against phase-B's error signal. The matcher here is reflection-class
    # (regex on the tenant tag): if B's read was DENIED but the denial echoes the
    # requested object/tenant back ("access denied for tenant_alpha"), the regex
    # matches the rejection, not a leak. _resolve_outcome downgrades that to
    # `echo` — same cry-wolf guard the tool_call path already has.
    outcome, evidence, error_note = _resolve_outcome(result, call_b, case.matcher.kind)

    return Finding(
        test_id=case.id,
        expected_signal=case.expected_signal,
        severity=case.severity,
        surface=case.surface,
        endpoint=cfg.endpoint,
        fired=result.fired,
        outcome=outcome,
        tool_name=phase_b.tool,
        evidence=(evidence or f"phase_b response: {call_b.text[:200]}"),
        error=error_note,
        owasp=list(case.owasp),
        atlas=list(case.atlas),
        payload={
            "phase_a": {"tool": phase_a.tool, "arguments": _redact_args(a_args, cfg)},
            "phase_b": {"tool": phase_b.tool, "arguments": _redact_args(b_args, cfg)},
        },
    )


async def _run_auth_case(case: TestCase, cfg: ScanConfig) -> Finding:
    """Run a single auth-misconfig probe with overridden credentials."""
    override = case.auth_override
    if override is None:
        return Finding(
            test_id=case.id,
            expected_signal=case.expected_signal,
            severity=case.severity,
            surface=case.surface,
            endpoint=cfg.endpoint,
            fired=False,
            outcome="error",
            evidence="surface=auth requires auth_override field; none provided",
            owasp=list(case.owasp),
            atlas=list(case.atlas),
        )

    # wrong_prefix requires a bearer to mutate; skip cleanly when absent.
    if override.mode == "wrong_prefix" and not cfg.bearer:
        return Finding(
            test_id=case.id,
            expected_signal=case.expected_signal,
            severity=case.severity,
            surface=case.surface,
            endpoint=cfg.endpoint,
            fired=False,
            outcome="skipped",
            evidence="auth_override=wrong_prefix requires --bearer to mutate; none provided",
            owasp=list(case.owasp),
            atlas=list(case.atlas),
        )

    error_note: Optional[str] = None
    try:
        async with MCPClient(
            cfg.endpoint,
            timeout_s=cfg.timeout_s,
            bearer=cfg.bearer,
            headers=cfg.headers,
            auth_override=override.mode,
        ) as client:
            tools = await client.list_tools()
            # Handshake + list_tools succeeded with intentionally-bad auth.
            outcome = override.expect_success
            evidence = (
                f"server accepted auth_override={override.mode}; "
                f"list_tools returned {len(tools)} tool(s)"
            )
            fired = (outcome == "vulnerable")
    except Exception as exc:
        fired = False
        if _is_transport_failure(exc):
            # Never reached the server — inconclusive, NOT a hardened server.
            outcome = "error"
            error_note = "transport failure: could not complete the auth handshake"
            evidence = f"could not reach endpoint (scan inconclusive): {type(exc).__name__}: {exc}"
        else:
            # Server answered and rejected the bad auth — the secure outcome.
            outcome = "pass"
            evidence = f"server rejected auth_override={override.mode}: {type(exc).__name__}: {exc}"

    return Finding(
        test_id=case.id,
        expected_signal=case.expected_signal,
        severity=case.severity,
        surface=case.surface,
        endpoint=cfg.endpoint,
        fired=fired,
        outcome=outcome,
        evidence=evidence[:300],
        error=error_note,
        owasp=list(case.owasp),
        atlas=list(case.atlas),
        payload={"auth_override": override.mode},
    )


# Matchers whose hit can be the server reflecting our own payload back — e.g.
# echoing the rejected path/id inside an access-denied message — rather than
# leaking protected data. A hit from one of these INSIDE an error response is
# reflection-in-a-denial, not a vulnerability.
_REFLECTION_MATCHERS: frozenset[str] = frozenset({"regex", "substring"})


# Exception type names + message markers that mean "we never reached the server"
# (connection refused, DNS failure, TLS error, timeout) — as opposed to the
# server being up and actively rejecting our intentionally-bad auth.
_TRANSPORT_FAILURE_TYPES: frozenset[str] = frozenset({
    "ConnectError", "ConnectTimeout", "ReadTimeout", "WriteTimeout",
    "PoolTimeout", "ConnectionError", "ConnectionRefusedError",
    "TimeoutError", "OSError", "gaierror",
})
_TRANSPORT_FAILURE_MARKERS: tuple[str, ...] = (
    "connection refused", "name or service not known", "nodename nor servname",
    "failed to establish", "all connection attempts failed", "connect call failed",
    "cannot connect", "timed out", "timeout", "max retries", "getaddrinfo",
    "ssl", "certificate",
)


def _is_transport_failure(exc: BaseException) -> bool:
    """True when an auth-probe exception is a connectivity/transport failure
    (endpoint unreachable) rather than the server actively rejecting bad auth.

    The auth probes conclude ``pass`` when the server REJECTS intentionally-bad
    auth (the handshake raised because the server answered 401/403). But a
    connection refusal, DNS failure, TLS error, or timeout means we never
    reached the server at all — recording that as ``pass`` would label a dead
    endpoint as a hardened one (a false negative that quietly inflates a
    benchmark). Those map to ``error`` (scan inconclusive) instead.

    Walks the exception chain because httpx/anyio wrap the root cause.
    """
    seen: set[int] = set()
    cur: Optional[BaseException] = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if type(cur).__name__ in _TRANSPORT_FAILURE_TYPES:
            return True
        msg = str(cur).lower()
        if any(marker in msg for marker in _TRANSPORT_FAILURE_MARKERS):
            return True
        cur = cur.__cause__ or cur.__context__
    return False


def _shared_client_failure(exc: BaseException) -> tuple[str, str]:
    """Classify a failure of the shared tool-surface client (handshake or
    ``list_tools``) into ``(outcome, reason)`` for the tool_call/tool_list/
    resource_list/prompt_list probes.

    - unreachable (connection / DNS / TLS / timeout) -> ``error`` (inconclusive).
    - auth wall (401/403) -> ``skipped`` with an actionable hint: we can't
      enumerate the tool surface without credentials. That's not a server
      defect — it's a missing ``--bearer``. The auth-SURFACE probes run on their
      own clients and already report whether the wall is real.
    - any other enumeration error -> ``error``.
    """
    if _is_transport_failure(exc):
        return "error", f"could not reach endpoint (scan inconclusive): {type(exc).__name__}: {exc}"
    msg = str(exc).lower()
    if any(s in msg for s in ("401", "403", "unauthorized", "forbidden")):
        return "skipped", (
            "server requires auth to enumerate tools — tool-surface probes not run. "
            f"Supply --bearer / --header. (list_tools failed: {type(exc).__name__})"
        )
    return "error", f"could not enumerate tools: {type(exc).__name__}: {exc}"


def _surface_findings(
    cases: list[TestCase], cfg: "ScanConfig", outcome: str, reason: str
) -> list[Finding]:
    """One Finding per case when the shared tool-surface client dies before any
    probe could run — so every tool-surface probe gets an explicit, uniform
    skip/error instead of vanishing into a stack trace."""
    return [
        Finding(
            test_id=c.id,
            expected_signal=c.expected_signal,
            severity=c.severity,
            surface=c.surface,
            endpoint=cfg.endpoint,
            fired=False,
            outcome=outcome,
            tool_name=None,
            evidence=reason,
            error=(reason if outcome == "error" else None),
            owasp=list(c.owasp),
            atlas=list(c.atlas),
        )
        for c in cases
    ]


# Max times the shared tool-surface client may be reconnected within one scan
# before we give up. Bounds the retry loop so a server that drops on every call
# can't spin forever; high enough to ride out a transient hiccup or two.
_MAX_RECONNECTS = 3


def _has_transport_drop(case_findings: list[Finding]) -> bool:
    """True if any finding in this batch is a transport-level failure — the
    signal that the shared client's connection died (vs. a tool-level error or
    a clean pass). Drives the reconnect-and-retry in :func:`run_scan`."""
    return any(
        bool(f.error) and "transport" in f.error.lower() for f in case_findings
    )


async def _reconnect_client(
    old: MCPClient, cfg: "ScanConfig"
) -> tuple[MCPClient, bool]:
    """Close ``old`` and open a fresh shared client. Returns ``(client, ok)``;
    ``ok`` is False if the new handshake fails (endpoint truly gone), in which
    case the caller should stop and mark the rest of the scan as error."""
    try:
        await old.__aexit__(None, None, None)
    except Exception:
        pass
    new = MCPClient(
        cfg.endpoint,
        timeout_s=cfg.timeout_s,
        bearer=cfg.bearer,
        headers=cfg.headers,
    )
    try:
        await new.__aenter__()
        return new, True
    except Exception:
        return new, False


def _resolve_outcome(
    result: MatcherResult, call: CallResult, matcher_kind: str
) -> tuple[str, str, Optional[str]]:
    """Refine a matcher verdict against the transport / tool-error signal.

    Returns ``(outcome, evidence, error_note)``.

    - transport error              -> ``error`` (we couldn't complete the call).
    - tool error, matcher silent   -> ``pass`` (server RAN and rejected our input
      safely; keep the server's message so a "rejected safely" pass is
      distinguishable from a clean-normal-response pass).
    - tool error, reflection-class matcher fired -> ``echo``. The match lives
      inside the server's denial, so a regex/substring matcher almost always
      matched our own payload echoed back (e.g. ``access denied: <path>``) — the
      server NAMING what it refused, not leaking it. Reporting that as
      ``vulnerable`` is the cry-wolf bug this guards against.
    - tool error, content-leak matcher fired -> keep ``vulnerable``. An error
      that returns a secret (secret_pattern / cloud_metadata) is still a leak.
    - otherwise                    -> the matcher's own verdict.
    """
    outcome = result.outcome
    evidence = result.evidence
    error_note: Optional[str] = None
    if call.transport_error:
        outcome = "error"
        error_note = "transport error: tool call did not complete"
        evidence = evidence or call.text[:200]
    elif call.is_error:
        if not result.fired:
            outcome = "pass"
            if not evidence:
                evidence = f"server rejected input (no leak): {call.text[:160]}"
        elif matcher_kind in _REFLECTION_MATCHERS:
            outcome = "echo"
            evidence = f"input reflected in server rejection (not a leak): {evidence}"
    return outcome, evidence, error_note


async def _run_case(
    client: MCPClient,
    case: TestCase,
    tools: list[ToolDescriptor],
    tools_ctx: list[dict[str, Any]],
    cfg: ScanConfig,
) -> list[Finding]:
    if case.surface in ("tool_list", "resource_list", "prompt_list") or case.applies_to.none:
        # Schema-only / listing-only tests: no tool call.
        run_id = _run_id()
        params = _resolve_matcher_params(case.matcher.params, run_id)
        result = run_matcher(case.matcher.kind, params, "", {"tools": tools_ctx})
        return [
            Finding(
                test_id=case.id,
                expected_signal=case.expected_signal,
                severity=case.severity,
                surface=case.surface,
                endpoint=cfg.endpoint,
                fired=result.fired,
                outcome=result.outcome,
                tool_name=None,
                evidence=result.evidence,
                owasp=list(case.owasp),
                atlas=list(case.atlas),
                payload={"matcher": case.matcher.kind, "params": params},
            )
        ]

    matched_tools = select_tools(case, tools)
    if not matched_tools:
        return [
            Finding(
                test_id=case.id,
                expected_signal=case.expected_signal,
                severity=case.severity,
                surface=case.surface,
                endpoint=cfg.endpoint,
                fired=False,
                outcome="skipped",
                tool_name=None,
                evidence="no compatible tool exposed by server",
                owasp=list(case.owasp),
                atlas=list(case.atlas),
            )
        ]

    findings: list[Finding] = []
    for tool in matched_tools:
        # Corroborated marker_echo: run 3 calls and aggregate.
        if (
            case.corroborate is not None
            and case.matcher is not None
            and case.matcher.kind == "marker_echo"
        ):
            findings.append(await _run_corroborated_marker_echo(client, case, tool, tools, cfg))
            continue

        run_id = _run_id()
        target = case.payload.tool or tool.name
        try:
            arguments = _resolve_arguments(
                case.payload.arguments, tool, run_id,
                case.applies_to.target_arg_kind, cfg.context_args, cfg.canary_path,
            )
        except (_UnresolvedFirstStringArg, _UnresolvedTargetArg, _UnsatisfiedRequiredArgs) as exc:
            findings.append(
                Finding(
                    test_id=case.id,
                    expected_signal=case.expected_signal,
                    severity=case.severity,
                    surface=case.surface,
                    endpoint=cfg.endpoint,
                    fired=False,
                    outcome="skipped",
                    tool_name=target,
                    evidence=_skip_evidence("payload arg resolution", exc),
                    owasp=list(case.owasp),
                    atlas=list(case.atlas),
                )
            )
            continue
        params = _resolve_matcher_params(case.matcher.params, run_id)
        call = await client.call_tool(target, arguments)
        result = run_matcher(
            case.matcher.kind,
            params,
            call.text,
            {"tools": [t.to_dict() for t in tools]},
        )
        # Outcome resolution (see _resolve_outcome). Refined 2026-05-27 to stop
        # a reflection-class matcher firing inside a server rejection from
        # reading as `vulnerable` (the prefix_bypass cry-wolf bug).
        outcome, evidence, error_note = _resolve_outcome(result, call, case.matcher.kind)
        findings.append(
            Finding(
                test_id=case.id,
                expected_signal=case.expected_signal,
                severity=case.severity,
                surface=case.surface,
                endpoint=cfg.endpoint,
                fired=result.fired,
                outcome=outcome,
                tool_name=target,
                evidence=evidence,
                owasp=list(case.owasp),
                atlas=list(case.atlas),
                payload={"tool": target, "arguments": _redact_args(arguments, cfg)},
                error=error_note,
            )
        )
    return findings
