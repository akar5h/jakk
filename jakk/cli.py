"""``jakk`` command-line entry point."""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from .findings import render_console, write_jsonl
from .library import filter_cases, load_library
from .scanner import ScanConfig, run_scan


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jakk",
        description="Black-box MCP scanner.",
    )
    sub = parser.add_subparsers(dest="surface", required=True)

    mcp_p = sub.add_parser("mcp", help="MCP-protocol scanning")
    mcp_sub = mcp_p.add_subparsers(dest="cmd", required=True)

    scan_p = mcp_sub.add_parser("scan", help="Scan an MCP endpoint with a YAML attack library.")
    scan_p.add_argument("--endpoint", required=True, help="MCP streamable-HTTP endpoint URL.")
    scan_p.add_argument(
        "--library",
        required=True,
        type=Path,
        help="Path to a directory of jakk YAML test files.",
    )
    scan_p.add_argument("--select", help="Run only the test with this id.")
    scan_p.add_argument("--owasp", help="Filter tests by OWASP code (e.g. MCP05).")
    scan_p.add_argument(
        "--safe",
        action="store_true",
        help="Only run probes annotated `side_effect: safe`. Use when scanning "
        "servers where state mutation is unacceptable (production, commercial).",
    )
    scan_p.add_argument(
        "--bearer",
        metavar="TOKEN",
        help="Bearer token. Sent as `Authorization: Bearer <token>`.",
    )
    scan_p.add_argument(
        "--oauth-token-file",
        type=Path,
        metavar="PATH",
        help="Read bearer token from this file (whitespace-stripped). Mutually "
        "exclusive with --bearer.",
    )
    scan_p.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Custom HTTP header. Pass multiple times for multiple headers.",
    )
    scan_p.add_argument(
        "--arg",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Supply a valid value for a non-target tool argument (e.g. "
        "--arg owner=octocat --arg repo=Hello-World). Fills any tool-declared "
        "arg the probe didn't set, so multi-arg tools (get_file_contents, etc.) "
        "reach the code path under test instead of erroring on a missing "
        "parameter. Pass multiple times.",
    )
    scan_p.add_argument(
        "--canary-path",
        metavar="PATH",
        help="Override the path that path-traversal probes target. They default "
        "to the breach-to-fix lab layout (/app/files/safe_files_sensitive), which "
        "only exists in the lab. Supply a path you know is sensitive / out-of-scope "
        "on the real target (e.g. --canary-path /etc/passwd) so the probe exercises "
        "THAT server instead of a lab-only path.",
    )
    scan_p.add_argument(
        "--cred-a",
        metavar="VALUE",
        help="Identity A's credential. Threaded into authz probe payloads as "
        "{cred_a}. Often a tool-arg API key (not an HTTP bearer).",
    )
    scan_p.add_argument(
        "--cred-b",
        metavar="VALUE",
        help="Identity B's credential. Threaded into authz probe payloads as {cred_b}.",
    )
    scan_p.add_argument(
        "--foreign-id",
        metavar="VALUE",
        help="Object identifier belonging to A's tenant. Threaded into authz "
        "probe payloads as {foreign_id}. B attempts to read this; success = "
        "cross-tenant authz failure.",
    )
    scan_p.add_argument(
        "--jsonl",
        type=Path,
        help="Write findings as JSONL to this path (in addition to console output).",
    )
    scan_p.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="Per-call MCP timeout in seconds (default 15).",
    )
    scan_p.add_argument(
        "--exit-nonzero-on-fired",
        action="store_true",
        help="Return exit code 2 if any finding fired (for CI use).",
    )
    return parser


def _parse_kv(values: list[str], flag: str) -> dict[str, str]:
    """Parse repeated KEY=VALUE flags into a dict. Used by --header and --arg."""
    out: dict[str, str] = {}
    for raw in values:
        if "=" not in raw:
            raise SystemExit(f"{flag} expects KEY=VALUE, got {raw!r}")
        key, _, value = raw.partition("=")
        key = key.strip()
        if not key:
            raise SystemExit(f"{flag} key is empty in {raw!r}")
        # Headers strip whitespace from values; --arg values are passed
        # verbatim (a context value may legitimately contain spaces).
        out[key] = value.strip() if flag == "--header" else value
    return out


def _parse_headers(values: list[str]) -> dict[str, str]:
    return _parse_kv(values, flag="--header")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.surface == "mcp" and args.cmd == "scan":
        return _cmd_scan(args)
    parser.error(f"unknown command: {args.surface} {args.cmd}")
    return 2  # unreachable


def _cmd_scan(args: argparse.Namespace) -> int:
    cases = load_library(args.library)
    selected = filter_cases(
        cases, select=args.select, owasp=args.owasp, safe_only=args.safe
    )
    if not selected:
        print(
            f"No tests matched (library={args.library} select={args.select} "
            f"owasp={args.owasp} safe={args.safe})",
            file=sys.stderr,
        )
        return 1

    if args.bearer and args.oauth_token_file:
        print("--bearer and --oauth-token-file are mutually exclusive", file=sys.stderr)
        return 1
    bearer = args.bearer
    if args.oauth_token_file:
        try:
            bearer = args.oauth_token_file.read_text().strip()
        except OSError as exc:
            print(f"failed to read --oauth-token-file: {exc}", file=sys.stderr)
            return 1

    headers = _parse_headers(args.header)
    context_args = _parse_kv(args.arg, flag="--arg")

    cfg = ScanConfig(
        endpoint=args.endpoint,
        timeout_s=args.timeout,
        bearer=bearer,
        headers=headers or None,
        cred_a=args.cred_a,
        cred_b=args.cred_b,
        foreign_id=args.foreign_id,
        context_args=context_args or None,
        canary_path=args.canary_path,
    )
    findings = asyncio.run(run_scan(selected, cfg))

    render_console(findings, endpoint=args.endpoint)
    if args.jsonl:
        write_jsonl(findings, args.jsonl)

    fired_any = any(f.fired for f in findings)
    if args.exit_nonzero_on_fired and fired_any:
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
