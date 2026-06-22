# jakk

**A black-box security scanner for MCP servers.** Point it at an MCP
endpoint; it enumerates the server's tools, fires a curated library of
single-call adversarial probes, and classifies what comes back. No LLM
in the loop — deterministic, fast, zero token cost.

[![CI](https://github.com/akar5h/jakk/actions/workflows/ci.yml/badge.svg)](https://github.com/akar5h/jakk/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Probes](https://img.shields.io/badge/probes-13-orange)
![Tests](https://img.shields.io/badge/tests-190-green)

---

The [Model Context Protocol](https://modelcontextprotocol.io) lets LLM
agents call tools on external servers. Those servers are a new,
fast-growing attack surface — command injection, path traversal,
broken authorization, SSRF, tool-description poisoning. `jakk` is the
fast first pass for MCP server maintainers: add one GitHub Action step,
scan the server you just built, and fail CI only on reproducible evidence.

```console
$ jakk mcp scan --endpoint http://127.0.0.1:8008/mcp/stream --library library/mcp

──────────────── jakk scan :: http://127.0.0.1:8008/mcp/stream ────────────────
                               Probe results (13)
┏━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ outcome    ┃ severity ┃ test id                ┃ tool            ┃ evidence     ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ vulnerable │ critical │ mcp.command.secret_…   │ init_bare_repo… │ FLAG{git_co… │
│ vulnerable │ high     │ mcp.command.shell_ma…  │ init_bare_repo… │ …xJAKK-MARK… │
│ pass       │ high     │ mcp.schema.descripti…  │ -               │              │
│ ...        │          │                        │                 │              │
└────────────┴──────────┴────────────────────────┴─────────────────┴──────────────┘
Tests run: 13  pass=4  skipped=5  vulnerable=4
4 vulnerability findings
```

## GitHub Action quick start

`jakk` is safest as a CI smoke test. The Action defaults to `safe: true`,
so it only runs read-only / no-side-effect probes unless you explicitly
opt into deeper testing.

```yaml
name: MCP security smoke test

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  jakk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Start your MCP server however your project normally does it.
      - name: Start MCP server
        run: |
          ./scripts/start-mcp-server.sh &
          echo $! > /tmp/mcp-server.pid

      - name: Wait for MCP endpoint
        run: |
          for i in {1..30}; do
            curl -fsS http://127.0.0.1:8000/health && exit 0
            sleep 1
          done
          exit 1

      - name: Run jakk
        uses: akar5h/jakk@v0.2
        with:
          endpoint: http://127.0.0.1:8000/mcp
          args: "--bearer ${{ secrets.MCP_TEST_TOKEN }}"
          sarif: jakk-findings.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: jakk-findings.sarif

      - name: Upload findings
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: jakk-findings
          path: jakk-findings.jsonl
```

For authorized test targets where mutation is acceptable, opt into the
full library:

```yaml
- uses: akar5h/jakk@v0.2
  with:
    endpoint: http://127.0.0.1:8000/mcp
    safe: "false"
    args: "--bearer ${{ secrets.MCP_TEST_TOKEN }} --arg owner=octocat --arg repo=Hello-World"
```

## Install

```bash
pip install jakk        # once published to PyPI
# or, from source:
git clone https://github.com/akar5h/jakk && cd jakk && pip install -e .
```

## Quick start

```bash
# Scan a local MCP endpoint with read-only probes
jakk mcp scan --endpoint http://127.0.0.1:8008/mcp/stream --library library/mcp --safe

# An authenticated server, safe (read-only) probes only, results to JSONL
jakk mcp scan \
  --endpoint https://api.example.com/mcp/stream \
  --library library/mcp \
  --bearer "$ACCESS_TOKEN" \
  --safe \
  --jsonl findings.jsonl \
  --sarif findings.sarif
```

> **jakk's production threat model is HTTP MCP servers.** stdio servers
> are single-user local subprocesses where auth probes don't apply; `--stdio`
> runs the local input-handling/schema subset and skips auth as N/A. See
> [docs/scope-decision.md](docs/scope-decision.md).

## Probe catalog

13 probes across 7 surfaces, covering OWASP-for-MCP classes MCP01–MCP05, MCP08, MCP10.

| Probe | Class | Severity |
|---|---|---|
| `mcp.command.shell_marker` | command injection (sink) | high |
| `mcp.command.secret_file_read` | command injection (impact) | critical |
| `mcp.path.prefix_bypass` | CVE-2025-53110 startswith bypass | high |
| `mcp.path.canary_file_read` | path traversal (impact) | critical |
| `mcp.response.secret_overshare` | secret leak in benign response | high |
| `mcp.response.directive_passthrough` | indirect injection via response | high |
| `mcp.schema.description_smuggling` | tool poisoning via description | high |
| `mcp.auth.no_credential` | anonymous access accepted | critical |
| `mcp.auth.invalid_token` | garbage token accepted | critical |
| `mcp.auth.wrong_prefix` | bearer accepted without scheme | low |
| `mcp.authz.cross_tenant_read` | confused deputy / BOLA | critical |
| `mcp.ssrf.cloud_metadata` | SSRF to cloud metadata endpoint | critical |
| `mcp.sql.error_based` | SQL injection via query-shaped args | high |

Per-probe specs in [`docs/tests/`](docs/tests/). What each `vulnerable`
verdict actually means for an attacker: [`docs/threat-models.md`](docs/threat-models.md).

## Outcomes

Every probe produces one of six outcomes — `vulnerable` is the only one
that warrants triage:

| Outcome | Meaning |
|---|---|
| **vulnerable** | The response shows the server diverging from a security property it should hold. |
| **echo** | Input reflected but not interpreted — not exploitable on its own. |
| **suggestive** | Corroboration disagreed across calls; rerun to disambiguate. |
| **pass** | Probe ran, response clean (incl. the server safely rejecting the input). |
| **skipped** | No compatible tool, or missing config (`--arg`, `--bearer`). Not a failure. |
| **error** | Couldn't complete the call (transport failure). |

`jakk` distinguishes *"server rejected our malicious input"* (pass)
from *"we couldn't test"* (error), and *"shell expansion happened"*
(vulnerable) from *"input was echoed back"* (echo). A scanner that
cries wolf is worse than none — every `vulnerable` is meant to be real.

## How it's different

- **No LLM.** Matchers are deterministic (regex / canary echo / schema scan). Zero token cost, fully reproducible.
- **GitHub-native.** The Action is safe-by-default, emits JSONL + SARIF, and can gate PRs with `--exit-nonzero-on-fired`.
- **Schema-aware, vendor-agnostic.** Probes target arguments by *semantic role* (`path`, `url`, `query`...), so one library generalizes across servers regardless of how they name their arguments. ([details](docs/context-args/README.md))
- **Honest classification.** A 6-outcome taxonomy that separates real findings from input reflection and from "couldn't test."
- **It eats its own dog food.** `jakk`'s own attack surface is audited — see [`docs/2026-05-23_self-security-audit.md`](docs/2026-05-23_self-security-audit.md).

`jakk` is the *server-side* half of MCP security testing. The
*agent-side* half (multi-turn, LLM-adaptive attacks against the agent
that consumes MCP) is a different problem and a separate tool.

## Trying it against deliberately-vulnerable labs

```bash
# Fetch the breach-to-fix lab targets (vulnerable + hardened variants)
./examples/external_targets/fetch.sh
docker compose -f examples/external_targets/_vendor/mcp-breach-to-fix-labs/docker-compose.yml \
  up -d git-command-injection-vulnerable git-command-injection-secure

jakk mcp scan --endpoint http://127.0.0.1:8008/mcp/stream --library library/mcp  # fires
jakk mcp scan --endpoint http://127.0.0.1:9008/mcp/stream --library library/mcp  # clean
```

See [`examples/external_targets/`](examples/external_targets/) for the
target registry, and [`docs/2026-05-22_smoke-report.md`](docs/2026-05-22_smoke-report.md)
for live results across ch01 / ch02 / ch08.

## Contributing a probe

The probe library is plain YAML — **adding a probe takes minutes and no
Python.** A probe declares which tools it applies to, a payload, and a
matcher:

```yaml
id: mcp.path.prefix_bypass
surface: tool_call
severity: high
side_effect: unsafe
applies_to:
  tool_name_regex: "(?i)(read|file|path|list)"
  target_arg_kind: path        # scanner finds the path arg by role
payload:
  arguments:
    __target_arg__: "/app/files/safe_files_sensitive/"
matcher:
  kind: regex
  params: { pattern: "safe_files_sensitive" }
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide, and
[`docs/README.md`](docs/README.md) for the complete YAML schema.

## Responsible use

`jakk` is an offensive security tool. Only run it against systems you
own or are explicitly authorized to test (your own infrastructure, a
bug-bounty program's defined scope, or a paid engagement). The
[depth-of-exposure methodology](docs/depth-of-exposure-methodology.md)
documents the authorization pre-flight expected before touching any
target you don't own. Report security issues per [SECURITY.md](SECURITY.md).

## License

[Apache 2.0](LICENSE).
