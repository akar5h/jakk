---
date: 2026-05-22
status: jakk v0.1 catalog
scope: MCP black-box single-call probes
---

# jakk — MCP scanner catalog

`jakk` ships a small, curated library of single-call probes. Each test
targets one OWASP-for-MCP class, fires deterministically (no LLM in the
loop), and includes a matcher that decides whether the probe fired based
on the response or the tool schema alone.

## How jakk differs from its agent-side sibling

| | its agent-side sibling | jakk |
|---|---|---|
| Attacker | LLM-driven, adaptive | deterministic payload table |
| Turns per probe | multi-turn, memory-carrying | single-shot |
| Target surface | full agent (HTTP/MCP/AgentDojo) | MCP endpoint only |
| Detection | oracle LLM + heuristics | regex / substring / canary echo |
| Latency | seconds–minutes per attack | <1s per probe |
| Cost | LLM tokens per turn | zero LLM cost |

jakk's job is the easy half: catch the bugs you can catch without an LLM
in the loop, fast and reliably. its agent-side sibling's job is the hard half: bugs
that only show up under adaptive pressure.

## Quick run

```bash
jakk mcp scan --endpoint http://127.0.0.1:8008/mcp/stream --library library/mcp
jakk mcp scan --endpoint http://127.0.0.1:8008/mcp/stream --library library/mcp --select mcp.command.shell_marker
jakk mcp scan --endpoint http://127.0.0.1:8008/mcp/stream --library library/mcp --owasp MCP05 --jsonl /tmp/jakk-results.jsonl
```

## GitHub Action verification

The composite Action is tested in this repo by
`.github/workflows/action-smoke.yml`. That workflow runs `uses: ./`
against `examples/stdio_smoke_server.py`, a tiny clean stdio MCP server,
then verifies:

- `jakk-action-smoke.jsonl` exists and has finding rows.
- No finding has `fired: true`.
- The JSONL artifact is uploaded for inspection.

That smoke test proves the Action wiring itself works: checkout,
install, stdio launch, scan execution, JSONL write, and clean-fixture
gating.

For a known external MCP implementation, `.github/workflows/real-target-smoke.yml`
runs the same local Action against GitHub's official `github-mcp-server`
Docker image in read-only HTTP mode. It is manual (`workflow_dispatch`)
and report-only (`fail-on-fired: false`) because the goal is calibration:
prove the Action can scan a real server and preserve the JSONL artifact,
not gate the repository on a third-party server's current behavior.

## Tests in v0.2

| id | OWASP | severity | side_effect | expected_signal | doc |
|---|---|---|---|---|---|
| `mcp.command.shell_marker` | MCP05 | high | unsafe | `input.command_injection` | [tests/mcp.command.shell_marker.md](tests/mcp.command.shell_marker.md) |
| `mcp.command.secret_file_read` | MCP05 | critical | unsafe | `input.command_injection` | [tests/mcp.command.secret_file_read.md](tests/mcp.command.secret_file_read.md) |
| `mcp.path.prefix_bypass` | MCP04 | high | unsafe | `input.path_traversal` | [tests/mcp.path.prefix_bypass.md](tests/mcp.path.prefix_bypass.md) |
| `mcp.path.canary_file_read` | MCP04/02 | critical | unsafe | `input.path_traversal` | [tests/mcp.path.canary_file_read.md](tests/mcp.path.canary_file_read.md) |
| `mcp.response.secret_overshare` | MCP02/05 | high | safe | `response.secret_leak` | [tests/mcp.response.secret_overshare.md](tests/mcp.response.secret_overshare.md) |
| `mcp.response.directive_passthrough` | MCP03 | high | safe | `response.directive_passthrough` | [tests/mcp.response.directive_passthrough.md](tests/mcp.response.directive_passthrough.md) |
| `mcp.schema.description_smuggling` | MCP01/03 | high | safe | `schema.tool_poisoning` | [tests/mcp.schema.description_smuggling.md](tests/mcp.schema.description_smuggling.md) |
| `mcp.auth.no_credential` | MCP10 | critical | safe | `auth.anonymous_access` | [tests/mcp.auth.no_credential.md](tests/mcp.auth.no_credential.md) |
| `mcp.auth.invalid_token` | MCP10 | critical | safe | `auth.token_not_validated` | [tests/mcp.auth.invalid_token.md](tests/mcp.auth.invalid_token.md) |
| `mcp.auth.wrong_prefix` | MCP10 | low | safe | `auth.scheme_not_enforced` | [tests/mcp.auth.wrong_prefix.md](tests/mcp.auth.wrong_prefix.md) |
| `mcp.authz.cross_tenant_read` | MCP08 | critical | safe | `authz.cross_tenant_read` | [tests/mcp.authz.cross_tenant_read.md](tests/mcp.authz.cross_tenant_read.md) |
| `mcp.ssrf.cloud_metadata` | MCP04 | critical | safe | `ssrf.cloud_metadata` | [ssrf/README.md](ssrf/README.md) |
| `mcp.sql.error_based` | MCP05 | high | unsafe | `input.sql_injection` | [tests/mcp.sql.error_based.md](tests/mcp.sql.error_based.md) |

`--safe` runs only the rows with `side_effect: safe` — auth/authz,
response/schema, and SSRF probes (8 total). Use it against any server
where state mutation is unacceptable (production, commercial, anything
you don't own).

SARIF upload is tested in `.github/workflows/real-target-smoke.yml`: the
workflow scans GitHub's official MCP server Docker image, verifies SARIF
2.1.0 output, uploads it with `github/codeql-action/upload-sarif@v3`,
and stores JSONL/SARIF artifacts.

The real-target workflow proves GitHub code-scanning ingestion. A
separate positive lab run proves non-empty alert content: scanning
`examples/external_targets/ch01-extended` with the authz probe produced
`vulnerable=1` and SARIF 2.1.0 with one rule/result
(`mcp.authz.cross_tenant_read`):

```bash
jakk mcp scan \
  --endpoint http://127.0.0.1:18011/mcp/stream \
  --library library/mcp \
  --select mcp.authz.cross_tenant_read \
  --cred-a alpha-api-key \
  --cred-b bravo-api-key \
  --foreign-id CRM-1001 \
  --sarif ch01-extended.sarif
```

This is the public proof point to cite when distinguishing "SARIF
uploads" from "SARIF carries actionable findings."

## Library YAML schema

```yaml
id: <dotted slug>                # required, unique across library
surface: tool_call | tool_list | resource_list | prompt_list | auth | authz
description: |
  Free-form prose.
owasp: [MCP01, MCP05, ...]       # optional, used by --owasp filter
atlas: [AML.T0051, ...]          # optional
severity: info | low | medium | high | critical
side_effect: safe | unsafe       # default unsafe; --safe filters to safe only
expected_signal: <stable class>  # emitted on the finding

applies_to:                          # which discovered tools to fire against
  tool_name: <exact name>            # optional
  tool_name_regex: <pyregex>         # optional, re.search semantics
  min_string_args: <int>             # optional
  require_no_required_args: false    # true → skip tools whose inputSchema.required is non-empty
  target_arg_kind: path|query|id|url|text  # optional; see "Argument-kind resolution" below
  none: false                        # true → skip tool selection (schema-only)

payload:
  tool: <name>                   # optional override; defaults to matched tool
  arguments:
    <key>: <value>               # strings may use {run_id}
    __first_string_arg__: <val>  # assign to tool's FIRST string-typed arg (position-based)
    __target_arg__: <val>        # assign to the arg matching applies_to.target_arg_kind (role-based)

# Required when surface == "tool_call" | "tool_list" | "resource_list" | "prompt_list":
matcher:
  kind: substring | regex | marker_echo | secret_pattern
      | directive_passthrough | schema_field | cloud_metadata
  params:                        # kind-specific; see jakk/matchers.py
    ...

# Required when surface == "auth":
auth_override:
  mode: none | garbage | wrong_prefix
  expect_success: vulnerable | pass   # default vulnerable

# Required when surface == "authz" (in addition to matcher):
phase_a:                          # A reads A's own object (sanity check)
  tool: <tool name>
  arguments:
    <object-id-key>: "{foreign_id}"
    <credential-key>: "{cred_a}"
phase_b:                          # B attempts the same read
  tool: <tool name>
  arguments:
    <object-id-key>: "{foreign_id}"
    <credential-key>: "{cred_b}"
```

Matchers receive a `{run_id}`-templated copy of `params`. `marker_template`
is conventionally promoted into `marker` after template expansion.

## Argument-kind resolution (generalizing across MCP servers)

Different MCP servers name the same conceptual argument differently. A
path-traversal probe needs to inject into the *path* argument, but that
arg is called `path` on GitHub's `get_file_contents(owner, repo, path)`,
`file_path` on breach-to-fix's `read_file_contents(file_path)`, and
`full_path` on its `list_directory_contents(full_path)`.

`target_arg_kind` solves this without per-server hardcoding. A probe
declares the *semantic role* of the arg it wants; the scanner inspects
each tool's `inputSchema` and resolves the role to the actual arg name.

```yaml
applies_to:
  tool_name_regex: "(?i)(read|get|file)"   # narrow the candidate pool
  target_arg_kind: path                     # declare the role
payload:
  arguments:
    __target_arg__: "/etc/passwd"           # lands in whichever arg matched
```

Resolution (in `jakk/applies.py:ARG_KINDS`):
1. First string-typed arg whose **name** matches the kind's name-regex.
2. Else first string-typed arg whose **description** matches the desc-regex.
3. Else the tool is filtered out — the probe `skipped`, not `error`.

Registered kinds: `path`, `query`, `id`, `url`, `text`. There is
deliberately **no `command` kind** — shell-injection probes have no
schema clue for which arg reaches a shell, so they keep
`__first_string_arg__` (position-based).

This is what lets one probe library run against any MCP server without a
per-vendor variant. The same `mcp.path.canary_file_read.yaml` probes
GitHub MCP, breach-to-fix, and a server we've never seen — the scanner
finds the path-shaped arg wherever it lives.

## CLI flags added in v0.2

| Flag | Purpose |
|---|---|
| `--library PATH` | Use a custom probe-library directory. Defaults to jakk's bundled MCP probe library. |
| `--safe` | Filter to `side_effect: safe` probes only. |
| `--bearer TOKEN` | Send `Authorization: Bearer <token>` on every request. |
| `--oauth-token-file PATH` | Read bearer from file (CI secrets). Mutually exclusive with `--bearer`. |
| `--header KEY=VALUE` | Custom HTTP header. Pass multiple times. |
| `--arg KEY=VALUE` | Supply valid values for non-target tool args (e.g. `owner`, `repo`) so multi-arg tools execute instead of erroring. Pass multiple times. See [context-args/README.md](context-args/README.md). |
| `--canary-path PATH` | Override the default lab path used by path-traversal probes with a path meaningful on the target. |
| `--sarif PATH` | Write fired findings as SARIF 2.1.0 for GitHub code scanning. JSONL remains the complete scan transcript. |
| `--exit-nonzero-on-fired` | Return exit code 2 when at least one `vulnerable` finding is found. `echo` and `suggestive` outcomes remain report-only by default. |
| `--cred-a VALUE` | Identity A's credential for authz probes. Template: `{cred_a}`. |
| `--cred-b VALUE` | Identity B's credential for authz probes. Template: `{cred_b}`. |
| `--foreign-id VALUE` | Object ID owned by A's tenant. Template: `{foreign_id}`. |
| `--stdio COMMAND` | Spawn and scan a stdio MCP server. Auth probes are skipped because stdio has no transport-auth layer. |
| `--exclude-surface SURFACE` | Skip a surface such as `auth`, `authz`, or `tool_call`. Useful for scoped CI checks. |
