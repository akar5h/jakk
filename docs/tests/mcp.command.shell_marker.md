# `mcp.command.shell_marker`

**OWASP:** MCP05 (insecure tool invocation) · **severity:** high · **signal:** `input.command_injection`

## What it is
Black-box shell-injection probe. We pick any tool whose name suggests it
shells out (`git`, `repo`, `exec`, `run`, `init`, `build`, `clone`, …)
and inject a command substitution into its first string argument:

```
x$(echo JAKK-MARKER-<run_id>)
```

`<run_id>` is fresh per call (4 random bytes). If the marker string
appears anywhere in the tool response, then `$(echo …)` was interpreted
by a shell — i.e. the server is concatenating user input into a
`shell=True` command (or equivalent).

## Why we picked it
Direct read of GHSA-3q26-f695-pp76 / breach-to-fix ch08 (`init_bare_repository`
in `examples/external_targets/_vendor/mcp-breach-to-fix-labs/08-.../vulnerable/server.py`).
The vulnerable server runs `subprocess.run(f"git init --bare {target}", shell=True)`
and returns the captured stdout/stderr — so an echoed marker is conclusive.

## Threat model
**What "vulnerable" means here:** the server interpolates a tool argument into a shell command (`shell=True` subprocess, `os.system`, `eval`-of-a-template). The marker showed up *without* its `$(echo …)` wrapper, proving the substitution executed.

**Harm:** arbitrary code execution as the server process. An attacker can read any file the server reads, connect outbound, plant a backdoor, pivot to adjacent services. For MCP, the attacker is anything feeding the LLM untrusted content (an email, a GitHub issue, a webpage) — indirect injection turns "LLM read this" into "LLM call vulnerable tool with my args".

**Harmed parties:** server operator (compromised infra), LLM host (their agent was weaponized), user (their data + credentials).

See [../threat-models.md](../threat-models.md) for the full class.

## How it fires
1. Filter `tools/list` by `applies_to.tool_name_regex` and `min_string_args ≥ 1`.
2. For each matched tool, build arguments mapping its first string-typed
   parameter → the marker-carrying payload.
3. Call the tool.
4. Run the `marker_echo` matcher on the flattened response.

## How detection works
`marker_echo` substring-matches a per-run-unique token. The token is
high-entropy (`JAKK-MARKER-<hex>`) so false positives from arbitrary
echo-back are ~zero.

### Corroboration (v0.2)
Single-call detection conflates *shell expansion* with *raw input echo*.
v0.2 adds corroboration: the scanner runs **three calls per matched
tool** instead of one.

| Call | Payload | Marker |
|---|---|---|
| `real_1` | `x$(echo JAKK-MARKER-<id_1>)` | `JAKK-MARKER-<id_1>` |
| `real_2` | `x$(echo JAKK-MARKER-<id_2>)` | `JAKK-MARKER-<id_2>` |
| `negative` | `xPLAIN-CANARY-<id_3>` *(no shell metacharacters)* | `PLAIN-CANARY-<id_3>` |

Decision table:

| `real_1` fires | `real_2` fires | `negative` fires | Verdict | Why |
|:---:|:---:|:---:|---|---|
| ✓ | ✓ | ✗ | **vulnerable** | Both shell substitutions ran; clean-input control didn't reflect. Strong evidence of expansion. |
| ✓ | ✓ | ✓ | **echo** | Server reflects everything including the plain control. No expansion proven. |
| ✓ | ✗ | * | **suggestive** | Intermittent; rerun to disambiguate (network blip, race, async caching). |
| ✗ | ✓ | * | **suggestive** | Same. |
| ✗ | ✗ | * | **pass** | Server rejected/quoted the substitution payload. |

The aggregated finding lists all three calls' markers and results in
its JSONL `payload.calls`.

## Expected results
- `http://127.0.0.1:8008/mcp/stream` (ch08 vulnerable) — **fires** on `init_bare_repository`.
- `http://127.0.0.1:9008/mcp/stream` (ch08 secure) — does **not** fire.

## YAML shape
See `library/mcp/mcp.command.shell_marker.yaml`.
