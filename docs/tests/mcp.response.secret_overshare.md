# `mcp.response.secret_overshare`

**OWASP:** MCP02 (excessive output) + MCP05 · **severity:** high · **signal:** `response.secret_leak`

## What it is
Call the lowest-friction enumeration tool the server exposes — a `list_*`,
`get_*`, `read_*`, `describe_*`, `status_*`, or `info_*` with no required
args — and scan the response for secret-shaped strings. The premise is
that some MCP servers leak credentials through what looks like a routine
read (logs, env, config endpoints, status pages).

## Why we picked it
The 2025 MCP threat surveys all flag "tool returns secret in routine
read" as a top finding. This is a one-network-call probe with high
return — if your `list_servers` or `get_config` happens to dump
`API_KEY=…` in the response, jakk catches it before any LLM gets near it.

## Threat model
**What "vulnerable" means here:** a benign-looking read tool returned secret-shaped strings in its response — API keys, PEM blocks, passwords, tokens — content the server should not be exposing to callers.

**Harm:** any agent or operator who calls the tool receives the secrets. LLM transcripts are usually logged (Langfuse, Phoenix, CloudWatch) — those secrets land in observability infrastructure. If the LLM summarizes the response back to the user or forwards it to another tool, the secrets travel further.

**Harmed parties:** server operator (their secrets exposed), user (their credentials may be among the leaked values). No active attacker required — this is a self-inflicted leak; any caller harvests it.

See [../threat-models.md](../threat-models.md) for the full class.

## How it fires
1. Pick the first tool matching `^(list|get|read|describe|status|info|inventory|repositories|files|tools)`.
2. Call with empty arguments (works if no required args; otherwise the
   server returns an error, and we don't fire).
3. Match the response against the `secret_pattern` set.

## How detection works
Same `secret_pattern` matcher as `secret_file_read` — pluggable list of
regexes. False positives are possible if a benign tool legitimately
returns a string that resembles `password = '…'`; report the finding
and let the operator triage.

## Expected results
- Endpoints whose tools deliberately or accidentally embed canary tokens
  (e.g. examples/vulnerable_server/team_kb_mcp configured with seeded
  secrets) — **fires**.
- ch08 / ch02 plain reads — does **not** fire (no secrets in routine
  output).

## YAML shape
See `library/mcp/mcp.response.secret_overshare.yaml`.
