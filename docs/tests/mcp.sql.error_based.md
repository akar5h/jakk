# `mcp.sql.error_based`

**OWASP:** MCP05 · **severity:** high · **signal:** `input.sql_injection`
**side_effect:** unsafe — a quote payload can reach a write-backed query path

## What it is

Sends an unbalanced single quote into a query-shaped argument and looks
for database syntax-error signatures in the tool response. It targets
tools where a search/filter/query value is supposed to be data, but may
be concatenated into SQL instead of passed as a bound parameter.

## Why we picked it

Many MCP servers front application databases through search, lookup, or
filter tools. Error-based SQL injection is a deterministic first signal:
a bound parameter treats the quote as data, while string concatenation
often returns a recognizable database-engine error.

## Threat model

**What "vulnerable" means here:** the server response contains a
database syntax error after a query-shaped argument received the probe
payload. That is evidence the argument influenced SQL syntax rather than
being safely parameterized.

**Harm:** depending on the underlying query and database permissions, an
attacker may be able to broaden reads, extract data, modify data, or use
database-specific features for further impact.

**Harmed parties:** the server operator and any users or tenants whose
data is reachable through the vulnerable query path.

## How it fires

1. Select tools with a `query`-kind string argument.
2. Send `jakk{run_id}'` into that argument.
3. Match the response against PostgreSQL, MySQL, SQLite, Oracle, MS SQL,
   and common wrapper error signatures.
4. A match is `vulnerable`; no match is `pass` unless the transport
   failed before the tool result could be evaluated.

## Expected results

- Parameterized query → `pass`.
- Concatenated SQL with visible syntax error → `vulnerable`.
- Tool requires other args and no `--arg` was supplied → `skipped` with
  an actionable hint.

## YAML shape

See `library/mcp/mcp.sql.error_based.yaml`.
