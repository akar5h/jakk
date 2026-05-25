# `mcp.auth.invalid_token`

**OWASP:** MCP10 (auth & access) · **severity:** critical · **signal:** `auth.token_not_validated`
**side_effect:** safe — one `tools/list` call with garbage credentials

## What it is
Sends `Authorization: Bearer garbage-<8-byte-hex>` and checks whether
the server returns a tool list. A correctly-configured server validates
the token before allowing protocol-level operations and responds with
401 / connection failure. A server that ignores the header or accepts
any bearer-shaped string is a critical misconfiguration.

## Why we picked it
Catches a class of bug that's surprisingly common: auth middleware
that *checks for the presence* of a Bearer header but doesn't *verify*
the token (e.g. forgotten JWT signature check, mis-wired introspection
endpoint, or `if header.startswith("Bearer ")` and nothing else).

## Threat model
**What "vulnerable" means here:** the server accepted a `Bearer garbage-<rand>` token. Either the auth middleware checks for the *presence* of an Authorization header without verifying the token (forgotten JWT signature check, mis-wired introspection endpoint) or it accepts any bearer-shaped string.

**Harm:** functionally equivalent to no_credential — anyone who knows the endpoint URL can call every tool. Slightly worse signal-wise: the server is misleading about being authenticated.

**Harmed parties:** same as no_credential — every user behind the server, plus the operator.

See [../threat-models.md](../threat-models.md) for the full class.

## How it fires
1. Generate a fresh per-run token: `garbage-<hex>` (8 random bytes).
2. Set `Authorization: Bearer garbage-<hex>` on the transport.
3. Open `fastmcp.Client` and call `list_tools()`.
4. **Success** → `vulnerable`. **Exception** → `pass`.

## How detection works
Same as `mcp.auth.no_credential` — connection success/failure is the
verdict. The garbage prefix is high-entropy specifically so the token
cannot collide with a legitimate one by accident (no false positive
from a random token actually being valid).

## Expected results
- Server enforcing token validation → `pass`.
- Server with no validation, or validation skipped → `vulnerable`.

## YAML shape
See `library/mcp/mcp.auth.invalid_token.yaml`.
