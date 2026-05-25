# `mcp.auth.wrong_prefix`

**OWASP:** MCP10 (auth & access) · **severity:** high · **signal:** `auth.scheme_not_enforced`
**side_effect:** safe — one `tools/list` call with malformed Authorization

## What it is
Sends the operator's bearer token in the `Authorization` header
**without the `Bearer ` scheme prefix**. RFC 6750 requires
`Authorization: Bearer <token>`; loose parsers accept raw tokens or
case-mangled schemes. This probe catches the simplest variant.

## Why we picked it
A server that accepts `Authorization: <raw-token>` is using loose
string-match auth logic (`if token in header`) rather than proper
header parsing. Other malformed variants (`bearer <token>`,
`BEARER <token>`, `Bearer  <token>` with extra space) usually slip
through the same code path. Catching this one is a high-signal flag
that the auth implementation needs review.

## Why this probe needs `--bearer`
We mutate the operator's actual token (strip the scheme prefix) so
that the server's logic gets a token it *would* have accepted if
correctly formatted. Without `--bearer` there's nothing to mutate;
the probe emits a `skipped` finding with explanatory evidence.

## Threat model
**What "vulnerable" means here:** the server accepted the bearer token *without* the `Bearer ` scheme prefix. Loose string-match auth logic (`if token in header`) rather than proper header parsing per RFC 6750. Other malformed variants (`bearer <token>`, `BEARER <token>`, extra whitespace) usually slip through the same code path.

**Harm:** an attacker who has obtained a token through any channel (logs, accidental disclosure, prior breach) can present it in malformed forms that bypass auth normalization layers. Often a leading indicator that the auth implementation needs review across the board.

**Harmed parties:** users whose tokens have leaked anywhere (which, given the prevalence of logs containing Authorization headers, is more than people think).

See [../threat-models.md](../threat-models.md) for the full class.

## How it fires
1. Read scan-wide `cfg.bearer`. If empty → emit `skipped`.
2. Set `Authorization: <bearer>` (no scheme prefix) on the transport.
3. Open `fastmcp.Client` and call `list_tools()`.
4. **Success** → `vulnerable`. **Exception** → `pass`.

## Expected results
- Server with strict scheme parsing → `pass`.
- Server with loose / contains-based auth check → `vulnerable`.
- No `--bearer` on command line → `skipped` (evidence: "auth_override=wrong_prefix requires --bearer to mutate").

## YAML shape
See `library/mcp/mcp.auth.wrong_prefix.yaml`.
