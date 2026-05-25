---
date: 2026-05-23
status: Architecture Decision Record (ADR)
decision: jakk targets HTTP (streamable-HTTP) production MCP servers.
          stdio transport is OUT OF SCOPE.
revisit: only if a stdio target with a multi-tenant threat model appears
          (currently a contradiction in terms).
---

# ADR — jakk scope: HTTP production MCP servers, stdio out of scope

## Context

jakk currently speaks only streamable-HTTP. The question arose during
the GitHub-MCP-target work: is HTTP-only a gap to fill (add stdio), or
a deliberate scope? This ADR records the decision that **HTTP-only is
deliberate and correct**, and stdio is out of scope.

## The transport landscape (2026)

MCP has two live transports that matter:

| | stdio | streamable-HTTP |
|---|---|---|
| Model | server is a subprocess of the client; stdin/stdout pipes | server is a networked service on a port/URL |
| Deployment | local, desktop, single-user (Claude Desktop spawns it) | hosted, shared, multi-user (SaaS) |
| Transport auth | none — env vars only | OAuth / Bearer at the HTTP layer |
| Audit | per-host, out-of-band | every call interceptable at a gateway |
| Where it lives | your laptop | production infrastructure |

The 2026 consensus (TrueFoundry, Apigene, Cloudflare, vendor docs) is
unambiguous: **streamable-HTTP is the production transport.** stdio is
the local-development default that teams convert away from before
deploying. As one survey put it: *"If you built with STDIO (the
default for local development), you need to switch to HTTP or
Streamable HTTP before deploying."*

The hosted production ecosystem (25+ servers as of April 2026 —
Supabase, GitHub, Stripe, Notion, Figma, Sentry, Atlassian, HubSpot,
Linear, Slack, Neon, Vercel) is **entirely streamable-HTTP**.

## The decision

**jakk targets HTTP production MCP servers. stdio is out of scope.**

## Why this is correct, not a limitation

The decisive argument is not "HTTP is more popular." It's that
**jakk's probe library is structurally an HTTP-server threat model:**

| jakk probe class | Requires | stdio has it? |
|---|---|---|
| `mcp.auth.no_credential` | transport-layer authentication to bypass | **No** — stdio has no transport auth |
| `mcp.auth.invalid_token` | token validation to defeat | **No** — no tokens at the transport |
| `mcp.auth.wrong_prefix` | an Authorization header scheme to malform | **No** — no headers |
| `mcp.authz.cross_tenant_read` | multiple tenants to cross | **No** — stdio is single-user by construction |

Four of jakk's eleven probes — the entire auth + authz half of the
library — are **meaningless against a stdio server.** A stdio server
runs as your own subprocess, authenticated by your own environment,
serving only you. There are no tenants to cross, no transport auth to
bypass, no network position to attack from. "Attacking" it is
attacking your own laptop process with your own credentials.

The interesting MCP bugs — auth bypass, cross-tenant reads, BOLA — live
**exclusively in the multi-tenant hosted servers**, which are all HTTP.
That's not a coincidence; it's the threat model. A security scanner
that targets that threat model is correctly HTTP-only.

Adding stdio would have been scope creep into the *least*
security-relevant targets, at the cost of the auth/authz probes
making no sense there.

## What about the input-handling probes?

The `command.*`, `path.*`, `response.*`, and `schema.*` probes
*could* technically run against a stdio server (they test input
handling, not transport). But:

1. The highest-value half of the library (auth/authz) wouldn't apply,
   so a stdio scan would be a partial scan by construction.
2. A stdio server's input-handling bugs are exploited by whoever
   already controls the client launching it — i.e. you. The indirect-
   injection threat (untrusted content steering the LLM into calling a
   vulnerable tool) still applies, but that's an *agent-side* attack
   (its agent-side sibling's territory), reachable regardless of transport.

So even the transport-agnostic probes don't justify stdio support on
their own.

## What changes if a real reason appears

Revisit only if **a stdio target with a genuine multi-tenant threat
model** emerges — which is close to a contradiction in terms, since
stdio is single-subprocess-per-client. Concretely, signals that would
reopen this:

- A widely-deployed stdio MCP server that holds multi-tenant state
  (would be an unusual architecture).
- The MCP spec adding transport-layer auth to stdio (not on any roadmap).
- A specific engagement requiring a stdio scan that can't be served by
  running the same server in HTTP mode.

Note the escape hatch the GitHub run demonstrated: **many "stdio"
servers also ship an HTTP mode.** github-mcp-server's local default is
stdio, but `github-mcp-server http` runs the identical server over
HTTP. When a stdio-default server needs scanning, the first move is to
check for an HTTP mode, not to add stdio to jakk.

## Implications

What we DON'T build:
- stdio transport in `mcp_client.py`
- subprocess-launching scan orchestration
- stdio-specific config (command + args instead of URL)

What we DO say, clearly:
- jakk is "a black-box scanner for **HTTP** MCP servers" — the qualifier
  is load-bearing and honest, not a hedge.
- For stdio servers: run them in HTTP mode if they support it; otherwise
  they're out of jakk's threat model.
- The agent-side attacks against any-transport MCP consumers are
  its agent-side sibling's job, not jakk's.

## Validation

The GitHub-MCP coverage run (2026-05-23) confirmed the scope works:
jakk connected to github-mcp-server in HTTP mode, authenticated
per-request, and the auth probes produced true negatives against a
correctly-implemented production server. See
`docs/2026-05-23_github-mcp-coverage-run.md`.

## References

- the README ("How it's different") — the two-axis frame (server-side vs agent-side; jakk vs its agent-side sibling)
- `docs/2026-05-23_github-mcp-coverage-run.md` — the run that validated HTTP scope
- 2026 transport landscape: TrueFoundry "MCP Stdio vs Streamable HTTP", Apigene "Host MCP Server 2026", Cloudflare "MCP Demo Day"
