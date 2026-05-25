# `mcp.authz.cross_tenant_read`

**OWASP:** MCP08 (broken object-level authorization, BOLA-equivalent) · **severity:** critical · **signal:** `authz.cross_tenant_read`
**side_effect:** safe (read-only)

## What it is
Two-credential confused-deputy probe. Two identities (A and B) attempt
to read the same object. If B can read an object belonging to A's
tenant, the server fails to enforce per-tenant authorization — the
classic *confused deputy* shape that drives most commercial-MCP bugs.

Phase A (sanity check): identity A reads its own object. Should
succeed. If it fails, the probe's `--cred-a` or `--foreign-id` is
wrong and the probe emits `error`, not a finding.

Phase B (the probe): identity B attempts the same read. If B succeeds
AND the response identifies the object as belonging to A → vulnerable.

## Why we picked it
Cross-tenant reads are the single most common bug class in commercial
MCPs (workspace MCPs, multi-account proxies, anything fronting a
multi-tenant backend). The fix is invariant across vendors — verify
per-call ownership — so a probe that catches the shape catches the bug
across many targets.

## Required configuration
Three CLI flags must all be set, or the probe emits `skipped`:

| Flag | Purpose |
|---|---|
| `--cred-a TOKEN` | Identity A's credential. For ch01: `alpha-api-key`. |
| `--cred-b TOKEN` | Identity B's credential. For ch01: `bravo-api-key`. |
| `--foreign-id ID` | An object ID owned by A's tenant. For ch01: `CRM-1001`. |

The credential is whatever the target uses for identity. ch01 uses a
tool-argument `api_key`; a Slack-style MCP would use the HTTP bearer
(in which case `--cred-a` / `--cred-b` could be passed but the YAML
arguments wouldn't reference them — they'd be set via `--bearer` per
call instead). This generality is intentional.

## Threat model
**What "vulnerable" means here:** the server *authenticates* the caller (validates that the credential is real) but doesn't *authorize* the specific resource (doesn't check that the credential's identity owns the requested object). Classic confused-deputy / BOLA (Broken Object-Level Authorization).

**Harm:** paying customers of a multi-tenant service read each other's data. Contracts, customer lists, financial records, PII, employee data, internal documents. In B2B SaaS this is typically the highest-impact bug class — often triggers public disclosure obligations (GDPR, SOC2, customer breach notifications).

**Harmed parties:** every other tenant of the service. The "attacker" is any paying customer; no exploitation skill required, just guessing or knowing other tenants' resource IDs (which are frequently predictable — sequential, low-entropy UUIDs, customer-name slugs).

See [../threat-models.md](../threat-models.md) for the full class.

## How it fires
1. Skip if any of `--cred-a` / `--cred-b` / `--foreign-id` missing.
2. Expand `{cred_a}` / `{cred_b}` / `{foreign_id}` / `{run_id}` in
   `phase_a.arguments` and `phase_b.arguments`.
3. Open one `MCPClient` (with scan-wide auth/headers).
4. Run `phase_a` — A reads A's object. Must succeed.
5. Run `phase_b` — B reads A's object.
6. Apply the matcher to `phase_b`'s response. For ch01, the matcher is
   a regex `"tenant"\s*:\s*"tenant_alpha"` — if B's response shows the
   object's tenant field as A's tenant, B saw A's data.

## Expected results
- `http://127.0.0.1:8001/mcp/stream` (ch01 vulnerable) — **vulnerable**.
  Both `fetch_project(CRM-1001, bravo-api-key)` and
  `fetch_project(CRM-2001, alpha-api-key)` leak. Evidence includes the
  `"tenant": "tenant_alpha"` match.
- ch01-secure variant — should return permission-denied for the cross-
  tenant read; matcher returns `pass`.
- Any server without the required flags → `skipped`.

## Adapting to other targets
Override these YAML fields for your target:

```yaml
phase_a:
  tool: <a read tool the server actually exposes>
  arguments:
    <object-id-arg>: "{foreign_id}"
    <credential-arg>: "{cred_a}"

phase_b:
  tool: <same tool, different identity>
  arguments:
    <object-id-arg>: "{foreign_id}"
    <credential-arg>: "{cred_b}"

matcher:
  kind: regex | substring | secret_pattern | ...
  params:
    pattern: <something distinctive about A's content that should not appear in B's normal results>
```

## YAML shape
See `library/mcp/mcp.authz.cross_tenant_read.yaml`.
