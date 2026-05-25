# `mcp.response.directive_passthrough`

**OWASP:** MCP03 (indirect prompt injection) · **severity:** high · **signal:** `response.directive_passthrough`

## What it is
Call a benign tool and scan the response for model-directed imperatives:
`SYSTEM:`, `Ignore previous instructions`, `You are now …`,
`<SYSTEM>…</SYSTEM>`, `New instructions:`. If a tool *response* carries
instructions to the model, that response is an injection surface even
though no malicious input was sent.

## Why we picked it
Breach-to-fix ch03 ("hidden instructions in tool responses") is the
canonical example. Realistic instances: notification feeds, news/RSS
helpers, message inboxes — anywhere the tool returns content that
originated outside the server's trust boundary.

## Threat model
**What "vulnerable" means here:** the tool's response contains content that *issues instructions to the LLM* (`SYSTEM:`, `Ignore previous instructions`, `<SYSTEM>…</SYSTEM>`, `You are now…`). The response is an indirect-prompt-injection surface even when the *input* was benign.

**Harm:** the LLM is hijacked mid-task. Attacker can steer it to exfiltrate the user's data, call destructive tools, leak the system prompt, or return misleading output. The user thinks they're talking to their agent; they're talking to whoever planted the content.

**Harmed parties:** user (agent hijacked) and operator (their tool became an injection surface, likely without their knowledge).

See [../threat-models.md](../threat-models.md) for the full class.

## How it fires
1. Pick any tool matching `^(list|get|read|describe|status|info|news|search|fetch|message|messages|notifications)`.
2. Call with empty arguments.
3. Match the response against the `directive_passthrough` heuristic set.

## How detection works
Curated regex set. Conservative on purpose — only matches relatively
unambiguous LLM-directive language. False positives are possible on
content that happens to discuss prompts (e.g. a blog post about prompt
injection). Operators should treat findings as "needs eyes," not
"definitely compromised."

## Expected results
- ch03 vulnerable helpers (whatsapp-rug, news-prompt-exfiltration) — **fires**.
- ch08 / ch02 plain tools — does **not** fire.

## YAML shape
See `library/mcp/mcp.response.directive_passthrough.yaml`.
