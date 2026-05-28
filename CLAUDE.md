# jakk — agent guidance

Deterministic, black-box security scanner for MCP servers. Public OSS, **no LLM in the loop**.

## Repo orientation

- `jakk/` — Python package (CLI, scanner, matchers, library loader, MCP client).
- `library/mcp/` — **public** probe library (YAML). Ships with the tool. Community-extensible.
- `tests/` — `pytest` (asyncio_mode=auto). Always green before commit.
- `examples/external_targets/` — vulnerable + hardened lab targets (breach-to-fix labs).
- `internal/` — **private, gitignored** working notes, in-flight project plans, novel-probe drafts. Local-only; do not assume future sessions on other machines see it.

## Probe library policy (load-bearing)

The public `library/mcp/` ships **known/standard** probe classes — what builders and ecosystem auditors should be able to run against their servers out of the box. Things documented elsewhere (OWASP-MCP, public CVE patterns, BlueRock-style reports).

**Novel** probe classes developed during research (new bug classes, server-specific traps, advanced techniques not yet publicly described) live under `internal/library/mcp/` and **must not** be committed to the public repo. They are reserved for paid offerings / pre-disclosure research / future commercialization.

When asked to "add a probe," ask whether it belongs in the public library (known class) or the private one (novel). When in doubt, file private first; promote to public only when (a) the class becomes widely known elsewhere, or (b) we choose to release as a goodwill move.

## Active project — FastMCP Ecosystem Audit

**Status doc: [`internal/benchmark/STATUS.md`](internal/benchmark/STATUS.md)** — read this first for current state, phase, in-progress tasks. If the file isn't present, this is a fresh checkout without the private workspace; ask the user.

Goal: scan ~50 FastMCP-built servers + ~10 reference/high-profile MCP servers, publish a per-server scoreboard, file coordinated disclosures, launch jakk to the community with the audit as the headline.

## Engineering conventions

- Branch off `main` for every change. No direct commits to `main`.
- Each commit single-purpose. Show the diff before committing on request.
- `pytest -q` clean before any commit that touches `jakk/` or `tests/`.
- Co-Authored-By trailer on AI-pair commits.
- Don't `git push` without an explicit ask (credential context is the user's).

## Coordinated disclosure (for benchmark findings)

- Findings against third-party servers go via **private channels** — project `SECURITY.md`, maintainer email, GitHub Security Advisory draft. **Never** a public Issue or PR before a fix exists.
- Hold publication ≥30 days after the maintainer is notified.
- FastMCP team receives an advance copy of the audit before the public writeup.
- Framing in the public writeup is constructive — "here's what the ecosystem looks like, here's what's already secure, here's what got fixed" — not "X is riddled with bugs."
