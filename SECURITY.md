# Security Policy

`jakk` is an offensive security tool that, by design, consumes untrusted
data from the servers it scans. Its own security posture matters.

## Reporting a vulnerability

**Do not open public issues, discussions, or pull requests for security
vulnerabilities.**

Email the maintainer (`akarshgajbhiye@gmail.com`) with:

- The affected component / file.
- A description of the issue and impact.
- Steps to reproduce (a minimal PoC if possible).

Expected response:

- **Triage acknowledgement within 48 hours.**
- A remediation timeline after triage.
- **Coordinated disclosure window: 90 days** from report, or sooner by agreement.

## Scope

### In scope

- Vulnerabilities in `jakk`'s own code (`jakk/`), its probe library (`library/`), or its declared dependency closure.
- Specifically: anything where a **malicious MCP server `jakk` is pointed at** can compromise the scanner host — code execution, terminal corruption, memory exhaustion, or exfiltration of the operator's own secrets. See [`docs/2026-05-23_self-security-audit.md`](docs/2026-05-23_self-security-audit.md) for the current self-audit.

### Out of scope

- **Third-party MCP servers** you point `jakk` at. Bugs there are findings *produced by* `jakk`; report them to that server's maintainer through their own disclosure process.
- The deliberately-vulnerable lab targets under `examples/external_targets/` — they are intentionally insecure test fixtures.
- Issues requiring a malicious local user who already has code execution on the operator's machine.

## Responsible use

Only run `jakk` against systems you own or are explicitly authorized to
test. See [`docs/depth-of-exposure-methodology.md`](docs/depth-of-exposure-methodology.md)
for the authorization pre-flight expected before testing any target you
do not own.
