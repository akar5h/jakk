# external_targets — real-world MCP servers for jakk-style scanning

A registry of third-party MCP servers we point scanners at. Sources are
fetched on demand (not vendored). Every target is reachable as
`http://localhost:<port>/<path>` via streamable HTTP.

This is the docker-compose pattern endorsed by the field-harness survey
(`docs/research/2026-05-15_field-harness-survey.md` §"mcp-breach-to-fix-labs")
— every target ships a `vulnerable` / `secure` pair where the upstream
provides one, giving us free negative controls for the false-positive rate
of the catalog.

## Prereqs

- Docker + Docker Compose v2 (`docker compose ...`, not `docker-compose ...`)
- Git
- ~5 GB free disk for the Playwright base image; ~500 MB for breach-to-fix builds
- A working `bash` for `fetch.sh`

## One-time setup

```bash
./fetch.sh                       # clones third-party sources into _vendor/ (gitignored)
docker compose -f playwright-mcp/docker-compose.yml build playwright-mcp   # ~2-3 min
```

## Bring up targets

Each entry in `targets.yaml` records how to start the corresponding
service. Examples:

```bash
# breach-to-fix challenge 08 (command injection)
docker compose -f _vendor/mcp-breach-to-fix-labs/docker-compose.yml up -d \
    git-command-injection-vulnerable git-command-injection-secure

# breach-to-fix challenge 03 (whatsapp RUG — needs both halves)
docker compose -f _vendor/mcp-breach-to-fix-labs/docker-compose.yml up -d \
    whatsapp-rug-helper whatsapp-rug-whatsapp-vulnerable

# playwright-mcp
docker compose -f playwright-mcp/docker-compose.yml up -d playwright-mcp
```

Tear them down with `docker compose ... down <service>` (or `down` to
stop everything in the file).

## targets.yaml — schema

```yaml
version: 1
targets:
  - name: dotted.identifier
    kind: docker-compose                  # only kind today
    compose_file: ./relative/path.yml
    service: service-name-in-compose
    transport: streamable-http
    endpoint: http://localhost:PORT/PATH
    expected_classes: [jakk.attack.class] # [] for negative controls
    notes: one-line context
```

A scanner consumes this file by iterating `targets`, bringing up
`compose_file:service`, scanning `endpoint`, and asserting that exactly
`expected_classes` fire — failures and missing fires both signal catalog
drift.

## First-round calibration grid

| target | expected classes | what it proves |
|---|---|---|
| `breach-to-fix.git-command-injection.vulnerable` | `input.command_injection` | known-good positive for the command-injection rule |
| `breach-to-fix.git-command-injection.secure` | _(none)_ | catalog does not over-fire on the patched variant |
| `breach-to-fix.filesystem-prefix.vulnerable` | `input.path_traversal` | independent confirmation of the team-kb-mcp anti-pattern |
| `breach-to-fix.filesystem-prefix.secure` | _(none)_ | rule does not over-fire on canonical-path enforcement |
| `breach-to-fix.whatsapp-rug.helper` | `description.smuggling` | hidden instructions inside tool responses surface as smuggling |
| `breach-to-fix.whatsapp-rug.vulnerable` | `response.directive_passthrough` | the directive carrier — same class as team-kb-mcp `read_page` |
| `playwright-mcp` | `input.ssrf`, `response.directive_passthrough` | first real-world target; `input.ssrf` is a gap class flagged by the reading list and roadmap |

A correctly calibrated jakk should produce exactly the `expected_classes`
on each target — over-fires on the `.secure` pair are false positives,
under-fires on the `.vulnerable` pair are missed detections.

## Layout

```
external_targets/
├── README.md             (this file)
├── .gitignore            (ignores _vendor/)
├── fetch.sh              (idempotent clone of upstream sources)
├── targets.yaml          (machine-readable registry)
├── breach-to-fix/
│   └── README.md         (which PawelKozy services are wired, ports, teardown)
├── playwright-mcp/
│   ├── Dockerfile        (Playwright base + npx @playwright/mcp)
│   └── docker-compose.yml
└── _vendor/              (gitignored, populated by fetch.sh)
    └── mcp-breach-to-fix-labs/
```

## Safety

These servers are intentionally vulnerable or expose powerful capabilities
(browser navigation, shell, filesystem). Do not bind them to non-loopback
interfaces, do not run them on a shared machine, and do not point them at
production credentials. The compose files publish to `localhost:` only.

## License posture

Nothing third-party is checked into this repo. `fetch.sh` clones at use
time. `mcp-breach-to-fix-labs` ships without a license file at the time of
writing — treat it as "all rights reserved", do not redistribute. The
microsoft/playwright-mcp project is Apache-2.0 and consumed via npm
inside the Dockerfile (not vendored either).
