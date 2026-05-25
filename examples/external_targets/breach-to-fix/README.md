# breach-to-fix targets

Wrapper for selected challenges from `PawelKozy/mcp-breach-to-fix-labs`.
Upstream is **not** vendored — `../fetch.sh` clones it into `../_vendor/`.
That directory is gitignored.

## Bring up a target

After running `../fetch.sh` once:

```bash
cd ../_vendor/mcp-breach-to-fix-labs
docker compose up -d <service>
```

…or, equivalently, from this directory:

```bash
docker compose -f ../_vendor/mcp-breach-to-fix-labs/docker-compose.yml up -d <service>
```

## Wired services (and what each is for)

| service | port | endpoint | what jakk should fire |
|---|---|---|---|
| `git-command-injection-vulnerable` | 8008 | `/mcp/stream` | `input.command_injection` |
| `git-command-injection-secure` | 9008 | `/mcp/stream` | _(none — negative control)_ |
| `filesystem-bypass-prefix-vulnerable` | 8002 | `/mcp/stream` | `input.path_traversal` (CVE-2025-53110) |
| `filesystem-bypass-prefix-secure` | 9002 | `/mcp/stream` | _(none — negative control)_ |
| `whatsapp-rug-helper` | 8003 | `/mcp/stream` | `description.smuggling` |
| `whatsapp-rug-whatsapp-vulnerable` | 8004 | `/mcp/stream` | `response.directive_passthrough` |

The `whatsapp-rug` scenario uses two services together — bring up both.

## Teardown

```bash
docker compose -f ../_vendor/mcp-breach-to-fix-labs/docker-compose.yml down <service>
```

Or stop everything in the upstream stack at once:

```bash
docker compose -f ../_vendor/mcp-breach-to-fix-labs/docker-compose.yml down
```

## Other challenges in the upstream repo

`mcp-breach-to-fix-labs` ships 9 challenges plus a partial 10th. We have wired
3 of them above; the rest are listed by the upstream compose file and can be
added to `../targets.yaml` when their attack class lands in the jakk catalog
(e.g. `input.sql_multistatement` → ch.04 xata, `response.exfiltration` →
ch.05 news, ch.06 log-poisoning, ch.07 stored-prompt SQLi, ch.09 GitHub
issue injection, ch.10 tool-description poisoning).
