# Contributing to jakk

Thanks for considering a contribution. The highest-value contribution is
usually **a new probe** — and that takes minutes, no Python required.

## Add a probe in 5 minutes

A probe is one YAML file in `library/mcp/`. It declares:
1. **which tools** it fires against (`applies_to`),
2. **what to send** (`payload`),
3. **how to decide if it fired** (`matcher`).

Minimal example (`library/mcp/mcp.path.prefix_bypass.yaml`):

```yaml
id: mcp.path.prefix_bypass          # unique dotted slug
surface: tool_call
severity: high                      # info | low | medium | high | critical
side_effect: unsafe                 # safe = read-only; --safe runs only these
owasp: [MCP04]
expected_signal: input.path_traversal

applies_to:
  tool_name_regex: "(?i)(read|file|path|list)"   # narrow the candidate tools
  target_arg_kind: path             # scanner finds the path-shaped arg by role
  min_string_args: 1

payload:
  arguments:
    __target_arg__: "/app/files/safe_files_sensitive/"   # lands in the path arg

matcher:
  kind: regex                       # substring | regex | marker_echo |
                                    # secret_pattern | directive_passthrough |
                                    # schema_field | cloud_metadata
  params:
    pattern: "safe_files_sensitive"
```

Then:

```bash
# 1. validate it loads + matches your expectation
pytest tests/unit/test_jakk_library.py

# 2. add a per-probe spec page
$EDITOR docs/tests/mcp.path.prefix_bypass.yaml.md

# 3. (optional) prove it fires against a real/lab target
jakk mcp scan --endpoint <url> --library library/mcp --select mcp.path.prefix_bypass
```

### Probe design principles

- **Target args by role, not name.** Use `target_arg_kind` + `__target_arg__` so the probe works across servers that name the same argument differently (`path` vs `file_path` vs `full_path`). See [`docs/README.md`](docs/README.md) for the full schema and the arg-kind registry.
- **Be honest about side effects.** `side_effect: safe` means the probe cannot mutate server state. If in doubt, mark it `unsafe`.
- **Sink + impact.** Where it helps, split a "the bug exists" probe from an "and here's the impact" probe (see `command.shell_marker` → `command.secret_file_read`).
- **Low false positives.** A probe that cries wolf is worse than none. Prefer precise matchers; document any false-positive risk in the per-probe spec.
- **Anchor in a threat model.** Add an entry to [`docs/threat-models.md`](docs/threat-models.md): what does `vulnerable` mean here, and who is harmed?

## Dev setup

```bash
git clone https://github.com/akar5h/jakk && cd jakk
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/unit -q          # 143 tests, no live server needed
```

## Pull requests

- Keep PRs focused (one probe, one fix, one feature).
- Add/extend tests — unit tests don't require a live MCP server.
- Match existing style (typed, comments where intent isn't obvious).
- Run `pytest tests/unit` before pushing; CI runs it on PRs.
- For a new probe, include its `docs/tests/<id>.md` spec and a threat-model entry.

## Reporting bugs / security issues

- Functional bugs: open an issue using the bug template.
- **Security vulnerabilities in jakk itself: do NOT open a public issue.** See [SECURITY.md](SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
