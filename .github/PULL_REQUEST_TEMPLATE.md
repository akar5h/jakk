## What

<!-- One or two sentences. -->

## Type

- [ ] New probe
- [ ] Bug fix
- [ ] Feature / capability
- [ ] Docs

## Checklist

- [ ] `pytest tests/unit -q` passes
- [ ] (new probe) added `docs/tests/<id>.md` spec + a `docs/threat-models.md` entry
- [ ] (new probe) `side_effect` set honestly; targets args by role (`target_arg_kind`) where possible
- [ ] No secrets / tokens in the diff
- [ ] Matches existing style; comments where intent isn't obvious
