# Contributing

PolicyProbe is written and maintained by Krishita Sanjay Choksi. Issues and discussion are
welcome — particularly on the mapping itself.

## The part most worth arguing about

The mapping in [`mappings/protocol_weakness_control.yaml`](mappings/protocol_weakness_control.yaml)
is one assessor's judgement about which control a given physical-layer finding evidences.
Two competent assessors will not agree on every row. That is exactly why every row carries a
rationale in plain language: so it can be disagreed with specifically rather than in general.

If you think a row is wrong, open an issue naming the weakness id, the control id, and what
you would map it to instead. That is a more useful contribution than code.

## Working on the code

```bash
make setup
make validate      # the knowledge base must have no dangling references
make test
```

If you change the knowledge base, run `make tables` so the README tables match it — CI
checks that the pipeline still runs, and a README that disagrees with the engine is a bug.

## Scope

Additions that extend the tool's *assessment* reach are in scope: more frameworks, more
credential generations, better evidence text, a sharper risk model.

Additions that extend its *offensive* reach are not: credential emulation, writing to blank
media, key recovery, jamming and relay are deliberately absent and will stay absent. See
[`docs/threat_model.md`](docs/threat_model.md) for the reasoning.
