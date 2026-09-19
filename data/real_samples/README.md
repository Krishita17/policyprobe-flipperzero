# Real sample reads

This directory holds genuine Flipper Zero reads of **the author's own test media** — blank
and development tags, a spare fob, an iButton, a remote the author owns. They exist so the
classifier can be scored on real signals as well as simulated ones (Tier 2 of the project).

## Rules for this directory

* Only devices the author owns, or that a client has explicitly provided for testing under
  a signed engagement.
* **No facility identifiers.** A sample records the technology and the observation, never
  where it was found. There is no field for a site, a door or an organisation, and adding
  one would be a mistake.
* No card numbers, facility codes or keys belonging to any organisation.
* Every sample must set `"owned_by_author": true`. The loader refuses anything else.

See `../../docs/threat_model.md` for the full scope rules.

## Format

One JSON object per file, or a JSON list of them. `TEMPLATE.json` is the schema and is
skipped by the loader.

## Capturing your own

```bash
make scan-real PORT=/dev/tty.usbmodemflip_Xxxxxxx
```

then transcribe the observation into a file here, set the true `device_type` and the
`ground_truth_weaknesses` you can justify, and re-run `make evaluate`. The classifier
accuracy figure gains its real-hardware comparison column automatically once samples are
present; until then it renders with a note saying the comparison is unpopulated, rather
than inventing numbers.
