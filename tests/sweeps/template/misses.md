# Misses — tester `<id>` for sweep `<sweep-id>`

> Things you wanted to test but couldn't. Bullet form. Surfaces
> coverage gaps without inflating `findings.jsonl` with non-bugs.

## Couldn't reproduce

- _example: "Tried to reproduce a flaky strike-block ramp from
  hackathon-stress-test.md but the dev config's `risk.strikes.block_at`
  is 50 — couldn't easily inflate. Needs a separate config fixture."_

## Out of scope for this slice

- _example: "Saw an unrelated CSP warning on the Console login page;
  belongs to slice `control.dashboard.config`, not mine."_

## Tooling gaps

- _example: "No easy way to generate a malformed CA bundle from the
  CLI for mTLS-T10 testing — had to hand-edit a PEM."_

## AI-assistant friction

- _example: "Assistant kept suggesting `cargo test` from inside the
  test process; had to remind it twice."_
