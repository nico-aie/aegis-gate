# Environment — tester `<id>` for sweep `<sweep-id>`

## Identity

- Tester: `<your-id>`
- AI assistant: `<model + version>` (e.g. `claude-sonnet-4.6`,
  `gpt-5-codex`, `gemini-2.5-pro`)
- Started: `<RFC 3339 UTC>`

## Code state

```sh
git rev-parse HEAD
# → paste full SHA here
git status -s
# → paste; should be empty (clean checkout)
```

## Build

```sh
cargo --version
# → paste
cargo build --release --workspace
# → paste tail (timing + warnings)
```

## Config

- Config file: `config/dev.yaml` (or path to your override)
- Listeners: data-plane `:8080`, admin `:9443` (default)
- State backend: `in_memory`
- Notable config diffs from upstream: <list, or "none">

## Aux services

```sh
docker compose -f deploy/docker-compose.dev.yml ps
# → paste
```

## Slice claimed

`<one of the slices from CLAIMS.md>`

## AI assistant prompt prefix

Confirm you prepended (or pasted) the contents of
`tests/AI-ASSISTANT-RULES.md` to your AI's system prompt before
the first message. ☐ yes ☐ no

If no — your findings will be filtered with extra suspicion
during consolidation.

## Pre-flight checks (run, paste output)

```sh
make smoke
# → paste tail
```
