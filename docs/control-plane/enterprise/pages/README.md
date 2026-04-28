# Per-page Specs

Each file in this directory is the design contract for one
sidebar page. They share a common shape:

1. **Route** — URL the SPA shell maps to this page.
2. **Data sources** — table of widget → endpoint, plus refresh
   policy (poll interval or SSE).
3. **Layout** — ASCII frame plus widget anatomy.
4. **Per-widget detail** — interactions, drill-ins, drawer flows.
5. **States** — loading / empty / error / stale.
6. **Performance** — caching, batching, expected payload sizes.
7. **Audit / safety** — when mutations happen, what gets written
   to the chain.

| Page | File |
|------|------|
| Overview | [`overview.md`](overview.md) |
| Live Feed | [`live-feed.md`](live-feed.md) |
| Attack Events | [`attack-events.md`](attack-events.md) |
| Analytics | [`analytics.md`](analytics.md) |
| Audit Log | [`audit-log.md`](audit-log.md) |
| Rule Manager | [`rule-manager.md`](rule-manager.md) |
| Tier Config | [`tier-config.md`](tier-config.md) |
| Blacklist | [`blacklist.md`](blacklist.md) |
| Whitelist | [`whitelist.md`](whitelist.md) |
| Settings | [`settings.md`](settings.md) |
| Tracking | [`tracking.md`](tracking.md) |

Cross-cutting design tokens, layout chrome, and component
library live one level up:

- [`../layout.md`](../layout.md)
- [`../theme.md`](../theme.md)
- [`../components.md`](../components.md)
- [`../api.md`](../api.md)
- [`../assets.md`](../assets.md)
- [`../accessibility.md`](../accessibility.md)
- [`../security.md`](../security.md)
