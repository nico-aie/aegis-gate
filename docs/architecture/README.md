# Architecture docs

Cross-cutting design notes that don't belong to a single subsystem.
The top-level [`../../Architecture.md`](../../Architecture.md) is the
authoritative system-shape reference; this folder holds the deeper
references it links into.

| Doc | Summary |
|---|---|
| [protocols.md](./protocols.md) | HTTP/1.1, HTTP/2, HTTP/3, WebSocket, gRPC — what the data plane speaks and how protocol choice affects the security pipeline |
| [scaling-model.md](./scaling-model.md) | Three-layer scaling model (in-node CPU / cross-node redundancy / shared state) and how the Aegis Console surfaces all three |
| [storage-and-contract.md](./storage-and-contract.md) | Where each piece of runtime data lives (Redis / etcd / disk) and how that layout maps to the v2.3 interop contract requirements |
