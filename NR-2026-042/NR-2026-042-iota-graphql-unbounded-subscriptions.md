# NR-2026-042 — IOTA GraphQL RPC: `subscription_handler` graphql-transport-ws WebSocket has no per-connection / per-IP / concurrent-subscription cap → unbounded broker + per-connection memory growth

**NullRabbit Operator Advisory** · Published 2026-07-13

## Summary

The IOTA GraphQL RPC exposes a WebSocket subscription surface whose `subscription_handler` upgrades an incoming
HTTP request to a **graphql-transport-ws** connection and serves it via `GraphQLWebSocket` with **no
per-connection, per-IP, or concurrent-subscription cap** — only per-operation query-complexity limits apply
(`iota-graphql-rpc` `builder.rs` `subscription_handler` + `types/subscription/mod.rs`). An **unauthenticated**
client can send a single `connection_init` followed by a burst of `subscribe` operations; each subscription pins
a broker stream (`BROKER_CHANNEL_SIZE = 10k`) plus per-connection state, and nothing bounds how many a single
connection — or a single source across many connections — may hold open. This is an **availability** concern
(WebSocket per-connection / broker memory exhaustion) on the **optional** GraphQL RPC surface. It is
**operator-gated**: it only affects nodes that have enabled the GraphQL RPC with indexer-streaming, which is
**off on default mainnet fullnodes**. That gating bounds severity to **MEDIUM**. As an availability /
resource-bounding hardening class it is **out of paid scope**, handled on NullRabbit's publish-track.

## Findings at a glance

| Finding | Primitive | Surface | Class | Severity |
|---|---|---|---|---|
| `IOTA_GRAPHQL_S1_UNBOUNDED_SUBS` | `iota_graphql_s1_unbounded_subs` | IOTA GraphQL RPC graphql-transport-ws subscription WebSocket (`iota-graphql-rpc`) | `graphql-subscription-cap` + `connection-exhaustion` | MEDIUM |

- **Reachability:** any remote host that can reach the GraphQL RPC WebSocket port **when the operator has
  enabled it**; no auth, minimal bandwidth. Default mainnet fullnodes do **not** expose this surface.
- **Severity:** MEDIUM — availability-only, and **operator-gated** (requires the optional GraphQL RPC +
  indexer-streaming). **Out of paid scope**, publish-track.
- **Affected:** IOTA nodes running the optional GraphQL RPC with indexer-streaming enabled. Not the default
  fullnode configuration.
- **Mitigation:** add per-connection + per-IP concurrent-subscription caps, a max-subscriptions-per-connection
  bound, and idle/auth timeouts on the graphql-transport-ws handler; bound the broker channel per subscriber;
  require auth or front the GraphQL RPC with a rate-limiting gateway. See Mitigation.

## Mechanism (source-cited, `iota-graphql-rpc`)

- **The upgrade path.** `builder.rs` `subscription_handler` upgrades an incoming request to a
  **graphql-transport-ws** WebSocket and hands it to `GraphQLWebSocket` (`types/subscription/mod.rs`). The
  handler applies the schema's per-operation **query-complexity** limits, but there is **no separate accounting
  for the number of concurrent subscriptions** on a connection, from an IP, or globally.
- **The missing caps.** No per-connection concurrent-subscription limit, no per-IP limit, no
  max-subscriptions-per-connection bound, and no idle/auth timeout gate the subscription lifecycle. Query
  complexity bounds the cost of *one* operation — not the *count* of operations held open.
- **The attack.** An unauthenticated client completes the `connection_init` handshake and then issues a burst of
  `subscribe` operations. Each accepted subscription pins a broker stream (`BROKER_CHANNEL_SIZE = 10k`) plus
  per-connection bookkeeping; because nothing caps the count, per-connection state and broker-stream allocation
  grow **unboundedly** with the burst size (and can be multiplied across many connections from one source),
  pinning memory on the GraphQL RPC process.

## Measurement (fidelity: explicit)

This finding is **predicted MEDIUM, source-traced — it is NOT yet live-measured.** The severity and mechanism
rest on the upstream source trace above (`subscription_handler` upgrading to graphql-transport-ws and serving
`GraphQLWebSocket` with only query-complexity limits, no subscription-count cap; `BROKER_CHANNEL_SIZE = 10k`),
**not** on an independent server-side resource measurement.

The published corpus reproducer (primitive `iota_graphql_s1_unbounded_subs`; family `connection_exhaustion`,
`source_class: original`, shipped in `NullRabbit/nr-bundles-public`) captures the **wire signature** of the
attack — the unauthenticated `connection_init` handshake followed by a `subscribe`-op burst over the
graphql-transport-ws WebSocket. The unbounded per-connection / broker-stream growth is the **source-traced
mechanism**, not a measured server outcome. There is no claimed victim RSS/CPU figure here — this advisory
stands on the source trace plus the captured wire signature, and explicitly does not assert a measured
exhaustion.

## Scope

Availability only (WebSocket per-connection / broker-channel memory growth on the **optional** GraphQL RPC
surface); no consensus-safety break, no funds, no authentication bypass, no data corruption. A node that does
**not** run the optional GraphQL RPC / indexer-streaming — which is the default mainnet fullnode posture — is not
affected, and a GraphQL RPC that enforces per-connection / per-IP concurrent-subscription caps is not affected.
The reproducer targets a local self-owned mock, carries no public IPs or mainnet hostnames, and is not a turnkey
mainnet weapon.

## Mitigation

- **Bound the subscription surface:** add a **per-connection** and **per-IP concurrent-subscription cap** plus a
  **max-subscriptions-per-connection** bound and **idle / auth timeouts** on the graphql-transport-ws handler,
  so a single connection or source cannot hold unbounded broker streams open.
- **Bound the broker per subscriber:** cap broker-channel allocation per subscriber rather than relying on the
  fixed `BROKER_CHANNEL_SIZE = 10k` with an unbounded subscriber count.
- **Gate access:** require authentication on the subscription WebSocket, or front the GraphQL RPC with a
  rate-limiting gateway where a bounded in-process cap cannot be relied upon.
- **Operators who do not need it:** leave the GraphQL RPC / indexer-streaming disabled (the default) — the
  surface is not present at all.

## Disclosure & provenance

Availability-only, deployment/hardening-mitigable resource exhaustion on an **operator-optional** GraphQL RPC
surface → **out of paid scope → publish-track** under NullRabbit's disclosure-scope policy. This is our own
(`source_class: original`) source-traced finding of the IOTA-specific missing subscription caps in
`iota-graphql-rpc` — not an assigned IOTA CVE and not yet an independent server measurement. The corpus primitive
`iota_graphql_s1_unbounded_subs` is **on-spec** (registered in the known-class provenance map) and **on-HF**
(shipped in `NullRabbit/nr-bundles-public`, registered in `HF_DATASET_PRIMITIVES`), so this advisory does not
outpace its shipped defensive artefact. Finding tracked as `IOTA_GRAPHQL_S1_UNBOUNDED_SUBS`; the advisory is
explicit that severity is **predicted MEDIUM, source-traced, not live-measured**, and bounded by the operator
gating described above.
