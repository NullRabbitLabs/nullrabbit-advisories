# NR-2026-027 — Sui JSON-RPC and admin-interface node-availability findings: response amplification, filter-driven scan, subscription exhaustion, and unauthenticated admin surface

**NullRabbit Operator Advisory** · Published 2026-07-08

> **Why we publish publicly:** these are out-of-scope-for-bounty, node-availability and hardening findings on the Sui fullnode/RPC surface — analysis + detection reproducers only. See [Why we publish these findings publicly](../WHY-WE-PUBLISH.md).

## Summary

Four independent findings on the Sui fullnode's public JSON-RPC surface and its node admin interface share one operator-facing theme: a small, unauthenticated request converts into disproportionate server work (CPU, egress, or held state), or reaches a control-plane that has no authentication beyond its loopback bind. None break consensus, funds, or safety; each is an availability or hardening concern on a node an operator has exposed beyond loopback. All four are measured against a self-owned Sui localnet; the loopback default is not remotely reachable.

## Findings at a glance

| Finding | Primitive | Surface | Mechanism | Measured |
|---|---|---|---|---|
| Response amplification | `sui_p05_multiget_txblocks_amp` | `POST` `sui_multiGetTransactionBlocks` | full-expand options return each tx block inflated | ~80.6× (2.6 kB → 213 kB at 50 digests) |
| Filter-driven scan | `sui_p07_getownedobjects_scan` | `POST` `suix_getOwnedObjects` | never-match filter walks the whole owned-object set (O(N)) | ~30× serial miss-path latency; ~184× control-probe degradation under 32 concurrent clients |
| Subscription exhaustion + filter breadth | `sui_p01_p06_subscribe_filter_exhaustion` | WS `suix_subscribeEvent` | held-open subscriptions leak permits; deep Or-tree filter drives per-event CPU | 99/100 permits held (legit probe fails); filter-breadth CPU per delivered event |
| Admin interface without authentication | `sui_h01_admin_no_auth_probe` | node admin HTTP port | ~16 control-plane endpoints, no auth, loopback-gated | all endpoints reachable on stock localnet; `/node-config` egress ~360,000× |

- **Class:** node-availability (response/compute amplification, connection exhaustion) plus one no-auth admin hardening finding
- **Severity:** availability / hardening only; **out of paid scope** on the Sui bug-bounty program, publish-track under NullRabbit's disclosure policy
- **Affected:** operators who expose the Sui JSON-RPC or admin interface on a non-loopback address (indexer / RPC-provider / explorer deployments); the loopback default is not remotely reachable

## Mechanism (source-cited, `MystenLabs/sui`)

**1. `sui_p05_multiget_txblocks_amp` — `sui_multiGetTransactionBlocks`.** With the full option set (`showInput` / `showRawInput` / `showEffects` / `showEvents` / `showObjectChanges` / `showBalanceChanges`) each requested digest returns a fully expanded transaction block (inputs, effects, events, object and balance changes). A ~2.6 kB batched request of 50 digests pulls a ~213 kB response, ~80.6× egress amplification with no per-response byte cap. Sibling of the `sui_multiGetObjects` amplifier (NR-2026-004).

**2. `sui_p07_getownedobjects_scan` — `suix_getOwnedObjects`.** `get_owned_objects` (`crates/sui-json-rpc/src/indexer_api.rs`) dispatches into the synchronous `get_owner_objects_iterator` (`crates/sui-core/src/authority_state.rs`), which walks `IndexStore::iter_owned_objects` (`crates/sui-core/src/authority.rs`, RocksDB prefix iterator over `(owner, object_id)`). The `StructType` / `MoveModule` / `Package` filters are applied **after** each candidate is yielded, so a never-matching filter walks the victim's entire owned-object set before returning `hasNextPage=false` with zero results: an O(N) scan per request on the tokio worker. Under concurrency it saturates the worker pool.

**3. `sui_p01_p06_subscribe_filter_exhaustion` — `suix_subscribeEvent` (WebSocket).** Unauthenticated WS subscriptions with a deep balanced Or-tree event filter, held open in a burst, exhaust the server's subscription permits (P01) and drive per-delivered-event filter-evaluation CPU (P06). Neither the permit accounting nor the filter breadth is bounded per source.

**4. `sui_h01_admin_no_auth_probe` — node admin interface.** The Sui node admin server exposes ~16 control-plane endpoints (`/capabilities`, `/node-config`, `/set-override-buffer-stake`, `/force-close-epoch`, `/traffic-control`, …) with no authentication; the only access control is the loopback bind. Any client that can reach the admin port enumerates and drives them with plain HTTP. This is a hardening finding: it is remotely reachable only where an operator has exposed the admin port (sidecar / misconfiguration). `/node-config` additionally returns a large response for a trivial request.

## Measurement (fidelity: lab)

Measured on self-owned Sui localnets (`sui start`, Sui v1.70.1 class), single process; figures are per-node resource cost, not a mainnet consensus claim:

- **P05:** 50-digest full-expand request ~2.6 kB → ~213 kB response, ~80.6× egress amplification.
- **P07:** never-match filter ~30× serial miss-path latency vs a no-filter call; a `getChainIdentifier` control probe degrades from ~1 ms p50 to ~186 ms p50 under 32 concurrent attackers (~184×) as the worker pool saturates; measured filter-miss amplification 26× at n=8.
- **P01/P06:** 99 of 100 subscription permits held by an attacker burst (a legitimate probe then fails to subscribe); wide-filter (breadth ~5000) drives measurable per-event CPU.
- **H01:** every admin endpoint returns 200 on a stock localnet with no credential; `/node-config` egress ~360,000× the request.

The published corpus reproducers capture the **attack traffic** — the small crafted request contrasted with the disproportionate response / held state on the same loopback flow. These advisories stand on the source trace and the handler-level measurement, not on the reproducer's localnet transport.

## Mitigation

- **P05:** cap the `sui_multiGetTransactionBlocks` response size / batch length; bound the per-block expansion.
- **P07:** apply the `StructType` / `MoveModule` / `Package` filter inside the storage iterator (or bound the scan) so a never-match filter cannot walk the full owned-object set; rate-limit `getOwnedObjects` per source.
- **P01/P06:** release subscription permits + streamer state on disconnect; cap concurrent subscriptions per source; bound event-filter vector length / Or-tree depth (see NR-2026-006).
- **H01:** keep the admin interface loopback-bound (the documented default); if an operator must expose it, front it with authentication; cap `/node-config` response size.

## Vendor channel and scope

Availability and hardening findings on the Sui node surface. DoS / resource-exhaustion and best-practice hardening are out of scope on the Sui bug-bounty program (HackenProof), and the direct `security@sui.io` channel is unresponsive, so these are published as plain operator advisories under NullRabbit's disclosure-scope policy rather than held. Vendor: **MystenLabs / `MystenLabs/sui`**.

## Scope

Availability / resource-cost and one no-auth hardening finding; no consensus-safety, no funds, no chain halt, no authentication break of the validator surface. The reproducers target self-owned localnets, carry no public IPs or mainnet hostnames, and are not a turnkey mainnet weapon. Loopback-bound JSON-RPC and admin interfaces (the defaults) are not remotely reachable.

## Provenance

NullRabbit original measurement (`provenance.source_class: original`); detection primitives `sui_p05_multiget_txblocks_amp`, `sui_p07_getownedobjects_scan`, `sui_p01_p06_subscribe_filter_exhaustion`, and `sui_h01_admin_no_auth_probe` are shipped in the public dataset [`NullRabbit/nr-bundles-public`](https://huggingface.co/datasets/NullRabbit/nr-bundles-public) (on-spec + on-HF). Source traces and per-finding measurement runs in `chains/sui/findings/`.

## Contact

Simon Morley, NullRabbit — `simon@nullrabbit.ai`.

If you operate Sui fullnode / RPC / indexer infrastructure and have applied the mitigations above, or have measurements at variance with these, we would like to hear from you.
