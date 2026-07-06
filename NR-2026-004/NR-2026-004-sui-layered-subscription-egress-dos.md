# NR-2026-004 — Sui fullnode takedown by composing a wide-filter subscription memory-pin with multiGetObjects egress amplification

**NullRabbit Operator Advisory** · Published 2026-07-02

> **Why we publish publicly:** these are out-of-scope-for-bounty, no-embargo node-availability findings — analysis + reproducer only. See [Why we publish these findings publicly](../WHY-WE-PUBLISH.md).

## Summary

A single attacker, from **one host and one IP**, can take a Sui fullnode out of
service in about 90 seconds by firing two cheap JSON-RPC/WebSocket vectors
concurrently:

1. **Wide-filter subscription memory-pin** — open ~100 WebSocket subscriptions,
   each with an oversized event filter, pinning ~10 MB of resident memory per
   subscription (≈1 GB total) that is **not released on disconnect**, and leaking
   the fullnode's fixed subscription permits so new subscribers are refused; and
2. **`sui_multiGetObjects` egress amplification** — a small batch read whose
   response is ~2,900× the request size, sustaining tens of MB/s of outbound
   traffic for a few MB/s of inbound.

Together these pin memory, exhaust the subscription permit pool, and saturate
egress. Legitimate subscribers are refused **during and after** the attack, and
**the fullnode must be restarted** to recover. It is an availability issue only —
no memory corruption, no funds or consensus impact.

The component primitives are individually known; this advisory's contribution is
the **composition**, its **single-host / single-IP repeatability**, and its
**persistence after the attacker disconnects**.

## Findings at a glance

| Item | Detail |
|---|---|
| Class | Composed availability attack — subscription memory-pin + permit leak (`connection_exhaustion`) + response amplification (`response_amp`) |
| Reachability | Remote, unauthenticated, single host, single IP, on the public JSON-RPC/WebSocket surface |
| Trigger | ~100 `suix_subscribeEvent` with an oversized `Any([...])` filter, concurrent with `sui_multiGetObjects` batch reads on framework packages (`showBcs`/`showContent`) |
| Impact | ≈1 GB RSS pinned (persists post-disconnect), 100/100 subscription permits leaked, sustained high egress; legitimate subscribers refused during and after; restart required |
| Severity | High for fullnode availability (single-host remote takedown, persistent) |
| Mitigation | Cap event-filter vector length; release subscription permits + streamer state on disconnect; bound `multiGetObjects` response size / batch. See Mitigation |

## Mechanism (source-cited, sui monorepo)

**Vector 1 — wide-filter subscription memory-pin + permit leak** (also publishable
standalone; see NR-2026-005):
- Sui's `EventFilter` is a flat `Any(Vec<EventFilter>)` with **no cap on the vec
  length** (`crates/sui-json-rpc-types/src/sui_event.rs`). An attacker-supplied
  `Any([...])` with ~100,000 elements is accepted; each such subscription pins
  ~9–10 MB of persistent RSS in the streamer-map `BTreeMap`.
- The subscription permit is **not released** when the subscription closes
  (`crates/sui-json-rpc/src/indexer_api.rs`), and the streamer map orphans entries
  (`crates/sui-core/src/streamer.rs`). The permit pool is fixed
  (`DEFAULT_MAX_SUBSCRIPTIONS = 100`), so ~100 subscribe/close cycles exhaust it;
  new subscribers then get `-32603 Internal error` until restart.

**Vector 2 — `sui_multiGetObjects` egress amplification:**
- A small `sui_multiGetObjects` batch on framework packages with
  `showBcs=true, showContent=true` returns a response roughly 2,900× the request
  size, so a few MB/s of inbound drives tens of MB/s of outbound — a bandwidth /
  serialization amplifier with no per-response size cap.

**Composition:** fired concurrently from one host, Vector 1 pins memory and burns
the permit pool while Vector 2 saturates egress, so the node is simultaneously
memory-pinned, unsubscribable, and bandwidth-starved — and stays unsubscribable
after the attacker leaves.

## Measurement

Measured across independent runs on a **self-owned lab fullnode** and reproduced
**cross-network on a cloud VM we controlled** (4 vCPU / 16 GB): ≈100 wide-filter
subscribes drove +924 MB RSS locally / +1.04 GB on the cloud VM (persistent),
100/100 permits leaked (restart required), and `sui_multiGetObjects` sustained
~2,900× egress amplification. Legitimate-subscriber denial was confirmed both
mid-attack and post-disconnect on every run. No third-party or mainnet
infrastructure was targeted.

## Mitigation

- **Cap the event-filter vector length** (reject oversized `Any([...])` /
  `All([...])` filters) so a single subscribe cannot pin large memory.
- **Release the subscription permit and streamer-map entry on disconnect**, so the
  fixed permit pool is not leaked.
- **Bound `multiGetObjects`** response size / batch count (or rate-limit by
  response bytes) so a small request cannot force a huge response.

An edge rate-limiter alone does not fix it: the memory pin and permit leak persist
after the connection closes.

## Vendor channel and scope

Reported to MystenLabs via direct security contact (email), **not** through a
bug-bounty program — so no program terms or non-disclosure agreement bind this
disclosure. Sui's paid scope is impact-driven with a fund-loss ceiling (a
crash-only availability bug is capped low; DoS is out of scope on the product
programs), so node-availability findings like this are **out of scope for a paid
bounty** and are published as an **operator advisory** to give operators the
mitigations now.

## Scope

This advisory targets fullnode **availability** only. No reproducer code targeting
live infrastructure is shipped, and this is **not a turnkey** attack tool — it
describes the mechanism and mitigations for operators; measurement was against
self-owned nodes.

## Provenance

NullRabbit original research (our own measurement). Cross-references: NullRabbit
finding id `SUI_LAYERED_S1_F10_DOS` (composition of `SUI_SUBSCRIPTION_PERMIT_LEAK`
+ the `sui_multiGetObjects` amplifier); detection primitive
`sui_f10_multiget_response_amp` (family `response_amp`). Companion advisory:
NR-2026-005 (the standalone subscription permit-leak).

## Contact

Simon Morley, NullRabbit — `simon@nullrabbit.ai`.
