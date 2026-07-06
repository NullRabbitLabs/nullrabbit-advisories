# NR-2026-005 — Sui fullnode subscription permit leak + streamer-map orphan + wide-filter memory pin

**NullRabbit Operator Advisory** · Published 2026-07-02

## Summary

A Sui fullnode serving the WebSocket JSON-RPC subscription API leaks its
**fixed pool of subscription permits**: each `suix_subscribeEvent` consumes a
permit that is **not returned when the subscription closes**, and the underlying
streamer map orphans the entry. The permit pool is small
(`DEFAULT_MAX_SUBSCRIPTIONS = 100`), so ~100 subscribe/close cycles exhaust it —
after which **every** new subscriber is refused with `-32603 Internal error`,
including legitimate ones, until the fullnode is **restarted**.

Two aggravators:
- **It leaks under benign use, not just attack.** A well-behaved subscriber using
  an empty `All([])` filter also leaks permits during quiet windows — an
  observability sidecar leaked several permits in seconds with no adversarial
  input. Any operator running the WS API is exposed, not only those with hostile
  users.
- **Memory-pin magnification.** Because the event filter is an uncapped vector, an
  attacker-supplied filter with ~100,000 elements pins ~9–10 MB of persistent
  resident memory per subscription on top of the permit leak.

Availability only — no memory corruption, no funds or consensus impact.

## Findings at a glance

| Item | Detail |
|---|---|
| Class | Per-subscription permit / streamer-state leak, not released on disconnect (`connection_exhaustion`) |
| Reachability | Remote, unauthenticated, on the public WebSocket JSON-RPC subscription surface |
| Trigger | ~100 `suix_subscribeEvent` subscribe/close cycles (leak fires even with a benign `All([])` filter; an oversized `Any([...])` filter adds a persistent memory pin) |
| Impact | Subscription permit pool exhausted → new subscribers refused `-32603` during and after; ~10 MB persistent RSS per wide-filter subscribe; restart required |
| Severity | High for fullnode subscription availability; persistent after disconnect |
| Mitigation | Release the permit + streamer-map entry on disconnect; cap the event-filter vector length |

## Mechanism (source-cited, sui monorepo)

1. **Permit not released on close.** A subscription acquires a permit from a fixed
   pool (`DEFAULT_MAX_SUBSCRIPTIONS = 100`), but the permit lifetime is not tied to
   the subscription teardown (`crates/sui-json-rpc/src/indexer_api.rs`) — closing
   the subscription does not return the permit.

2. **Streamer map orphans entries.** The event streamer retains per-subscription
   state that is not cleaned up when the subscriber disconnects
   (`crates/sui-core/src/streamer.rs`), so the leak persists after the connection
   is gone.

3. **Uncapped filter → memory pin.** `EventFilter` is a flat `Any(Vec<EventFilter>)`
   with no length bound (`crates/sui-json-rpc-types/src/sui_event.rs`); a large
   attacker-supplied filter pins ~9–10 MB persistent RSS per subscribe in the
   streamer map, compounding the leak into a memory-exhaustion vector.

## Measurement

Measured on a **self-owned lab fullnode** and reproduced **cross-network on a
cloud VM we controlled**: cap observed at 100 (default), 1:1 permit leak per close,
recovery requires a fullnode restart. The benign-filter leak was observed from a
passive observability subscriber (several permits lost in ~15 s with no adversarial
filter). ~100 wide-filter subscribes pinned ~0.9–1.0 GB persistent RSS. No
third-party or mainnet infrastructure was targeted.

## Mitigation

- **Release the subscription permit and streamer-map entry on disconnect** (tie the
  permit lifetime to subscription teardown) — this is the core fix; it closes both
  the adversarial and the benign leak.
- **Cap the event-filter vector length** so a single subscribe cannot pin large
  memory.
- Operationally, until patched: monitor the active-subscription permit count and
  restart before it saturates; prefer not exposing the WS subscription API to
  untrusted networks.

## Vendor channel and scope

Reported to MystenLabs (and IOTA Foundation, which shares the affected code paths)
via direct security contact (email), **not** through a bug-bounty program — so no
program terms or non-disclosure agreement bind this disclosure. Node-availability
DoS is out of paid scope (Sui's paid impacts are fund-loss-driven; IOTA runs no
paid program), so this is published as an **operator advisory** to give operators
the fix now.

## Scope

This advisory targets fullnode subscription **availability** only. No reproducer
code targeting live infrastructure is shipped and this is **not a turnkey** attack
tool; measurement was against self-owned nodes.

## Provenance

NullRabbit original research (our own measurement). Cross-references: NullRabbit
finding id `SUI_SUBSCRIPTION_PERMIT_LEAK`; detection primitive
`sui_subscription_permit_leak` (family `connection_exhaustion`). Composed into the
layered takedown in NR-2026-004.

## Contact

Simon Morley, NullRabbit — `simon@nullrabbit.ai`.
