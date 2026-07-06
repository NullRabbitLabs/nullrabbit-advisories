# NR-2026-006 — IOTA node OOM/CPU wedge via deep event-filter + reconnect-runaway subscription leak

**NullRabbit Operator Advisory** · Published 2026-07-03

> **Why we publish publicly:** these are out-of-scope-for-bounty, no-embargo node-availability findings — analysis + reproducer only. See [Why we publish these findings publicly](../WHY-WE-PUBLISH.md).

## Summary

An IOTA node's WebSocket event-subscription API can be driven to a CPU stall and then an out-of-memory
kill by a single unauthenticated client, two ways that compound:

1. **Deep filter → per-event CPU blow-up.** `iotax_subscribeEvent` accepts an arbitrarily nested
   `Or([...])` / `And([...])` event filter. A deeply nested filter makes the server evaluate a large
   predicate tree **for every event**, so a trivial subscribe commits the node to disproportionate CPU
   on each notification (measured ~15 s of CPU per event at depth ~17).

2. **Reconnect-runaway memory pin.** Subscriptions whose filter matches nothing are **orphaned** in the
   event streamer instead of being cleaned up, so each subscribe pins server memory that is never
   released. Because the node correctly releases the subscription *permit* on disconnect, an attacker can
   **reconnect and repeat** — memory growth is bounded only by attacker time, not by any permit cap.
   Measured ~1.4 GB pinned per reconnect round; **~11 rounds (~2.5 minutes) OOM-kills a 16 GB validator.**

Legitimate subscribers can still subscribe between rounds, so an operator watching "subscribe success"
sees nothing wrong until the node dies. Availability only — no memory corruption, no funds/consensus impact.

## Findings at a glance

| Item | Detail |
|---|---|
| Class | Subscription-filter per-event CPU amplification (`subscription_cpu_amp`) + orphaned-subscription memory leak |
| Reachability | Remote, unauthenticated, single client, on the public WebSocket JSON-RPC subscription surface |
| Trigger | `iotax_subscribeEvent` with a deeply nested `Or([...])` filter; and/or repeated reconnect batches of wide non-matching-filter subscriptions |
| Impact | ~15 s CPU per event at depth ~17; ~1.4 GB pinned per reconnect round → OOM-kill of a 16 GB validator in ~2.5 min. Restart required |
| Severity | Critical for node availability (single unauthenticated client → deterministic OOM); not RCE |
| Mitigation | Cap event-filter nesting depth/breadth; clean up (don't orphan) subscriptions whose filter matches nothing; bound per-connection streamer memory |

## Mechanism (source-cited)

- **Per-event predicate cost:** the event filter is an unbounded recursive `Or`/`And` tree; the server
  evaluates the whole tree per event with no depth cap, so per-event CPU scales with the attacker-chosen
  filter depth.
- **Orphan leak:** in the event streamer, a subscription whose filter matches nothing hits a `continue`
  that skips the send path, and the associated cleanup is never reached — the subscription's state stays
  pinned in the streamer map (`iota-core/src/streamer.rs`, the `continue`-before-`try_send` path). A
  direct gauge confirmed the active-subscriber count climbing and holding across connection close.
- **No permit ceiling on the leak:** the subscription permit *is* released on disconnect (correct), which
  removes the natural cap — so reconnecting and re-subscribing adds another batch of pinned state each
  round, growing memory without bound. (The sibling Sui code path caps this via a permit leak; IOTA does
  not, so IOTA is the more severe of the two.)

## Measurement

Measured against a **self-owned IOTA lab fullnode** (localnet): baseline ~137 MB → ~8.4 GB after 6
reconnect rounds (~1.4 GB/round, ~13 s/round), projecting to OOM on a 16 GB host in ~11 rounds / ~2.5 min;
and ~15 s CPU per event at filter depth ~17. No third-party or mainnet infrastructure was targeted.

## Mitigation

- **Cap event-filter nesting** (reject `Or`/`And` trees beyond a small depth/breadth) so a subscribe can't
  commit the server to large per-event work.
- **Clean up non-matching subscriptions** — on the `continue` path, still release/track the subscription so
  it isn't orphaned in the streamer map.
- **Bound per-connection streamer memory** and/or rate-limit subscribe reconnect churn.

## Vendor channel and scope

IOTA's security contact is `security@iota.org`; IOTA does **not** run a public paid bug-bounty program.
Node availability / DoS is not a paid-impact category, so this is **out of scope for a bounty** and is
published as an **operator advisory** so operators can apply the mitigations now. It rests on our own
measurement against a self-owned lab node; no vendor program terms bind its disclosure.

## Scope

Targets node **availability** only. No reproducer code targeting live infrastructure is shipped and this
is **not a turnkey** attack tool; measurement was against self-owned nodes.

## Provenance

NullRabbit original research (our own measurement). Cross-references: NullRabbit finding id
`IOTA_S1_EVENTFILTER_EXPONENTIAL`; detection primitive `iota_s1_widefilter_subscribe_cpu`
(family `subscription_cpu_amp`).

## Contact

Simon Morley, NullRabbit — `simon@nullrabbit.ai`.
