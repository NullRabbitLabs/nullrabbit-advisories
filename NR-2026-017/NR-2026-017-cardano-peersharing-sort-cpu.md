# NR-2026-017 — Cardano PeerSharing: per-request O(N log N) sort, no rate limit → CPU amplification

**NullRabbit Operator Advisory** · Published 2026-07-06

## Summary

Cardano's `ouroboros-network` **PeerSharing** mini-protocol runs an `O(N log N)` sort over the
node's known-peer set on **every** `MsgShareRequest`, with **no idle timeout** on the protocol and
**no per-peer rate limit** on the request. At mainnet peer-set size (~3000 known peers), each request
costs ~170 µs of `sortBy` + `hashWithSalt` CPU. A single post-handshake connection that floods
`MsgShareRequest` sustains ~10–20% of one core; multiple attacker connections scale linearly. It is an
availability issue only — no funds or consensus impact.

## Findings at a glance

| Item | Detail |
|---|---|
| Class | Post-handshake CPU amplification via per-request algorithmic-cost sort (`compute_amp`) |
| Reachability | Remote peer on the standard Cardano node-to-node peer protocol; post-handshake, unauthenticated request rate |
| Trigger | Flood of `MsgShareRequest` on an established PeerSharing mini-protocol channel |
| Measured | ~170 µs CPU per request at ~3000-peer set; single connection ~10–20% of one core; multi-attacker linear |
| Severity | Medium (public reach, cheap per-request cost, no rate limit; bounded per-connection but multiplies) |
| Affected | Cardano relay/staking nodes running `ouroboros-network` with PeerSharing enabled (standard stack) |
| Mitigation | Per-peer rate-limit / cooldown on `MsgShareRequest`; add an idle timeout; cache/bound the peer-sample work. See Mitigation |

## Mechanism (source-cited, `IntersectMBO/ouroboros-network`)

Three compounding gaps on the PeerSharing mini-protocol:

1. **No idle timeout** — `Ouroboros/Network/Protocol/PeerSharing/Codec.hs:160` (the codec keeps the
   channel open with no inactivity bound), so an attacker holds the channel and streams requests.
2. **No per-peer rate limit** on `MsgShareRequest` — verified absent in `PeerSharing.hs` (no
   `rate-limit` / `throttle` / `cooldown` in the handler).
3. **`O(N log N)` sort per request** — `Ouroboros/Network/PeerSharing.hs:203-237` builds the response by
   `sortBy`-ing a `hashWithSalt`-keyed view over the full known-peer set (`psPolicyPeerShareMaxPeers`
   sample). At mainnet peer-set sizes the sort dominates: ~170 µs of CPU per request.

So an established peer that simply sends `MsgShareRequest` as fast as it can pins server CPU
proportional to its request rate × the peer-set size — no authentication beyond being a peer, and no
throttle to stop it.

## Reproduction (fidelity: explicit)

The sort CPU is a server-side effect and the Ouroboros node-to-node handshake + mux framing is
abstracted. The published corpus reproducer
(`chains/cardano/lab/drivers/known_class_cardano_peershare.py`, primitive
`cardano_peershare_sort_cpu` in `NullRabbit/nr-bundles-public`) captures the wire signature — a
post-handshake flood of `MsgShareRequest` CBOR messages (`[0, amount]`) — with
`provenance.wire_fidelity = "peershare_request_flood_representative"` and the measured ~170 µs/req /
~20%-core figures in `attack_parameters`. **This advisory stands on the source trace and the
measurement, not on the reproducer's transport shim.**

## Mitigation

- **Rate-limit `MsgShareRequest` per peer** (token bucket / minimum inter-request interval), so a peer
  cannot convert its request rate into unbounded server CPU.
- **Add an idle timeout** to the PeerSharing mini-protocol so held-open abusive channels are dropped.
- **Bound / cache the peer-sample work** — precompute or amortise the sorted sample rather than
  re-sorting the full known-peer set on every request.

## Disclosure & provenance

Availability-only finding (no funds/consensus impact). DoS/availability on the public Cardano
peer-protocol surface is publish-track under NullRabbit's disclosure-scope policy. Vendor: IntersectMBO
(`ouroboros-network`). NullRabbit measurement; source-trace and numbers in
`chains/cardano/findings/H_CARDANO_4_PEERSHARING`. Corpus primitive `cardano_peershare_sort_cpu` shipped
in `NullRabbit/nr-bundles-public`.
