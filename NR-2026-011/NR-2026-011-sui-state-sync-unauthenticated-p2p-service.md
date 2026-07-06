# NR-2026-011 — Sui `state_sync` p2p service: no authorization layer, rate limits default off

**NullRabbit Operator Advisory** · Published 2026-07-06

## Summary

Sui's anemo **`state_sync`** p2p service exposes its RPC methods (including
`push_checkpoint_summary`) to **any peer with no `RequireAuthorizationLayer`**, and
**all of its per-method rate limits default to "no limit."** The security pattern
exists and is used right next door — the `randomness` service, merged into the
**same** p2p router, gates on `allowed_peers` and applies size caps — but
`state_sync` does not apply it. Any unauthenticated peer can therefore stream
requests to `state_sync` at an unbounded rate.

This is a **hardening / missing-authorization** finding (CWE-306 Missing
Authentication for a Critical Function; CWE-693 Protection-Mechanism Failure),
source-verified against `sui 1.70.1`. Severity is **Medium-to-High depending on
deployment** — it affects any operator running stock Sui with the default p2p
config. It is an availability / hardening issue; no funds or consensus-safety
impact is claimed.

## Findings at a glance

| Item | Detail |
|---|---|
| Class | Missing authorization + absent rate limits on a p2p service (`gossip_abuse`; CWE-306 / CWE-693) |
| Reachability | Remote peer on the anemo p2p network; no authentication required to reach the `state_sync` RPCs |
| Trigger | Unauthenticated requests (e.g. `push_checkpoint_summary`) to the `state_sync` service at attacker-chosen rate |
| Impact | The service admits + processes unauthenticated peer traffic with no per-method rate limit — an unmetered inbound surface on every stock fullnode/validator |
| Severity | Medium-to-High (deployment-dependent; stock default config affected) |
| Affected | `github.com/MystenLabs/sui`, tested `sui 1.70.1` @ `a7e7b45a4ceeee819b07820e31ce6094cd0757d1` |
| Mitigation | Apply `RequireAuthorizationLayer(allowed_peers)` to the `state_sync` router (as `randomness` does) and set non-infinite per-method rate limits. See Mitigation |

## Mechanism (source-cited, sui monorepo)

Both services are built into the **same merged anemo p2p router**, so the contrast
is in the same file tree:

**`randomness/builder.rs:74–77`** — gated:
```rust
let allowed_peers = AllowedPeersUpdatable::new(Arc::new(HashSet::new()));
let router = anemo::Router::new()
    .route_layer(RequireAuthorizationLayer::new(allowed_peers.clone()))
    .add_rpc_service(randomness_server);
```

**`state_sync/builder.rs:128–133`** — **not** gated (only a size limit):
```rust
let router = anemo::Router::new()
    // Size limit layer applied before deserialization.
    .route_layer(SizeLimitLayer::new(
        state_sync_config.max_checkpoint_summary_size(),
    ))
    .add_rpc_service(state_sync_server);
```

`state_sync` has a `SizeLimitLayer` but **no `RequireAuthorizationLayer`**, so it
admits any peer; and its per-method rate limits default to unlimited. The
`randomness` service in the same router demonstrates the intended hardening the
`state_sync` router omits.

## Reproduction (fidelity: explicit)

The canonical attack is a QUIC/anemo `push_checkpoint_summary` flood driven by a
native anemo client. The published corpus reproducer (primitive
`sui_h02_state_sync_flood` in `NullRabbit/nr-bundles-public`) is a **TCP-flood
proxy** for that anemo flood — an unauthenticated rapid open → write (1 KB
stand-in message) → close flood against the no-authorization service — and every
bundle is stamped `provenance.wire_fidelity = "tcp_flood_proxy_for_anemo"` so the
gap is explicit in the training data. **This advisory stands on the source trace
above, not on the proxy's traffic volume.** A native anemo client is the
full-fidelity upgrade path (see `chains/sui/findings/H02`).

## Mitigation

- **Add authorization.** Wrap the `state_sync` router in
  `RequireAuthorizationLayer(allowed_peers)`, exactly as `randomness/builder.rs`
  does, so only allowed peers reach the service.
- **Set finite rate limits** on all `state_sync` RPC methods rather than leaving
  them at the unlimited default.
- Operators can reduce exposure by firewalling the anemo p2p port to known peers
  where the deployment permits.

## Disclosure & provenance

Hardening / availability finding (no funds or consensus-safety impact claimed),
source-verified against `sui 1.70.1`. Vendor: MystenLabs. DoS/availability +
missing-authorization hardening on the p2p surface is treated as publish-track
under NullRabbit's disclosure-scope policy. Full source trace and measurement in
the finding record `chains/sui/findings/H02`.
