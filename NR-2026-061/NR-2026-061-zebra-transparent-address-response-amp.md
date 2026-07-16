# NR-2026-061 — Zcash (Zebra): transparent-address index RPC response amplification (getaddressutxos / getaddresstxids)

**NullRabbit Operator Advisory** · Published 2026-07-15

## Summary

Zebra's transparent address-index RPCs return **all** results for a queried address with no pagination:
`getaddressutxos` returns every UTXO (one JSON entry each) and `getaddresstxids` returns every txid. An
attacker seeds an address they control with N cheap entries (dust UTXOs / N transactions), then each ~116-byte
query returns a response that scales with N — a **response-amplification** DoS payable by an unauthenticated
caller, bounded per query only by `rpc.max_response_body_size` (default 50 MiB) and unbounded across queries.
`getaddressbalance` returns a scalar (≈1×), discriminating the amplifying methods. Availability only, out of
paid scope → publish-track.

## Findings at a glance

| Finding | Primitive | Method | Class | Severity |
|---|---|---|---|---|
| `ZEC_ZEBRA_GETADDRESSUTXOS_AMP` | `zcash_zebra_getaddressutxos_response_amp` | `getaddressutxos` | `response_amp` | MEDIUM |
| `ZEC_ZEBRA_GETADDRESSTXIDS_AMP` | `zcash_zebra_getaddresstxids_response_amp` | `getaddresstxids` | `response_amp` | LOW |

- **Reachability:** any remote client reaching a non-loopback-bound Zebra RPC; no auth.
- **Affected:** Zebra (`ZcashFoundation/zebra`) with the transparent address-index RPCs exposed.

## Affected versions

Observed on a Zebra 4.2.0 Regtest node (zebra-rpc). The behaviour is the documented unpaginated method
semantics, not a version-specific regression.

## Mechanism (source-cited, `ZcashFoundation/zebra`)

`getaddressutxos` (`zebra-rpc` `methods.rs` → `zebra_state::ReadRequest::UtxosByAddresses`) emits one JSON
entry per UTXO (`address/txid/outputIndex/script/satoshis/height`, ~235 B); `getaddresstxids` emits one txid
per transaction. Both build the full list in memory and return it whole, capped only by
`rpc.max_response_body_size` (default 50 MiB). The attacker steers the count by seeding UTXOs / transactions
at a controlled transparent address.

## Measurement (fidelity: lab)

Self-owned Zebra 4.2.0 Regtest, N=1000 coinbase entries at a controlled t-address: `getaddressutxos` →
**~116 B request → ~235 KB response (≈1,902×)**; `getaddresstxids` → **≈541×**; `getaddressbalance` scalar →
≈1× (control). Corpus reproducers `zcash_zebra_getaddressutxos_response_amp` and
`zcash_zebra_getaddresstxids_response_amp` (`response_amp`, `source_class: original`) ship in
`NullRabbit/nr-bundles-public`.

## Scope

Availability / bandwidth-and-memory only; no funds, consensus, or auth break. A loopback-bound RPC (default)
or one behind a response-size-capping gateway is not affected.

## Mitigation

- Paginate / cap result count for the address-index RPCs; lower `rpc.max_response_body_size`; rate-limit per
  source; keep the RPC on loopback or behind an authenticating gateway.

## Vendor channel and scope

Vendor **Zebra (`ZcashFoundation/zebra`)**. Availability-only, config-mitigable → **out of paid scope →
publish-track**.

## Provenance

Our own (`source_class: original`) measurement; no CVE. On-spec + on-HF (`NullRabbit/nr-bundles-public`).

## Contact
research@nullrabbit.ai
