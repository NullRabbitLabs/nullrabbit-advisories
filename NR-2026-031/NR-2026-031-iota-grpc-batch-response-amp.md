# NR-2026-031 — IOTA (iota-node gRPC): `GetObjects` / `GetTransactions` uncapped batch → response-amplification DoS

**NullRabbit Operator Advisory** · Published 2026-07-09

## Summary

The IOTA node's gRPC `LedgerService` methods `GetObjects` and `GetTransactions` accept a **batch of object
IDs / transaction digests with no per-batch count cap** — batching is bounded only by a response **byte**
ceiling (`default_grpc_api_max_message_size_bytes`, default 4 MB base, up to ~128 MB per message), not by the
**number** of requested elements — and the server performs **no digest deduplication**. An **unauthenticated**
caller therefore sends a small batched request whose elements each pull a full BCS body back, producing a
large **egress amplification** on a single TCP flow: a 200 KB `GetObjects` call over the framework packages
returned **264.51 MB (1,322×)**, and — because repeated digests are not deduplicated — a `GetTransactions`
call replaying one "fat" digest (the ~193 KB Genesis transaction) 5,000 times returned **966.64 MB
(5,085×)**. This is a **response-amplification / bandwidth-exhaustion** DoS against an **exposed** gRPC
surface. It is an **availability issue only** — no funds, no consensus break, no auth bypass — and falls
**out of paid scope** (a batching/rate-limit/deployment concern), so it is handled on NullRabbit's
publish-track.

## Findings at a glance

| Finding | Primitive | Endpoint | Class | Severity |
|---|---|---|---|---|
| `IOTA_F10_GRPC_BATCH` | `iota_f10_grpc_batch_amp` | `LedgerService/GetObjects` + `/GetTransactions` (gRPC) | `byte-amplification` | MEDIUM-HIGH |

- **Reachability:** any remote client that can reach a non-loopback-bound gRPC port (`:50051`); no auth, no
  handshake. The loopback default is not remotely reachable.
- **Severity:** availability-only response-amplification DoS; **out of paid scope**, publish-track.
- **Affected:** `iota-node` exposing the gRPC `LedgerService` on a routable interface with no external batch /
  rate limit (measured on iota-node 1.23.2).
- **Mitigation:** cap the per-request element **count** (not just response bytes), dedup repeated digests, and
  rate-limit / gateway the gRPC endpoint. See Mitigation.

## Mechanism (source-cited, IOTA `iota-node`)

`iota-grpc-server/src/ledger_service/{get_objects,get_transactions}.rs` iterate the request's
`Vec<*Request>` with **no length validation**; the only backpressure is the response byte size cap
(`default_grpc_api_max_message_size_bytes` in `iota-config/src/node.rs`), so a caller can request an arbitrary
**number** of elements as long as the *serialised response* fits the (generous, up to ~128 MB) message limit.
Each requested element is served as its full BCS body, and the server does **not** deduplicate repeated
digests — so N copies of one digest return N copies of that transaction's body.

Two amplification levers, both measured:

- **`GetObjects`** over the framework packages (`0x1`/`0x2`/`0x3` rotated) at N = 5,000 IDs:
  **200 KB request → 264.51 MB response = 1,322× per-byte egress** (cross-network, 2026-05-27).
- **`GetTransactions`** replaying the Genesis-transaction digest (its BCS is ~193 KB, the largest tx on a
  fresh-genesis chain) at N = 5,000 replicas: **190 KB request → 966.64 MB response = 5,085×** (2026-05-28).
  Because there is no dedup, **any** single fat digest (a large package-publish tx, a large parameter-update
  tx) can be replayed in arbitrary batch size for the same effect — the attacker does not need framework
  objects.

The server reports sub-second completion; the client-observed wall time is network transit of the amplified
response. The class is generic response-amplification, with uncapped batch count × un-deduplicated fat bodies
as the multiplier.

## Measurement (fidelity: explicit)

The published corpus reproducer (primitive `iota_f10_grpc_batch_amp`; family `response_amp`,
`source_class: original`, shipped in `NullRabbit/nr-bundles-public`) captures the **attack traffic** — the
small batched gRPC request and the amplified multi-megabyte response on one HTTP/2 flow — across postures
N = 1 / 25 / 50 / 100, reproducing the faithful ~1,500–5,000× wire ratio at capture-sane sizes. The full
966 MB / 5,085× ceiling at N = 5,000 (and the 264 MB / 1,322× `GetObjects` figure) are the **measured**
numbers recorded in the bundle provenance; the reproducer transfers a representative slice rather than a full
1 GB response. **This advisory stands on the source trace (uncapped batch count + no dedup) and the
cross-network + localnet measurements — not on the capped lab-transfer size.**

## Scope

Availability / bandwidth-and-egress exhaustion only; no consensus-safety, no funds, no authentication break,
no chain halt. The harm is degradation of an **exposed** gRPC endpoint under amplified pull; a loopback-bound
gRPC port (the default) is not remotely reachable, and a node behind a gateway that caps request element
count and rate-limits per source is not affected. The reproducer targets a local self-owned mock sized to the
measured ratios, carries no public IPs or mainnet hostnames, and is not a turnkey mainnet weapon.

## Mitigation

- **Cap the per-request element count** on `GetObjects` / `GetTransactions` (a hard `max_batch_size`), not
  only the response byte size — a byte-only cap still permits ~128 MB single-call responses.
- **Deduplicate repeated digests / IDs** within a batch so N copies of one fat body cannot be pulled N times.
- **Rate-limit the gRPC endpoint per source** and cap concurrent in-flight requests at a gateway; the node
  does not do this itself.
- **Do not expose the gRPC `LedgerService` unauthenticated on a routable interface.** Keep it on loopback or
  behind an authenticating, rate-limiting gateway.

## Disclosure & provenance

Availability-only, deployment/rate-limit-mitigable response-amplification on the public gRPC surface →
**out of paid scope → publish-track** under NullRabbit's disclosure-scope policy. Vendor: **IOTA Foundation
(`iota-node`)**; this is our own (`source_class: original`) measurement of the documented absence of a
per-batch count cap and digest dedup, not a novel implementation flaw or an assigned CVE. The corpus primitive
`iota_f10_grpc_batch_amp` is **on-spec** (registered in the known-class provenance map) and **on-HF** (shipped
in the public dataset `NullRabbit/nr-bundles-public`), so this advisory does not outpace its shipped defensive
artefact.
