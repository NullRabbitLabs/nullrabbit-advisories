# NR-2026-010 — IOTA fullnode egress amplification via `iota_multiGetObjects` full-BCS reads

**NullRabbit Operator Advisory** · Published 2026-07-06

## Summary

A single unauthenticated JSON-RPC request to an IOTA fullnode can pull a
**~20 MB response from a ~487-byte request** — a **~41,600× egress
amplification** — by asking `iota_multiGetObjects` to return the full BCS of the
IOTA framework packages. The attacker sends the 50-ID per-call maximum using the
**abbreviated framework object IDs** (`0x1`, `0x2`, `0x3`) with `showBcs: true`;
the node serialises each framework package's entire bytecode into the response.

This is the IOTA port of the Sui F10 amplification (see NR-2026-004); it is a
**verbatim fork of the same bug**, and because IOTA's framework packages have
accreted more bytecode than Sui's, the per-call amplification is **~27× larger**
than the original Sui measurement. It is an availability / bandwidth issue only —
no memory corruption, no funds or consensus impact.

## Findings at a glance

| Item | Detail |
|---|---|
| Class | Response amplification (`response_amp`) — small request, disproportionate egress |
| Reachability | Remote, unauthenticated, single host, single IP, public JSON-RPC surface |
| Trigger | One `iota_multiGetObjects` at the 50-ID cap with short framework IDs (`0x1`/`0x2`/`0x3`) and `showBcs: true` |
| Measured | 487-byte request → 20,276,856-byte (19.34 MB) response → **41,636× per call** (measured on a live IOTA fullnode) |
| Impact | Sustained tens of MB/s outbound egress for trivial inbound cost; server-side CPU stays low — the bottleneck is downstream bandwidth, not the node's compute |
| Severity | Medium (single-vector egress amplification; composes with other vectors for a fuller availability attack, as in the Sui NR-2026-004 composition) |
| Affected | IOTA node exposing the public JSON-RPC read API with default `iota_multiGetObjects` behaviour |
| Mitigation | Bound the `multiGetObjects` response size (not just the 50-ID count); cap or meter full-BCS (`showBcs`) egress; rate-limit by response bytes, not request count. See Mitigation |

## Mechanism (source-cited)

IOTA inherits the Sui read-API shape verbatim:

- `crates/iota-json-rpc/src/read_api.rs` exposes `iota_multiGetObjects`, which
  calls `get_object(id, options)` per ID and `join_all`s the results — the same
  structure as Sui's `multiGetObjects` read path (`crates/sui-json-rpc/src/read_api.rs`).
- The per-call object-ID hard cap is **50** (`QUERY_MAX_RESULT_LIMIT`), matching
  Sui; a 50-ID request succeeds at the cap.
- `IotaObjectDataOptions { showBcs: true, … }` triggers BCS-byte serialisation of
  each object's data. For a **framework package** (`0x1` MoveStdlib, `0x2`
  IotaFramework, `0x3` IotaSystem — static, always-present addresses), that BCS is
  the package's full module bytecode.

The **amplification lever** is that IOTA accepts **abbreviated** object IDs, so a
50-ID request is only ~487 bytes on the wire, while the framework-package response
is ~20 MB. Per-object single-probe sizes measured on IOTA: `0x1` ≈ 24.5 KB, `0x2`
≈ 128.6 KB, `0x3` ≈ 70.0 KB; the 50-ID full response measured **20,276,856 bytes**.

## Measurement

Measured directly against a live IOTA fullnode:

| | Sui F10 (2026-04-18) | IOTA (this measurement) |
|---|---|---|
| Object IDs per request | 10 | 50 |
| Request body | 932 B | **487 B** |
| Response body | 1,434,403 B | **20,276,856 B (19.34 MB)** |
| Per-call amplification | 1,539× | **41,636× (≈27× worse than Sui F10)** |

Under sustained load (4 parallel workers, tight-looping the 50-ID call), aggregate
egress reached 12.2 MB/s — bounded by the measurement host's residential downstream
and cross-network RTT, not by the node's CPU (which stayed well below saturation).
The **per-call 41,636× ratio** is the canonical signal.

## Reproduction

The corpus reproducer (`chains/iota/lab/drivers/known_class_iota_f10.py`, primitive
`iota_f10_multiget_amp`, published in `NullRabbit/nr-bundles-public`) captures the
wire signature over loopback: a 484-byte `iota_multiGetObjects` request against a
mock JSON-RPC endpoint returning framework-object-shaped BCS blobs sized to the
measured 20 MB aggregate, yielding the 41,915× ratio on the wire.

## Mitigation

- **Bound the response, not just the request.** Cap `multiGetObjects` (and the
  single-object read) total response size; the 50-ID count cap is insufficient when
  each object can be MB-scale.
- **Meter `showBcs` egress.** Full-BCS reads of framework packages are the
  amplification surface; rate-limit or cache them, and account cost by response
  bytes rather than request count.
- **Egress rate-limit per source** at the RPC edge, keyed on outbound bytes.

## Disclosure & provenance

Availability-only finding (no funds/consensus impact). DoS/availability on the IOTA
node RPC surface is treated as publish-track under NullRabbit's disclosure-scope
policy. NullRabbit measurement; source-trace and measurement in the finding record
`chains/iota/findings/IOTA_F10_MULTIGET_AMP`. The corpus primitive
`iota_f10_multiget_amp` is shipped in `NullRabbit/nr-bundles-public`.
