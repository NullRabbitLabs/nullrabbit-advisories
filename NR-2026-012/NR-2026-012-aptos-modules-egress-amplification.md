# NR-2026-012 — Aptos fullnode egress amplification via `/v1/accounts/{addr}/modules`

**NullRabbit Operator Advisory** · Published 2026-07-06

## Summary

A single unauthenticated `GET /v1/accounts/{addr}/modules?limit=200` to an Aptos
fullnode's public REST API returns the **entire set of Move modules** under an
address as a JSON array (each module's bytecode as a hex string). At the framework
address `0x1` that is ~150 modules ≈ **1.6 MB of JSON for a ~50-byte URL** — a
single-request **~11,186× egress amplification**. Cycling the framework addresses
`0x1`/`0x3`/`0x4` defeats trivial server-side response caching.

Measured on a live aptos-node, 32 workers sustained **2.87 Gbps (2.87 Gbps) of
server egress** at 584 req/s — the primitive is **bandwidth-bound**, saturating the
serializer well before any per-IP request-rate limit engages. It is an
availability / bandwidth issue only — no memory corruption, no funds or consensus
impact.

This is the Aptos port of the Sui F10 / IOTA F10 read-amplification class
(NR-2026-004 / NR-2026-010), on a REST-GET endpoint rather than JSON-RPC.

## Findings at a glance

| Item | Detail |
|---|---|
| Class | Response amplification (`response_amp`) — small request, disproportionate egress |
| Reachability | Remote, unauthenticated, single host, public Aptos REST API (typically port 8080) |
| Trigger | `GET /v1/accounts/{addr}/modules?limit=200` at a framework address (`0x1`/`0x3`/`0x4`) |
| Measured | ~50-byte URL → ~1.6 MB response → **~11,186×**; 32 workers → **2.87 Gbps sustained egress**, 584 req/s, bandwidth-bound |
| Impact | A few MB/s of inbound sustains multi-Gbps outbound; the API bandwidth-saturates before per-IP request rate throttles |
| Severity | Medium-to-High for fullnode availability (single-host remote egress saturation) |
| Affected | Aptos fullnode exposing the public REST API (default) |
| Mitigation | Bound the `/modules` (and `/resources`) response by bytes, not just the `limit` count; paginate/stream framework reads; rate-limit by response bytes per source. See Mitigation |

## Mechanism

`GET /v1/accounts/{addr}/modules?limit=200` returns every Move module under the
address, each entry carrying the module's full bytecode hex-encoded plus its ABI.
The `limit` parameter caps the **number** of modules, not the **bytes** — a
framework address returns ~150 modules totalling ~1.6 MB, so a ~50-byte URL yields
a ~1.6 MB response (~11,186× by URL; ~3,000× counting HTTP request headers). The
three framework addresses `0x1` (aptos-framework), `0x3`, `0x4` each hold
non-trivial module sets, so rotating them defeats a naive response cache.

## Measurement (live aptos-node)

| Configuration | Smoke (8 workers × 10 s) | E2E (32 workers × 120 s) |
|---|---|---|
| Total requests | 3,603 | 70,106 |
| Sustained throughput | 358 req/s | **584 req/s** |
| Server egress | 1,767 Mbps | **2,873 Mbps (2.87 Gbps)** |
| Amplification (URL → response) | 11,198× | **11,186×** |
| HTTP 200 success rate | 100 % | 100 % |

Doubling workers 8→32 yielded only 1.6× egress — the serializer is bandwidth-bound,
not request-rate-bound, so per-IP request-rate limits (if any) are reached *after*
the bandwidth is already saturated.

## Reproduction

The corpus reproducer (`chains/aptos/lab/drivers/known_class_aptos_f10.py`, primitive
`aptos_f10_modules_amp`, published in `NullRabbit/nr-bundles-public`) captures the
wire signature over loopback: a tiny `GET /v1/accounts/{addr}/modules?limit=200`
against a mock endpoint returning framework-module-shaped JSON of the measured ~1.6 MB.

## Mitigation

- **Cap the response by bytes.** The `limit` count cap is insufficient when each
  module is tens of KB; enforce a total-byte ceiling on `/modules` and `/resources`.
- **Paginate / stream** large framework reads instead of returning the full set.
- **Rate-limit by outbound bytes per source** at the REST edge, not by request count.

## Disclosure & provenance

Availability-only finding (no funds/consensus impact). DoS/availability on the
public Aptos REST surface is publish-track under NullRabbit's disclosure-scope
policy. NullRabbit measurement; source-trace and measurement in
`chains/aptos/findings/APT_F10`. Corpus primitive `aptos_f10_modules_amp` shipped in
`NullRabbit/nr-bundles-public`.
