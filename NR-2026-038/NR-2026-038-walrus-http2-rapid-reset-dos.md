# NR-2026-038 — Walrus (walrus-node): `http2_max_pending_accept_reset_streams = u32::MAX` default → HTTP/2 Rapid Reset memory exhaustion

**NullRabbit Operator Advisory** · Published 2026-07-13

## Summary

The Walrus storage-node service ships an HTTP/2 server whose **`http2_max_pending_accept_reset_streams` is
defaulted to `u32::MAX`** (`crates/walrus-service/src/node/config.rs:1800`), plumbed straight into the
`axum-server 0.8` HTTP/2 builder (`server.rs`) and reinforced in the published `node_config_example.yaml`. That
setting **disables the post-CVE-2023-44487 accounting limit** shipped in the Rust `h2` crate. An unauthenticated
attacker opens HTTP/2 streams and immediately cancels each one (`HEADERS` → `RST_STREAM`) in a rapid cycle — the
classic **HTTP/2 Rapid Reset (CVE-2023-44487 class)** — so pending-accept-reset stream state accumulates
**without bound**, pinning memory until OOM, and the server never issues a `GOAWAY` to shed load. This is an
**availability** DoS against a **public-by-default** storage-node REST surface; it is a misconfiguration /
resource-bounding hardening class, **out of paid scope**, handled on NullRabbit's publish-track.

## Findings at a glance

| Finding | Primitive | Endpoint | Class | Severity |
|---|---|---|---|---|
| `WALRUS_W14_HTTP2_RAPID_RESET` (W14) | `walrus_http2_rapid_reset` | walrus storage-node HTTP/2 REST (axum-server 0.8 / h2) | `http2-rapid-reset` + `transport-DoS` | HIGH |

- **Reachability:** any remote host that can reach the storage node's HTTP/2 REST port; no auth, minimal
  bandwidth, single source suffices.
- **Severity:** HIGH — a 4-connection attacker pins ~28 GiB RSS and ~12 cores in ~60 s at ~40 MiB/s (sub-
  volumetric), with no GOAWAY and no reclaim → OOM. **Out of paid scope**, publish-track.
- **Affected:** `walrus-node` (boot-verified on 1.48.1); every storage node running the default config carries
  the same `u32::MAX` value.
- **Mitigation:** set `http2_max_pending_accept_reset_streams` to a bounded value (e.g. `200`) — a one-line
  `walrus-node.yaml` change effective on next restart, no binary upgrade. See Mitigation.

## Mechanism (source-cited, `MystenLabs/walrus`)

- **The disabled limit.** `crates/walrus-service/src/node/config.rs:1800` defaults
  `http2_max_pending_accept_reset_streams = u32::MAX`. The `h2` crate added
  `max_pending_accept_reset_streams` (default 20) specifically to bound the Rapid-Reset accumulation post
  CVE-2023-44487; setting it to `u32::MAX` opts back out.
- **Plumbed into the server.** The value flows into the `axum-server 0.8` `http_builder().http2()` chain, so the
  live server advertises/uses the unbounded limit (runtime dump prints
  `http2_max_pending_accept_reset_streams: 4294967295`).
- **The attack.** Client opens a stream (`HEADERS`) and immediately sends `RST_STREAM` before the server
  finishes accepting it; repeated rapidly, the "pending accept reset" queue grows unbounded → memory pin → OOM;
  the server emits **no `GOAWAY`** to protect itself.

## Measurement (fidelity: explicit)

On a **production-faithful mirror** (same `axum-server 0.8` + `h2 0.4` + `rustls 0.23` crate set as upstream
walrus-service, same `http_builder().http2()` chain), a single attacker host with **4 concurrent TLS
connections, 60 seconds sustained**:

- Victim RSS: 5,960 KiB → **~28 GiB pinned (~4,933×)**
- Victim CPU: **~1,245% (~12.4 cores)**
- Attacker traffic: ~2.34 GiB out (~40 MiB/s — **well below any volumetric threshold**)
- Server `GOAWAY` frames issued: **zero**; memory not reclaimed after disconnect → OOM under sustained attack
- Safe-mode baseline (same mirror, limit left at the `h2` library default of 20) tears the attacker down inside
  ~50 ms with the expected `h2` warning log — no memory growth.

The published corpus reproducer (primitive `walrus_http2_rapid_reset`; family `memory_amp`,
`source_class: original`, shipped in `NullRabbit/nr-bundles-public`) captures the **attack traffic** — rapid
`HEADERS`→`RST_STREAM` cycles across postures, with zero `GOAWAY`. **This advisory stands on the source trace
(`u32::MAX` default disabling the h2 accounting limit) and the mirror measurement — not on the reproducer
traffic alone.**

## Scope

Availability only (unbounded pending-reset accumulation → memory pin → OOM); no consensus-safety break, no
funds, no authentication bypass, no data corruption. A node configured with a bounded
`http2_max_pending_accept_reset_streams` is not affected. The reproducer targets a local self-owned mock,
carries no public IPs or mainnet hostnames, and is not a turnkey mainnet weapon.

## Mitigation

- **Set a bounded limit:** `http2_max_pending_accept_reset_streams: 200` (or the `h2` default of `20`) in
  `walrus-node.yaml` — effective on next restart, no binary upgrade required. Change the compiled default in
  `crates/walrus-service/src/node/config.rs:1800` and `node_config_example.yaml` so operators inherit a safe
  value.
- **Front the HTTP/2 REST port with a rapid-reset-aware, GOAWAY-emitting gateway** where a bounded upstream
  cannot be relied upon.

## Disclosure & provenance

Availability-only, deployment/hardening-mitigable HTTP/2 Rapid Reset on a public-by-default storage-node REST
surface → **out of paid scope → publish-track** under NullRabbit's disclosure-scope policy. This is our own
(`source_class: original`) measurement of the walrus-specific `u32::MAX` default — a **CVE-2023-44487-class**
misconfiguration, not a novel implementation flaw of ours and not an assigned Walrus CVE. The corpus primitive
`walrus_http2_rapid_reset` is **on-spec** (registered in the known-class provenance map) and **on-HF** (shipped
in `NullRabbit/nr-bundles-public`), so this advisory does not outpace its shipped defensive artefact.
