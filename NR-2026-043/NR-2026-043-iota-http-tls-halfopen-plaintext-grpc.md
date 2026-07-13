# NR-2026-043 — IOTA (iota-node): three composed transport defects — no `tls_handshake_timeout` + no `max_pending_connections` + hardcoded `.allow_insecure(true)` → half-open-TLS connection-slot exhaustion + plaintext gRPC accept

**NullRabbit Operator Advisory** · Published 2026-07-13

## Summary

The IOTA validator binary ships **three composed transport-layer defects** that together let an
unauthenticated remote attacker exhaust a validator's connection-accept path and talk to its gRPC service
in the clear. (a) `iota-http` has **no `tls_handshake_timeout`** — the accept loop
(`crates/iota-http/src/lib.rs:281-313`) awaits `tls_acceptor.accept(io)` with no deadline, so a client that
sends a TLS `ClientHello` and then stalls pins a connection slot indefinitely (slowloris-style half-open
handshake). (b) `iota-http` has **no `max_pending_connections`** — each accepted connection is
`tokio::spawn`ed into an unbounded `JoinSet` with no concurrency cap, so half-open holds accumulate
**without bound**, one file descriptor + allocation each. (c) `crates/iota-network-stack/src/server.rs:76`
**hardcodes `.allow_insecure(true)`**, so the validator gRPC service accepts **plaintext** HTTP/2 — a
transport-confidentiality / downgrade gap that also removes the TLS handshake as a barrier to reaching the
gRPC surface. Sui closed all three in PR #26069; the IOTA fork still carries them. This is an **availability**
DoS (connection-slot / FD exhaustion) plus a **transport-hardening** gap; no consensus break, no funds, no
signed-operation forgery. It is a resource-bounding / hardening class, **out of paid scope**, handled on
NullRabbit's publish-track.

## Findings at a glance

| Finding | Primitive | Surface | Class | Severity |
|---|---|---|---|---|
| `IOTA_HTTP_TLS_AND_PLAINTEXT_GRPC` | `iota_http_tls_halfopen_plaintext_grpc` | IOTA validator `iota-http` TLS accept path + `iota-network-stack` gRPC server | `half-open-TLS-exhaustion` + `plaintext-gRPC-accept` (composed) | MEDIUM |

- **Reachability:** any remote host that can reach the validator's TLS-fronted `iota-http` port and/or its
  gRPC port; **no auth**, minimal bandwidth, single source suffices. The half-open TLS hold costs the attacker
  almost nothing (a `ClientHello` then silence); the plaintext gRPC accept needs a single unencrypted request.
- **Severity:** **MEDIUM** — each sub-defect is independently MEDIUM. The half-open-TLS memory/FD pin is real
  and measured but bounded by the OS FD ulimit; the plaintext gRPC accept is a high-shock auth-boundary
  observation whose exploit value is bounded (no direct state forgery — see Scope). **Out of paid scope**,
  publish-track.
- **Affected:** every IOTA validator binary built from `iotaledger/iota` HEAD as of 2026-05-25 (no
  `tls_handshake_timeout` / `max_pending_connections` in `iota-http`; `.allow_insecure(true)` hardcoded in
  `iota-network-stack`). Boot-verified on `iota-node 1.23.2`.
- **Mitigation:** add a bounded `tls_handshake_timeout` (e.g. `5s`) and `max_pending_connections` (e.g. `4096`)
  to `iota-http` and enforce them in the accept loop; remove the hardcoded `.allow_insecure(true)` (require
  mTLS) or gate it behind an explicit opt-in — the three-line port of Sui #26069. See Mitigation.

## Mechanism (source-cited, `iotaledger/iota` HEAD @ 2026-05-25)

- **Defect (a) — no TLS handshake timeout.** `crates/iota-http/src/config.rs` defines the server `Config`
  with **no `tls_handshake_timeout` field**. The accept loop at `crates/iota-http/src/lib.rs:281-313` calls
  `tls_acceptor.accept(io).await` **with no deadline and no `tokio::time::timeout` wrapper**. A client that
  opens TCP and sends only the TLS `ClientHello`, then never continues, holds that connection — and its FD +
  allocation — until it disconnects. Sui post-#26069 has `tls_handshake_timeout: Some(Duration::from_secs(5))`
  in `sui-http/src/config.rs` and wraps the accept in `tokio::time::timeout(...)` at `sui-http/src/lib.rs:293`.
- **Defect (b) — no `max_pending_connections`.** Same `iota-http/src/config.rs` — **no field**; the accept
  loop `tokio::spawn`s each connection into an **unbounded `JoinSet` with no concurrency cap**. Combined with
  (a)'s missing timeout, N half-open handshakes pin **N FDs + N allocations indefinitely**. Sui post-#26069
  bounds this with `max_pending_connections: Some(4096)` (`sui-http/src/config.rs`, enforced at
  `sui-http/src/lib.rs:302`).
- **Defect (c) — hardcoded `.allow_insecure(true)`.** `crates/iota-network-stack/src/server.rs:76` builds the
  validator gRPC `ServerBuilder` with `.allow_insecure(true)` **hardcoded**, so a client with **no TLS and no
  client cert** can hit the validator gRPC port and get a valid gRPC HTTP/2 response — the entire
  transport-encryption layer is bypassable/downgradeable. Sui removed this in #26069 (`sui-network-stack`
  requires mTLS for all operations).
- **Composed effect.** (a)+(b) give an unauthenticated attacker an unbounded, near-free way to pin connection
  slots (half-open TLS accumulation → FD/memory pin), and (c) means the gRPC surface is reachable in the clear
  with no handshake barrier — plaintext floods add to the accept-path pressure and expose the service to
  trivial probing/profiling.

## Measurement (fidelity: explicit)

**Live-measured** on an **IOTA 4-validator fresh-genesis localnet** (`iota-node 1.23.2`), single attacker
host. All three sub-defects confirmed live.

- **Half-open TLS (defects a+b), slowloris probe** — opens N TCP connections, sends only the TLS `ClientHello`,
  holds for the stated duration:
  - **2,000 conns / 60 s hold:** `ok=2000 err=0` — validator accepted every half-open hold with no error;
    validator RSS peak **2.59 GB**.
  - **5,000 conns / 60 s hold:** `ok=5000 err=0`; validator RSS peak **2.66 GB**; **validator FD count
    7,307 (baseline) → 12,309 peak (+5,002 FDs) sustained for the 60 s hold window** — a 1:1 match with
    attacker connection count (`fdcounter.log` captured).
  - **10,000 conns / 60 s hold:** **all 10,000 accepted, no error** — the validator did not reject a single
    connection at the OS, kernel, or application layer.
- **Plaintext gRPC (defect c):** `curl -v http://127.0.0.1:34141/health` → **`HTTP/1.1 200 OK`,
  `content-type: application/grpc`** — no TLS handshake, no client cert. Independently **confirmed
  cross-network** on a remote lab validator: `curl --http2-prior-knowledge http://<validator>:50051/` →
  **`HTTP/2 200`, `content-type: application/grpc`** (`grpc-status: 12` UNIMPLEMENTED for the placeholder
  path — the server is alive and framing gRPC over a plaintext connection).

**Honest bounds — what the measurement does *not* certify.** The lab box's FD ulimit was high enough to absorb
10k+ FDs, so **FD-table saturation was not itself triggered**. At a default `ulimit -n 1024`, the measured
linear FD growth (≈1 FD per attacker connection) predicts saturation at **~1,000 attacker connections**,
blocking legitimate peer accepts — this is a **predicted** consequence of the measured growth, **not separately
certified**. No signed-operation forgery was demonstrated over the plaintext channel (see Scope), and
legitimate-peer latency degradation during the flood was not directly measured. Note also a **defended adjacent
surface**, reported for honesty: an h2c HTTP/2 rapid-reset (`HEADERS`+`RST_STREAM`) flood against the JSON-RPC
port was **defended** — `iota-http` leaves `http2_max_pending_accept_reset_streams: None`, inheriting hyper's
post-CVE-2023-44487 default, which issued `GOAWAY` at ~1,450 RST/conn. That rapid-reset vector is **not** part
of this finding; the three defects above stand on the source trace and the localnet + cross-network
measurements.

The published corpus reproducer (primitive `iota_http_tls_halfopen_plaintext_grpc`; `source_class: original`,
shipped in `NullRabbit/nr-bundles-public`) captures the **attack traffic** — half-open TLS holds and the
plaintext gRPC accept — against a self-owned localnet. **This advisory stands on the source trace (the two
absent `iota-http` bounds + the hardcoded `.allow_insecure(true)`) and the localnet/cross-network measurement,
not on the reproducer traffic alone.**

## Scope

Availability + transport-hardening only: unbounded half-open-TLS accumulation → connection-slot / FD /
memory pin (bounded by the OS FD ulimit), plus a plaintext-gRPC transport-confidentiality gap. **No
consensus-safety break, no funds, no authentication *bypass into state*.** The validator gRPC `ValidatorService`
still rejects unsigned / invalid-signature operations at the application layer, so the plaintext channel enables
**probing, profiling, and amplification of other surfaces** — not direct transaction forgery. A validator built
with a bounded `tls_handshake_timeout` + `max_pending_connections` and mTLS-only gRPC is not affected. The
reproducer targets a local self-owned validator localnet, carries no mainnet hostnames, and is not a turnkey
mainnet weapon.

## Mitigation

- **Port Sui #26069's three changes into the IOTA fork:**
  - Add to `crates/iota-http/src/config.rs`:
    ```rust
    pub tls_handshake_timeout: Option<Duration>,  // default: Some(Duration::from_secs(5))
    pub max_pending_connections: Option<usize>,   // default: Some(4096)
    ```
    and enforce them in `crates/iota-http/src/lib.rs:281-313` — wrap `tls_acceptor.accept(io)` in
    `tokio::time::timeout(config.tls_handshake_timeout, ...)` and bound the pending-handshake `JoinSet` by
    `config.max_pending_connections`.
  - Remove `.allow_insecure(true)` at `crates/iota-network-stack/src/server.rs:76` so validator gRPC requires
    mTLS for **all** operations — or, if a plaintext path is genuinely needed, gate it behind an explicit,
    documented opt-in that defaults **off** rather than hardcoding it on.
- **Operationally, until the binary is patched:** front the TLS/gRPC ports with a connection-rate-limiting,
  handshake-timeout-enforcing gateway, and set the validator process `ulimit -n` well above expected legitimate
  peer count so a half-open flood is absorbed rather than starving real peers.

## Disclosure & provenance

Availability-plus-hardening (half-open-TLS connection-slot exhaustion + plaintext gRPC accept) on a validator
transport surface, deployment/hardening-mitigable → **out of paid scope → publish-track** under NullRabbit's
disclosure-scope policy. This is our own (`source_class: original`) measurement of the IOTA-specific composed
defect set — three transport bounds/settings that Sui closed in PR #26069 and the IOTA fork still carries; it is
not an assigned IOTA CVE. The corpus primitive `iota_http_tls_halfopen_plaintext_grpc` (finding
`IOTA_HTTP_TLS_AND_PLAINTEXT_GRPC`) is **on-spec** (registered `original` in the known-class provenance map) and
**on-HF** (shipped in `NullRabbit/nr-bundles-public`, `HF_DATASET_PRIMITIVES`), so this advisory does not
outpace its shipped defensive artefact. Vendor: **IOTA Foundation**.
