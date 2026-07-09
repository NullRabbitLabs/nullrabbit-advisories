# NR-2026-033 — XRP (rippled): inbound TLS listeners have no handshake timeout or per-IP half-open cap → RSS-pin + FD-exhaustion crash

**NullRabbit Operator Advisory** · Published 2026-07-09

## Summary

`rippled`'s **inbound** TLS listeners — the peer-protocol port (`51235`) and the RPC-over-HTTPS port
(`5006`) — install **no handshake deadline** and **no per-IP half-open connection cap**. (The *outbound* peer
handshake is protected by a 15 s deadline at `ConnectAttempt.cpp:153`; the inbound path is not — the
asymmetry is the root cause.) An unauthenticated attacker opens many TCP connections, sends a 5-byte partial
TLS record header (`16 03 01 02 00` — handshake record, declared length 512) and then **stalls**, never
sending the body. Each half-open pins server-side SSL-stream state that **does not recover on client close**.
Two measured impacts: **(Bug A)** persistent RSS grows linearly with attacker connection count —
**+745 MB from a single source IP holding 10,000 half-opens** on the peer port — trending to OOM under a
sustained rate; **(Bug B)** at the default Linux `ulimit -n = 1024`, ~1,000 half-opens exhaust file
descriptors and trip a buggy `Server::reopenAcceptor` retry loop that fails to release the old acceptor →
uncaught exception → **process abort (SIGSEGV / exit 139) in ~14 s**. This is an **availability**
DoS against **public-by-default** listeners; it is a rate-limit/handshake-hardening class, **out of paid
scope**, handled on NullRabbit's publish-track.

## Findings at a glance

| Finding | Primitive | Endpoint | Class | Severity |
|---|---|---|---|---|
| `RIP_TLS_SLOW_HANDSHAKE` | `rippled_tls_slow_handshake` | inbound TLS: peer `:51235` + RPC-HTTPS `:5006` | `tls-slowloris` + `fd-exhaustion-panic` | HIGH |

- **Reachability:** any remote host that can reach the peer port (`51235`, default-listened) or an exposed
  RPC-HTTPS port; no auth, no completed handshake, single source IP suffices.
- **Severity:** HIGH — single-host RSS pin scales linearly and does not recover (OOM under sustained rate),
  and at default `ulimit` the same attack crashes the process; **out of paid scope**, publish-track.
- **Affected:** `rippled` inbound TLS acceptors (measured on v3.1.3 / `xrpllabsofficial/xrpld:latest`;
  DigitalOcean production-shape run confirmed cross-network).
- **Mitigation:** install an inbound TLS-handshake deadline symmetric with the outbound one, cap concurrent
  half-open handshakes per source IP, raise/normalize the FD ulimit, and fix the acceptor-reopen retry. See
  Mitigation.

## Mechanism (source-cited, `XRPLF/rippled`)

- **Outbound is defended, inbound is not.** `ConnectAttempt.cpp:153` wraps the *outbound* peer
  `async_handshake` in a 15 s `boost::asio::steady_timer` deadline. The *inbound* path (peer port `51235`,
  `OverlayImpl::onHandoff` → `boost::asio::ssl::stream::async_handshake`) installs **no** analogous deadline;
  the RPC-HTTPS listener (`5006`, `protocol = https`) likewise has **no** handshake deadline and **no** per-IP
  half-open cap.
- **The only documented defence gates rate, not count.** The per-IP `Resource::Consumer`
  (`OverlayImpl.cpp:235`) throttles admission *rate*, not the *number* of concurrent half-open handshakes —
  measurement confirms N = 10,000 half-opens from a single IP complete admission in ~1 s without throttling.
- **State pins and does not recover.** Each partial handshake allocates SSL-stream state (peer-protocol
  sessions additionally pre-allocate Squelch/Compression/Manifest/send-queue buffers), which survives client
  TCP close, server-side TLS cleanup, and socket release — post-close RSS samples stay within ±60 KB of the
  held samples.
- **Bug B — acceptor-reopen crash.** When accept fails on `EMFILE` (FD exhaustion at low ulimit),
  `Server::reopenAcceptor` retries in a loop that does not release the prior acceptor → `bind: address
  already in use` → uncaught `std::exception` → process abort.

## Measurement (fidelity: explicit)

Clean idle baseline 117 MB. Single source IP, ulimit 65536:

| Port | N half-opens | Δ persistent RSS | Δ / conn |
|---|---|---|---|
| 51235 (peer) | 1,000 | +97 MB | 97 KB |
| 51235 (peer) | 5,000 | +444 MB | 89 KB |
| 51235 (peer) | 10,000 | **+745 MB** | 75 KB |
| 5006 (rpc-https) | 10,000 | +342 MB | 34 KB |

Cumulative +1.85 GB committed from one source IP across a 6-burst series (32,000 half-opens held). RSS does
not recover post-close. **Bug B:** at default `ulimit -n = 1024`, N = 1,000 half-opens crash rippled
(SIGSEGV / exit 139) in ~14 s. A DigitalOcean production-shape run (lon1 target, sfo3 attacker, ~140 ms RTT,
stock Ubuntu 24.04) reproduced Bug A within 5–15 % of the loopback per-connection cost (+712 MB at peer
N = 10k) and fired Bug B in the same wall-second at stock ulimit.

The published corpus reproducer (primitive `rippled_tls_slow_handshake`; family `connection_exhaustion`,
`source_class: original`, shipped in `NullRabbit/nr-bundles-public`) captures the **attack traffic** — many
short TCP flows each sending the 5-byte partial ClientHello then idling half-open, across postures
(single-IP low-volume/saturating, multi-source distributed, and a paced RPC-HTTPS mimicry variant). **This
advisory stands on the source trace (inbound handshake has no deadline / no half-open cap) and the
loopback + DigitalOcean production-shape measurements — not on the reproducer traffic alone.**

## Scope

Availability only (memory pin → OOM, and FD-exhaustion → process crash); no consensus-safety break, no funds,
no authentication bypass. The harm is degradation/crash of **public-by-default** inbound TLS listeners; a node
whose inbound handshake is deadline-bounded and half-open-capped per source, at a normal FD ulimit, is not
affected. The reproducer targets a local self-owned mock, carries no public IPs or mainnet hostnames, and is
not a turnkey mainnet weapon.

## Mitigation

- **Install an inbound TLS-handshake deadline** symmetric with the outbound `ConnectAttempt` 15 s timer, on
  both the peer (`51235`) and RPC-HTTPS (`5006`) acceptors, so a stalled handshake is torn down.
- **Cap concurrent half-open handshakes per source IP** (the `Resource::Consumer` rate budget is not a count
  cap); drop new half-opens from an IP already holding many.
- **Run with a raised, normalized FD ulimit** and **fix the `Server::reopenAcceptor` retry** so an accept
  failure cannot abort the process.
- **Do not expose the RPC-HTTPS port unauthenticated on a routable interface**; front it with a
  rate-limiting, handshake-bounding gateway.

## Disclosure & provenance

Availability-only, deployment/hardening-mitigable slow-handshake + FD-exhaustion on public-by-default TLS
listeners → **out of paid scope → publish-track** under NullRabbit's disclosure-scope policy. Vendor:
**XRPLF (`rippled`)**; this is our own (`source_class: original`) measurement of the inbound-vs-outbound
handshake-deadline asymmetry and the acceptor-reopen crash, not a novel implementation flaw of ours or an
assigned CVE. The corpus primitive `rippled_tls_slow_handshake` is **on-spec** (registered in the known-class
provenance map) and **on-HF** (shipped in `NullRabbit/nr-bundles-public`), so this advisory does not outpace
its shipped defensive artefact.
