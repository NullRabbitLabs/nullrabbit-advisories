# NR-2026-047 — Internet Computer (replica QUIC P2P transport): unbounded half-open connection pin → per-source memory ratchet

**NullRabbit Operator Advisory** · Published 2026-07-14

## Summary

The Internet Computer replica's **QUIC P2P transport** (quinn) accepts inbound connections in a loop that
spawns **every** inbound `Initial` packet into an **unbounded `inbound_connecting` `JoinSet`**, with **no
per-source-IP rate limit** and `EndpointConfig::default()` (i.e. **no Retry / no address validation**). An
attacker who sends a **truncated ClientHello** — a QUIC CRYPTO frame that declares a large length but sends
fewer bytes than quinn's 16 KiB crypto buffer — leaves rustls in the "incomplete, waiting for more" state.
The half-open connection then lives until the pre-handshake timeout, pinning quinn + rustls per-connection
state the whole time. Critically, the **mTLS `NodeId` allow-list fires *after* the pin is committed**, so
certificate trust does not mitigate: the memory is spent before the peer is ever authorised. Sending many
such truncated hellos ratchets replica RSS up in proportion to concurrent half-opens. This is an
**availability / memory-exhaustion** class, **out of paid scope**, on NullRabbit's publish-track.

## Findings at a glance

| Finding | Primitive | Endpoint | Class | Severity |
|---|---|---|---|---|
| `IC_QUIC_HALFOPEN_PIN` | `ic_quic_halfopen_pin` | replica QUIC P2P transport (UDP/4100) | `connection-exhaustion` + `half-open-pin` | MEDIUM |

- **Reachability:** network-reachable to whoever can send UDP to the replica's QUIC port (4100). In the
  default mainnet deployment UDP/4100 is default-deny to ~10 IPv6 datacenter prefixes, which bounds the
  practical attacker set; the pin itself needs **no valid certificate** (it precedes the mTLS gate).
- **Severity:** MEDIUM — measured ~95–132 KiB pinned per half-open with no rejection and no per-IP cap; RSS
  ratchets and holds on attack timescales, but replica hardware is large (512 GiB) and the network prefix
  allow-list bounds reach. Availability only. **Out of paid scope**, publish-track.
- **Affected:** `dfinity/ic` replica QUIC transport (`rs/p2p/quic_transport/`), **verified on the shipped
  replica binary** `release-2026-05-29_04-44-base` (commit `a47e543`, SHA256-verified).
- **Mitigation:** bound the `inbound_connecting` JoinSet, enable QUIC **Retry** (address validation), and add
  a **per-source-IP UDP pre-handshake budget**. See Mitigation.

## Mechanism (source-cited, `dfinity/ic`)

- **Unbounded accept fan-out.** The `quic_transport` connection manager's accept loop spawns each inbound
  `Initial` into an `inbound_connecting` `JoinSet` with **no size bound** and **no per-source-IP limit** — so
  the number of simultaneous in-progress handshakes is attacker-controlled.
- **No address validation.** `EndpointConfig::default()` ships **without Retry**, so quinn does not force a
  round-trip to validate the source address before committing handshake state; a spoofable/one-shot UDP
  `Initial` already reserves per-connection memory.
- **Half-open pin via truncated CRYPTO.** A CRYPTO frame that advertises a large length but delivers fewer
  bytes than quinn's 16 KiB crypto buffer keeps rustls in "incomplete" — the connection sits half-open,
  holding quinn + rustls per-connection state, until the pre-handshake timeout elapses.
- **Auth is too late to help.** The mTLS `NodeId` allow-list is enforced **after** the handshake state is
  committed, so an attacker with no valid node certificate still pins the memory. `EndpointConfig`'s
  `max_simultaneous_connections_per_ip_address` control is **TCP-only** and does not bound this UDP path.

## Measurement (fidelity: explicit)

**Measured on the shipped replica binary** (`release-2026-05-29_04-44-base`, commit `a47e543`,
SHA256-verified) on 2026-06-02, using an `ic-prep` 2-node loopback topology with QUIC on `127.0.0.1:4100`
and an RSS sampler on the victim replica:

| Burst (half-opens) | Peak Δ RSS | Per-conn pin | Connections rejected |
|---|---|---|---|
| n = 1000 | +129 MiB | ≈ 132 KiB/conn | 0 / 1000 |
| n = 3000 | +278 MiB (abs 420 MiB) | ≈ 95 KiB/conn | 0 / 12200 (cumulative) |

**No connection was rejected** across 12,200 attempts — confirming the absence of any pre-handshake rate
limit or per-IP cap. RSS **ratchets and holds** on attack timescales (it returns only over hours of idle),
so a sustained truncated-hello stream drives a monotic per-source memory climb. These numbers reproduce
earlier `ic-mirror` estimates almost exactly, so the mirror was accurate rather than inflated; running
against the **actual shipped product** removes any "did you test the real binary?" caveat.

The published corpus reproducer (primitive `ic_quic_halfopen_pin`; family `connection_exhaustion`,
`source_class: original`, shipped in `NullRabbit/nr-bundles-public`) captures the **attack traffic** — bursts
of truncated-ClientHello QUIC `Initial`s from one source with no completed handshakes — across postures. The
volume is capped for capture speed with the measured per-conn pin preserved in bundle provenance. **This
advisory stands on the shipped-binary measurement and the source trace (unbounded JoinSet + default
EndpointConfig + post-pin mTLS), not on the reproducer traffic alone.**

## Scope

Availability only (per-source memory ratchet → RSS pressure / eventual OOM under sustained load). No
consensus-safety break, no funds, no authentication bypass (the pin *precedes* auth but grants the attacker
nothing beyond memory occupancy), no state corruption. The default network-prefix allow-list on UDP/4100
bounds reach to datacenter peers, and 512 GiB replica RAM raises the volume needed for a fatal OOM — hence
MEDIUM, not HIGH. The reproducer targets a local self-owned loopback topology, carries no public IPs or
mainnet hostnames, and is not a turnkey mainnet weapon.

## Mitigation

- **Bound the accept fan-out.** Cap the `inbound_connecting` `JoinSet` (reject / shed once the in-progress
  handshake count exceeds a ceiling) so half-opens cannot grow without limit.
- **Enable QUIC Retry / address validation.** Configure the `EndpointConfig` with Retry so quinn forces a
  source-address round-trip before committing per-connection state, defeating one-shot / spoofed `Initial`s.
- **Per-source-IP UDP pre-handshake budget.** Add a per-source-IP limit on *in-progress* handshakes on the
  UDP path (the existing `max_simultaneous_connections_per_ip_address` is TCP-only and does not apply here).
- **Shorten the half-open timeout** for connections that stall mid-CRYPTO, so a truncated hello is reaped
  faster.

## Disclosure & provenance

Availability-only, deployment/hardening-mitigable memory-pin on the replica QUIC transport, network-bounded
by the default UDP prefix allow-list → **out of paid scope → publish-track** under NullRabbit's
disclosure-scope policy. Vendor: **DFINITY (`dfinity/ic`)**; this is our own (`source_class: original`)
measurement — verified against the shipped replica binary — of the unbounded half-open handshake exposure,
not a novel implementation flaw of ours or an assigned CVE. The corpus primitive `ic_quic_halfopen_pin` is
**on-spec** (registered in the known-class provenance map) and **on-HF** (shipped in
`NullRabbit/nr-bundles-public`), so this advisory does not outpace its shipped defensive artefact.
