# NR-2026-039 — Casper, Conflux & Icon: an unauthenticated peer forces a pre-admission asymmetric-crypto handshake step (P-521 ECDSA-verify / secp256k1 & P-256 ECDH) → pre-auth crypto-CPU burn and honest-peer degradation

**NullRabbit Operator Advisory** · Published 2026-07-13

## Summary

Three Kraken-listed, non-Coinbase chains — **Casper** (`casper-node`), **Conflux** (`conflux-rust`), and
**Icon** (`goloop`) — share one transport-layer weakness: an **unauthenticated inbound peer forces the node to
run an asymmetric-crypto handshake step (an ECDH point-multiply or a full ECDSA signature verify) BEFORE any
admission, allowlist, per-peer cap, or rate gate**. In each case the only pre-crypto gates are *concurrency*
counters (a per-IP session cap, a soft per-peer cap, or none at all) — not rate limits — so a churn of fresh
pre-auth connections, each triggering one server-side asymmetric-crypto operation and then closing, burns
crypto-CPU and degrades honest peering. This is the same family as **NR-2026-037** (Qtum BIP-324 pre-auth
ellswift-ECDH). All three are **MEDIUM**, **availability-only** (pre-auth crypto-CPU → honest-peering
degradation; no consensus halt — each chain produces blocks on a separate PoW/PoS path), and **out of paid
scope** for each chain's own program (DoS/availability), so each is handled on NullRabbit's **publish-track**.

Unlike NR-2026-037 — where the Qtum path was independently CPU-**measured** in a DigitalOcean production shape —
the three findings here are **source-traced + traffic-modelled**: the published reproducers capture the
pre-auth connection-churn **wire signature**, and the server-side crypto-CPU burn is the **source-traced
mechanism**, **not** an independent server-side CPU measurement. See Measurement.

## Findings at a glance

| Finding | Primitive | Endpoint | Class | Severity |
|---|---|---|---|---|
| `CSPR_KRAKEN_TRANSPORT` | `casper_p521_preauth_verify_burn` | inbound P2P TLS-1.3 acceptor (`SslVerifyMode::PEER`) | `pre-auth-crypto-burn` + `tls-ecdsa-verify` | MEDIUM |
| `CFX_KRAKEN_TRANSPORT` | `cfx_ecies_preauth_ecdh_burn` | inbound P2P `:32323` (ECIES handshake responder) | `pre-auth-crypto-burn` + `ecies-ecdh` | MEDIUM |
| `ICX_KRAKEN_TRANSPORT` | `icon_goloop_preauth_ecdh_burn` | inbound `goloop` TCP P2P listener (`network/`) | `pre-auth-crypto-burn` + `ecdh` | MEDIUM |

- **Reachability (all three):** any remote host that can reach the peer port; no auth, no completed handshake,
  no server pubkey and no valid MAC/HMAC required; a single source IP suffices to drive the pre-auth crypto
  (fleet-amplified where a per-IP concurrency cap applies).
- **Severity:** MEDIUM each — source-traced pre-auth asymmetric-crypto before any cost gate. Ceiling is
  fullnode-peering / pre-auth-CPU availability, **not** a consensus halt.
- **Provenance:** each `source_class: original`; each primitive is **on-HF** (shipped in
  `NullRabbit/nr-bundles-public`, registered in `HF_DATASET_PRIMITIVES`).

## Mechanism (source-cited, per chain)

### Casper — `CSPR_KRAKEN_TRANSPORT` / `casper_p521_preauth_verify_burn`

`casper-node`'s P2P listener is a **TLS-1.3 acceptor with `SslVerifyMode::PEER` and a verify callback returning
`true`** (`tls.rs:362`), and it is reached **unconditionally** at `tasks.rs:341` (`server_setup_tls`) — i.e.
the TLS handshake runs **BEFORE** the `allow_handshake` guard (`tasks.rs:370`) and **BEFORE** the per-peer cap
(`network.rs:555`, whose default is `0` = *unlimited*). Post-TLS, the node runs `validate_self_signed_cert`
(`tls.rs:500-540`), which performs a **full P-521 ECDSA `cert.verify()`** on the attacker's self-signed
certificate (serial `1`, `subject == issuer`, curve `SECP521R1`, `ECDSA-SHA512`). A single unauthenticated host
floods **fresh-cert-per-connection TLS-1.3 handshakes** (no application bytes ever sent), forcing **one P-521
signature verify per connection** and defeating any per-`NodeId` cap (the cap is applied *after* the crypto).
Source-traced `casper-node @ee2fe18`.

### Conflux — `CFX_KRAKEN_TRANSPORT` / `cfx_ecies_preauth_ecdh_burn`

`conflux-rust`'s session handshake runs `ecies::decrypt` → `ecdh::agree` — a **secp256k1 point-multiply on the
server's static node secret** — on an attacker-supplied **209-byte ECIES auth frame** (`AUTH_PACKET_SIZE`),
**BEFORE the HMAC tag check AND BEFORE the blacklist/admission gate** (`handshake.rs:173-197`;
`cfx_crypto/src/crypto.rs:150`). A one-way **connect → single 209-byte auth frame → close** flood needs **no
server pubkey and no valid HMAC** (the length check is an attacker-fillable garbage filter; the ECDH runs
first). The only pre-crypto gate is `single_ip_quota=1` — a **concurrency cap, not a rate limit** — so this is
a fleet-amplified pre-auth ECDH burn on the server's IoService worker pool. Source-traced
`conflux-rust @2dfb5f91`.

### Icon — `ICX_KRAKEN_TRANSPORT` / `icon_goloop_preauth_ecdh_burn`

`goloop`'s custom TCP P2P listener (`network/`) runs an **unbounded accept loop with NO allowlist, trusted-set,
connection cap, or rate limit** before `authenticator.go` `handleSecureRequest` → `secure.go:226`
`c.ScalarMult` — a **full P-256 ECDH plus HKDF-SHA3-256** — computed on the attacker's `Unmarshal`'d curve
point. A single unauthenticated host floods **connect → one msgpack `SecureRequest` → close**, burning server
ECDH CPU pre-auth. The P-256 `ScalarMult` costs ~tens-of-microseconds, so the ceiling is
**fullnode-peering / pre-auth-CPU availability**, **not** a consensus halt at single-IP scale. Source-traced
`goloop @67f6ff8`.

## Measurement (fidelity: explicit)

**These three findings are source-traced + traffic-modelled; the server-side crypto-CPU burn is NOT
live-measured.** This is a deliberately weaker fidelity claim than NR-2026-037 (whose Qtum path carried a
DigitalOcean production-shape CPU measurement) — **no measured latency, handshake-rate, or core-saturation
numbers are asserted here**.

For each finding, the published corpus reproducer (`casper_p521_preauth_verify_burn`,
`cfx_ecies_preauth_ecdh_burn`, `icon_goloop_preauth_ecdh_burn`; each `source_class: original`, shipped in
`NullRabbit/nr-bundles-public`) captures the **pre-auth-connection-churn wire signature** — a churn of fresh
inbound connections, each carrying exactly the minimal frame that triggers the server's asymmetric-crypto step
(a fresh-cert TLS-1.3 ClientHello for Casper; a 209-byte ECIES auth frame for Conflux; a single msgpack
`SecureRequest` for Icon) and then closing. **The server-side CPU cost is the source-traced mechanism (the
ECDH / ECDSA-verify runs before any cost gate, per the citations above) — it is not an independent server-side
CPU measurement.** These advisories stand on the source trace, not on a measured saturation figure.

## Scope

Availability only (pre-auth asymmetric-crypto CPU → honest-peer connection/peering degradation); **no
consensus-safety break, no funds at risk, no authentication bypass**. Each chain produces blocks on a separate
PoW/PoS path that is not halted by this class at single-IP scale. A node whose pre-auth handshake is
cost-gated per source IP — with a real admission/rate gate ahead of the ECDH/ECDSA-verify and a reserve of
slots for established peers — is not affected. Each reproducer targets a local self-owned mock, carries no
public IPs or mainnet hostnames, and is not a turnkey mainnet weapon.

## Mitigation

- **Cost-gate the pre-auth crypto per source IP:** apply a per-source-IP rate limit / cheap PoW / connection-rate
  cap **BEFORE** the ECDH point-multiply (Conflux, Icon) or the ECDSA `cert.verify()` (Casper) runs, so an
  unauthenticated peer cannot force unbounded asymmetric-crypto work.
- **Make the per-peer / per-connection cap a real admission gate, not a post-crypto concurrency cap:** Casper's
  per-peer cap (`network.rs:555`, default `0`/unlimited) and Conflux's per-IP session quota (`single_ip_quota`)
  are applied *after* — or are pure concurrency counters that do not bound — the pre-auth crypto; move a real
  rate/admission decision ahead of the crypto, and give `goloop`'s unbounded accept loop a connection cap.
- **Reserve slots for established peers** so fresh-socket churn cannot displace or starve honest, verified peers.

## Disclosure & provenance

Availability-only, deployment/hardening-mitigable pre-auth CPU-exhaustion on public-by-default P2P listeners →
**out of paid scope → publish-track** under NullRabbit's disclosure-scope policy. Casper, Conflux, and Icon are
Kraken-listed, non-Coinbase assets; DoS/availability is out of scope for each chain's own program, so this is
publish-track (the Kraken channel is a courtesy, **not** a bounty venue). Each finding is our own
(`source_class: original`) source trace of a pre-auth-cost-gating gap — the same family as the measured Qtum
BIP-324 path in NR-2026-037 — **not** a novel implementation flaw of ours and **not** an assigned CVE. Each
corpus primitive is **on-HF** — `casper_p521_preauth_verify_burn`, `cfx_ecies_preauth_ecdh_burn`, and
`icon_goloop_preauth_ecdh_burn` are all shipped in `NullRabbit/nr-bundles-public` and registered in
`HF_DATASET_PRIMITIVES` — so this advisory does not outpace its shipped defensive artefact.
