# NR-2026-016 — Bitcoin Core BIP-324 v2 transport: pre-authentication ECDH CPU exhaustion

**NullRabbit Operator Advisory** · Published 2026-07-06

## Summary

Bitcoin Core's BIP-324 v2 encrypted transport performs an expensive **pre-authentication**
cryptographic operation the instant an inbound peer sends its 64-byte ellswift key — a
secp256k1 ellswift ECDH plus HKDF-SHA256 key derivation — **before** any allowlist check,
per-IP rate limit, or completed handshake. The only upstream gate is the *soft* 125-inbound
connection cap (eviction-on-full), and the inbound accept path is single-threaded. So a cheap
attacker that repeatedly opens a TCP connection, sends 64 bytes, and disconnects ("churn")
forces repeated pre-auth ECDH and **pins a CPU core**, degrading honest-peer handshakes.

NullRabbit measured **HIGH**: from 4 attacker IPs, honest-peer handshake latency degraded
**55× at p50 and 256× at p99** on Bitcoin Core. It is an availability issue only — no memory
corruption, no funds or consensus impact.

## Findings at a glance

| Item | Detail |
|---|---|
| Class | Pre-authentication CPU exhaustion on the P2P accept path (`compute_amp`) |
| Reachability | Remote, unauthenticated, on the public P2P port; triggered before any auth/rate-limit |
| Trigger | Churn of inbound TCP connections each sending a 64-byte ellswift key (the v2 transport start) |
| Measured | Honest-peer handshake latency **55× p50 / 256× p99** at 4 attacker IPs (Bitcoin Core); Qtum 65–107× p50 / 182× p99 / 11% denial |
| Severity | High for node availability (cheap remote pre-auth core-pin, single-threaded accept path) |
| Affected | Bitcoin Core ≥ 27.0 (v2 transport **default-on** since 27.0, Apr 2024) and derived nodes that keep `DEFAULT_V2_TRANSPORT{true}` — incl. Bitcoin Knots, Dash, Groestlcoin, Particl, Namecoin (source-verified), Qtum (measured) |
| Mitigation | Rate-limit / proof-of-work-gate the pre-auth ellswift ECDH per source; move it behind the inbound cap; parallelise the accept path. See Mitigation |

## Mechanism (source-cited)

On an inbound v2 connection, the first 64 bytes are the peer's ellswift public key
(`src/bip324.cpp`). Receiving them triggers the responder's ellswift ECDH + HKDF-SHA256 session
key derivation — the expensive step — **at the point of receipt**, ahead of any peer
authorization, per-IP limit, or handshake completion. The only prior gate is the inbound
connection cap (`DEFAULT_MAX_PEER_CONNECTIONS` / the 125-inbound soft limit), which is
eviction-on-full rather than a hard reject, and the accept loop that runs this is single-threaded,
so the per-connection ECDH cost serialises against honest inbound handshakes.

v2 transport was added off-by-default in Core 26.0 and became **default-on in Core 27.0**
(PRs #29058 / #29347). A fork carrying `bip324.cpp` is only default-reachable if it also ships
`DEFAULT_V2_TRANSPORT{true}` and the `CreateNodeFromAcceptedSocket` inbound v2 wiring — verified
present on Bitcoin Knots, Dash, Groestlcoin, Particl, Namecoin; Syscoin ships it off-by-default.

## Reproduction (fidelity: explicit)

The CPU pin is a server-side effect. The published corpus reproducer
(`chains/bitcoin/lab/drivers/known_class_btc_bip324.py`, primitive
`btc_bip324_prehandshake_ecdh_cpu` in `NullRabbit/nr-bundles-public`) captures the wire signature —
a churn of inbound TCP connections each sending a 64-byte ellswift key then closing — with
`provenance.wire_fidelity = "ellswift_churn_representative"` and the measured 55×/256× latency
degradation recorded in `attack_parameters`. **This advisory stands on the source trace and the
live measurement, not on the reproducer's synthetic churn rate.**

## Mitigation

- **Gate the pre-auth ECDH.** Apply a per-source rate limit (or a cheap challenge / proof-of-work)
  *before* running ellswift ECDH + HKDF on an inbound connection.
- **Move the cost behind the inbound cap** and make the cap a hard reject for unauthenticated peers
  under load, rather than eviction-on-full.
- **Parallelise / offload** the accept-path key derivation so one attacker cannot serialise honest
  handshakes.
- Operators can reduce exposure by lowering `-maxconnections` pressure and firewalling the P2P port
  to known peers where the deployment permits.

## Disclosure & provenance

Availability-only finding (no funds/consensus impact). Bitcoin Core operates **no paid bug-bounty
program**, so this is a free operator advisory (publish-track — the Anza/Bitcoin-Core "confirmed
oos-publish" class). NullRabbit measurement; source-trace and live numbers in
`chains/bitcoin/findings/BTC_V0_BIP324_PREHANDSHAKE_CPU`. Corpus primitive
`btc_bip324_prehandshake_ecdh_cpu` shipped in `NullRabbit/nr-bundles-public`.
