# NR-2026-049 — libp2p Noise pre-auth handshake CPU/connection burn across five chains (Ethereum CL, Filecoin, Polkadot/Substrate, Optimism, Celestia)

**NullRabbit Operator Advisory** · Published 2026-07-14

## Summary

Five chains built on libp2p — **Ethereum consensus layer** (Lighthouse, rust-libp2p), **Filecoin**
(go-libp2p), **Polkadot/Substrate** (litep2p), **Optimism op-node** (go-libp2p), and **Celestia DA**
(go-libp2p) — share the libp2p connection-establishment path in which the **Noise `XX` handshake runs an
X25519 ECDH before the remote peer is authenticated or admitted**. An unauthenticated attacker that opens a
storm of fresh connections, each carrying the `/multistream/1.0.0` → `/noise` → `/yamux/1.0.0` opening
handshake, forces per-connection pre-auth crypto plus connection-manager / peerstore state on the victim —
with no valid peer identity and no cost to the attacker. The multistream/noise/yamux wire is **byte-identical
across libp2p implementations**, so this is a single class realised on five deployments. Availability-only,
on NullRabbit's publish-track.

## Findings at a glance

| Finding | Primitive | Chain | Class | Severity |
|---|---|---|---|---|
| `ETHCL_LIBP2P_NOISE_PREAUTH` | `ethcl_libp2p_noise_preauth_flood` | ethereum-consensus-layer | `connection-exhaustion` (Noise pre-auth ECDH) | MEDIUM |
| `FIL_P2P_NOISE_HANDSHAKE_PREAUTH` | `fil_libp2p_noise_preauth_flood` | filecoin | `connection-exhaustion` (Noise pre-auth ECDH) | MEDIUM |
| `SUBSTRATE_LITEP2P_NOISE_PREAUTH` | `substrate_litep2p_noise_preauth_flood` | polkadot-substrate | `connection-exhaustion` (Noise pre-auth ECDH) | MEDIUM |
| `OPT_OPNODE_LIBP2P_PRENOISE_NO_PERIP_GATE` | `op_libp2p_noise_preauth_flood` | optimism | `connection-exhaustion` (pre-Noise, no per-IP gate) | MEDIUM |
| `CELESTIA_DA_LIBP2P_RCMGR_GLOBAL_CONN_CAP` | `celestia_libp2p_noise_preauth_flood` | celestia | `connection-exhaustion` (rcmgr global conn-cap) | MEDIUM |

- **Reachability:** any host that can open a libp2p transport connection to the node's P2P listener —
  pre-auth, no peer identity needed.
- **Severity:** MEDIUM — pre-auth Noise ECDH + connection/peerstore state per fresh connection; a sustained
  fresh-connection storm degrades peering capacity. The resource-manager defaults (go-libp2p `rcmgr`,
  litep2p limits) bound a single source but the pre-auth work still lands. Availability only.
  **Out of paid scope**, publish-track.
- **Affected:** `lighthouse@176cce5` (rust-libp2p, `noise`), `filecoin-lotus@797feeb` (go-libp2p v0.47.0),
  `polkadot-sdk@1aeb6ec` (litep2p v0.14.0), `optimism@286107f` (go-libp2p v0.36.2),
  `celestia-node@4343f61` (go-libp2p v0.48.0).

## Mechanism (source-cited)

libp2p secures every inbound connection with the Noise `XX` pattern, which performs ephemeral **X25519
Diffie-Hellman** as part of the handshake — necessarily **before** the remote static key is known and the
peer is authenticated / checked against the connection manager and any allow-list. The opening exchange is
multistream-select negotiating the security transport (`/noise`) then the muxer (`/yamux`), and these
protocol IDs and the Noise message framing are **byte-identical across every libp2p implementation**
(go-libp2p, rust-libp2p, litep2p). So a flood of fresh connections drives:

- per-connection **Noise X25519 ECDH** (pre-auth CPU), and
- per-connection **connection-manager slot + peerstore entry** (accounting the manager was designed for
  regular churn, not a targeted storm).

Op-node's finding notes the **absence of a per-source-IP gate** ahead of this path; Celestia's notes the
**global connection-cap** (rcmgr `system` scope) being saturable by one source. Both are the same
fresh-connection/Noise-handshake flood realised against each deployment's config.

## Measurement (fidelity: explicit)

The **traffic** for each chain is captured via a loopback libp2p connection-setup mock that speaks the exact
`/multistream/1.0.0` → `/noise` → `/yamux/1.0.0` opening handshake — byte-identical to what each node's
libp2p stack receives — under saturating + distributed postures. Bundles
`{ethcl,fil,substrate,op,celestia}_libp2p_noise_preauth_flood` ship in `NullRabbit/nr-bundles-public`. The
per-chain claim is **source-confirmed** (each uses libp2p Noise, versions above) + captured traffic; it is
**not** an independent per-chain CPU measurement. Honest split: proven = shared Noise handshake wire +
captured attack traffic; source-confirmed = each deployment's use of libp2p Noise and its rate-limit posture.

## Scope

Availability only — pre-auth Noise ECDH + connection/peerstore consumption on the libp2p listener. No
consensus-safety break, no funds, no memory corruption, no authentication bypass. The reproducer targets a
self-owned loopback mock, carries no public IPs or mainnet hostnames, and is not a turnkey mainnet weapon.

## Mitigation

- **Per-source-IP connection-rate + concurrency limits** ahead of the libp2p handshake (op-node's gap):
  cap new inbound connections per source so one host cannot storm the Noise path.
- **Scope the resource manager tightly** (go-libp2p `rcmgr`: per-peer + per-IP + transient scopes below the
  system cap so a single source cannot exhaust the global connection budget — Celestia's gap; litep2p:
  the equivalent connection limits).
- **Prefer curated/trusted peering** where the deployment allows, and keep handshake timeouts short so
  half-open Noise handshakes are reaped quickly.

## Disclosure & provenance

Availability-only, deployment/hardening-mitigable pre-auth Noise handshake burn common to libp2p → **out of
paid scope → publish-track** under NullRabbit's disclosure-scope policy. Vendors: Sigma Prime / EF
(Lighthouse), Protocol Labs (Filecoin/go-libp2p), Parity (Polkadot/litep2p), OP Labs (Optimism), Celestia
Labs. This is our own (`source_class: original`) source trace + captured traffic of the shared libp2p Noise
pre-auth class, not a novel implementation flaw of ours or an assigned CVE. The corpus primitives
`{ethcl,fil,substrate,op,celestia}_libp2p_noise_preauth_flood` are **on-spec** and **on-HF** (shipped in
`NullRabbit/nr-bundles-public`), so this advisory does not outpace its shipped defensive artefact.
