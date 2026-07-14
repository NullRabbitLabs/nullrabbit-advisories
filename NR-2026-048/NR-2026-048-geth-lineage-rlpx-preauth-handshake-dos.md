# NR-2026-048 — geth-lineage forks inherit the RLPx pre-auth handshake CPU/bandwidth burn (BNB Smart Chain, Polygon Bor, Sonic)

**NullRabbit Operator Advisory** · Published 2026-07-14

## Summary

Three go-ethereum-derived clients — **BNB Smart Chain** (`bnb-chain/bsc` / core-chain), **Polygon Bor**
(`maticnetwork/bor`), and **Sonic** (`0xsoniclabs/sonic`, go-opera lineage) — vendor go-ethereum's
`p2p/rlpx` **byte-identically**, and therefore inherit the known RLPx **pre-authentication handshake
burn**: on each inbound TCP connection the node runs ECIES decryption + an ECDH (`GenerateShared`) over the
attacker-supplied auth frame **before** the peer is authenticated or admitted. An unauthenticated attacker
that floods RLPx auth packets on fresh connections spends the victim's handshake CPU + bandwidth with zero
cost to itself and no valid node identity. This is the **`geth_rlpx_auth_flood`** class (a public
Ethereum-Foundation-disclosed devp2p exposure) reproduced on the fork family; **availability-only**, on
NullRabbit's publish-track (out of paid scope for these node vendors).

## Findings at a glance

| Finding | Primitive | Chain | Class | Severity |
|---|---|---|---|---|
| `BSC_RLPX_HANDSHAKE_ECDH_PREAUTH` | `bsc_rlpx_auth_flood` | bnb-smart-chain | `connection-exhaustion` (RLPx pre-auth ECDH) | MEDIUM |
| `POLYGON_BOR_RLPX_DECODE_BURN` | `bor_rlpx_auth_flood` | polygon-pos | `connection-exhaustion` (RLPx pre-auth ECDH) | MEDIUM |
| `SONIC_RLPX_INHERITED` | `sonic_rlpx_auth_flood` | sonic-fantom | `connection-exhaustion` (RLPx pre-auth ECDH) | MEDIUM |

- **Reachability:** any host that can open TCP to the node's devp2p port (default `:30303`) — pre-auth, no
  node identity needed.
- **Severity:** MEDIUM — pre-auth crypto/bandwidth burn on the handshake path; degrades peering capacity
  under a sustained flood, but the per-connection cost is bounded and go-ethereum's handshake timeout +
  peer caps limit a single source. Availability only. **Out of paid scope**, publish-track.
- **Affected:** `core-chain@3dd2b07` (BSC), `polygon-bor@01182de` (Bor), `sonic@7f56acb` (Sonic,
  go-ethereum v1.17.1 dep) — all source-confirmed to carry the unmodified go-ethereum RLPx handshake.

## Mechanism (source-cited)

RLPx `Conn.Handshake` (`p2p/rlpx/rlpx.go`) reads the inbound auth message and, before any peer-identity or
allow-list check, performs the ECIES/ECDH work:

- `readMsg(authMsg, prv, conn)` (`rlpx.go:415`) **ECIES-decrypts** the attacker's auth frame;
- `ecies.GenerateKey(...)` (`:450`) + `randomPrivKey.GenerateShared(remoteRandomPub, ...)` (`:473`) run the
  **X25519/secp256k1 ECDH** — a secp256k1 point-multiply on the server's ephemeral secret against the
  attacker-supplied point.

All of this happens on the attacker's bytes, before the node knows or trusts who is connecting. BSC, Bor,
and Sonic import `github.com/ethereum/go-ethereum/crypto/ecies` and reuse this exact code path unchanged
(BSC/Bor carry the `p2p/rlpx/rlpx.go` file verbatim; Sonic depends on go-ethereum v1.17.1). So the
established Ethereum RLPx pre-auth-flood exposure applies identically to all three.

## Measurement (fidelity: explicit)

The **traffic** for each fork is captured (RLPx auth-flood: fresh TCP connections each sending the RLPx auth
packet without completing the handshake) against a go-ethereum reference node — the wire is byte-identical
across the lineage, so it faithfully represents what a BSC/Bor/Sonic node's rlpx handshake receives. Bundles
`{bsc,bor,sonic}_rlpx_auth_flood` (saturating + distributed postures) ship in `NullRabbit/nr-bundles-public`.
The **impact** is the measured `geth_rlpx_auth_flood` base class (EF public disclosure); the per-fork claim
is **source-confirmed inheritance** (identical vendored code) + captured traffic, **not** an independent
per-fork CPU measurement. Honest split: proven = shared vendored code path + captured attack traffic;
inherited = the base-class CPU/bandwidth impact.

## Scope

Availability only — pre-auth handshake CPU/bandwidth consumption on the devp2p listener. No consensus-safety
break, no funds, no memory corruption, no authentication bypass (the attacker gains nothing but resource
occupancy). The reproducer targets a self-owned loopback reference node, carries no public IPs or mainnet
hostnames, and is not a turnkey mainnet weapon.

## Mitigation

- **Per-source-IP inbound rate limiting** on the devp2p port (connection + auth-packet rate) so one source
  cannot monopolise handshake CPU — front the p2p port with a stateful firewall / connection-rate limiter.
- **Cap concurrent inbound handshakes** and keep the handshake timeout tight (go-ethereum already bounds
  in-flight handshakes; size it for the node's peer budget).
- **Prefer a curated static/trusted peer set** where the deployment allows, reducing exposure of the open
  inbound listener.

## Disclosure & provenance

Availability-only, deployment/hardening-mitigable pre-auth handshake burn inherited from upstream
go-ethereum → **out of paid scope → publish-track** under NullRabbit's disclosure-scope policy. Vendors:
BNB Chain (`bnb-chain/bsc`), Polygon (`maticnetwork/bor`), Sonic Labs (`0xsoniclabs/sonic`). This is our own
(`source_class: original`) source trace + captured traffic of the inherited `geth_rlpx_auth_flood` class, not
a novel implementation flaw of ours or an assigned CVE. The corpus primitives `bsc_/bor_/sonic_rlpx_auth_flood`
are **on-spec** (registered in the known-class provenance map) and **on-HF** (shipped in
`NullRabbit/nr-bundles-public`), so this advisory does not outpace its shipped defensive artefact.
