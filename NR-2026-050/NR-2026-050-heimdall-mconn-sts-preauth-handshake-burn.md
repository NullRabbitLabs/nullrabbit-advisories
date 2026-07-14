# NR-2026-050 — Polygon Heimdall inherits the Tendermint SecretConnection STS pre-auth crypto burn

**NullRabbit Operator Advisory** · Published 2026-07-14

## Summary

**Polygon Heimdall** (the Polygon PoS consensus/validator layer) runs a fork of Tendermint
(`maticnetwork/tendermint v0.33.5`) and therefore inherits Tendermint's **SecretConnection STS
pre-authentication crypto burn**: an unauthenticated peer that repeatedly runs the `MakeSecretConnection`
station-to-station exchange forces the server's **X25519 Diffie-Hellman** + **ed25519 signature
verification** on every probe — **before** the caller's `NodeID`-allow-list check in `p2p/peer.go`. So an
attacker with no valid node identity spends the victim's asymmetric-crypto CPU per handshake at zero cost.
This is the same class NullRabbit measured on modern CometBFT (CometBFT MConn STS handshake-burn), here
confirmed on the Heimdall fork. Availability-only, on NullRabbit's publish-track.

## Findings at a glance

| Finding | Primitive | Chain | Class | Severity |
|---|---|---|---|---|
| `POLYGON_HEIMDALL_MCONN_PREAUTH` | `heimdall_mconn_handshake_burn` | polygon-pos | `compute-amp` (SecretConnection STS pre-auth) | MEDIUM |

*(The parallel cosmos-ecosystem survey — the same class across gaia / osmosis / injective / dydx /
celestia — rides the already-shipped CometBFT MConn primitive and is not re-modelled here.)*

- **Reachability:** any host that can open a TCP connection to the Heimdall P2P port (Tendermint default
  `:26656`) — pre-auth, no node identity needed.
- **Severity:** MEDIUM — pre-auth asymmetric crypto (X25519 DH + ed25519 verify) per handshake probe; a
  sustained STS-handshake flood burns CPU and can pressure honest peering, but the per-probe cost is bounded.
  Availability only. **Out of paid scope**, publish-track.
- **Affected:** Polygon Heimdall on `maticnetwork/tendermint v0.33.5` (fork of `tendermint v0.34.24`).

## Mechanism (source-cited)

Tendermint/CometBFT authenticate the P2P link with an encrypted `SecretConnection` established via a
station-to-station handshake **before** the peer's `NodeID` is checked against the node's allow-list:

- `MakeSecretConnection` (`p2p/conn/secret_connection.go`) performs the ephemeral **X25519 DH** and then an
  **ed25519 `VerifySignature`** over the exchanged challenge;
- only *after* the secret connection is established does `p2p/peer.go` check the peer's `NodeID` against the
  configured allow-list.

So the expensive asymmetric crypto runs on an unauthenticated attacker's handshake. Heimdall's
`maticnetwork/tendermint v0.33.5` carries this SecretConnection STS design (the STS crypto is unchanged
across the Tendermint/CometBFT line), so the pre-auth burn applies. An attacker floods short STS handshakes
(connect → run the exchange → drop) to sustain the CPU cost.

## Measurement (fidelity: explicit)

The **STS handshake-burn traffic** is captured (unauthenticated peers repeatedly running the
SecretConnection exchange) against a CometBFT reference node. **Fidelity note:** Heimdall pins
`tendermint v0.33.5` while the reference capture is CometBFT v0.38 — the SecretConnection STS *crypto* is
version-stable (X25519 DH + ed25519 verify pre-auth), so the capture is **class-representative**; the exact
wire *framing* differs between 0.33.5 and 0.38. Bundle `heimdall_mconn_handshake_burn` (saturating +
distributed) ships in `NullRabbit/nr-bundles-public`. The impact is the measured CometBFT MConn STS handshake-burn
base class (NullRabbit measured ~17µs asymmetric crypto per probe, unauth); the Heimdall claim is
**source-confirmed inheritance** + class-representative captured traffic, **not** an independent
Heimdall-node CPU measurement. Honest split stated so operators aren't over-sold.

## Scope

Availability only — pre-auth handshake CPU consumption on the P2P listener. No consensus-safety break, no
funds, no memory corruption, no authentication bypass. The reproducer targets a self-owned reference node,
carries no public IPs or mainnet hostnames, and is not a turnkey mainnet weapon.

## Mitigation

- **Per-source-IP connection-rate limiting** on the Heimdall P2P port so one source cannot sustain a
  handshake-burn flood — front `:26656` with a stateful connection-rate limiter.
- **Cap concurrent inbound handshakes / secret-connection setups**, and keep the handshake timeout tight so
  incomplete STS exchanges are reaped.
- **Prefer a curated persistent-peer / seed set** and firewall the P2P port to known infrastructure where
  the deployment allows.

## Disclosure & provenance

Availability-only, deployment/hardening-mitigable pre-auth STS crypto burn inherited from the Tendermint
SecretConnection design → **out of paid scope → publish-track** under NullRabbit's disclosure-scope policy.
Vendor: Polygon (`maticnetwork/heimdall`, `maticnetwork/tendermint`). This is our own
(`source_class: original`) source trace + class-representative captured traffic of the inherited
SecretConnection STS pre-auth burn, not a novel implementation flaw of ours or an assigned CVE. The corpus
primitive `heimdall_mconn_handshake_burn` is **on-spec** and **on-HF** (shipped in
`NullRabbit/nr-bundles-public`), so this advisory does not outpace its shipped defensive artefact.
