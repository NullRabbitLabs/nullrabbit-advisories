# NR-2026-008 — CometBFT SecretConnection pre-authentication handshake CPU burn

**NullRabbit Operator Advisory** · Published 2026-07-04

## Summary

A CometBFT node completes the full SecretConnection STS handshake — including the
two expensive asymmetric-crypto operations, an **X25519 Diffie–Hellman** and an
**Ed25519 signature verification** — for *any* peer that connects, **before** the
caller checks whether that peer's node-ID is in the persistent/allowlist set and
disconnects it. An unauthenticated remote source therefore forces ~100–150 µs of
asymmetric crypto per connection attempt with zero authentication. Sustained, a
single source (~56k handshake probes/sec in our measurement) saturates roughly
three CPU cores on the target node.

This is an **availability / resource issue only**: the node keeps running, and on
a multi-validator network the chain keeps producing blocks. No crash, no
consensus-safety violation, no funds impact. **Severity: MEDIUM** (single-node CPU
load under a sustained pre-auth handshake flood).

## Affected configuration

Every CometBFT-based node. SecretConnection is the upstream P2P transport for the
whole Cosmos-SDK family (~100 chains). Measured against `cometbft v0.38.22`
(single-validator localnet, `--proxy_app=kvstore`). No per-IP handshake rate-limit
is applied before the crypto runs, so the default configuration is affected.

## Findings at a glance

| Item | Detail |
|---|---|
| Class | Pre-authentication asymmetric-crypto CPU burn on the P2P handshake (`compute_amp`) |
| Reachability | Remote, unauthenticated, single source IP; no valid signing key required |
| Trigger | Repeated SecretConnection handshakes; the server runs one X25519 DH + one Ed25519 verify per attempt |
| Impact | ~100–150 µs of asymmetric crypto per probe; ~56k probes/sec saturates ~3 cores. Quorum block production unaffected on multi-validator networks |
| Severity | MEDIUM — single-node CPU; no crash, no consensus-safety or funds impact |
| Mitigation | Per-IP connection / handshake rate-limiting at the P2P listener, applied *before* the STS crypto; prioritise handshakes from allowlisted node-IDs |

## Mechanism (source-cited)

In `p2p/conn/secret_connection.go`, `MakeSecretConnection` runs the STS exchange in
order: generate the ephemeral key, exchange ephemeral public keys, compute the
**X25519 shared secret** (`computeDHSecret`), derive the transcript/HKDF keys, sign
the challenge, and finally **verify the remote peer's Ed25519 signature**
(`remPubKey.VerifySignature`). Only after `MakeSecretConnection` returns does the
caller in `p2p/peer.go` compare the now-known remote node-ID against the node's
allowlist and disconnect an unwanted peer.

The two costly asymmetric operations — the X25519 DH and the Ed25519 verify — both
complete **before** that allowlist check. The module's own documentation notes that
consumers must authenticate the remote pubkey against known information such as a
node-ID (the MITM caveat); it does not call out the second consequence, that the
pre-authentication path lets any unauthenticated source spend the node's asymmetric
crypto budget at will.

## Impact & mitigation

- **Impact:** elevated CPU on the targeted node under a sustained pre-auth
  handshake flood. On a multi-validator network, quorum height and block
  production continue at baseline; this is node-local load, not a chain halt.
- **Mitigation:** apply a per-IP connection / handshake rate-limit at the P2P
  listener *before* the SecretConnection crypto runs; give allowlisted-peer
  handshakes priority so a flood of unauthenticated attempts cannot starve them.

## Scope

This advisory targets node **availability** only. The vendor scopes node-level
availability / DoS out of its paid-impact categories; a class the vendor declines
to treat as a paid impact carries no disclosure embargo, so — as with the
previously published CometBFT consensus-channel floods (NR-2026-007) — this is
published as an operator advisory and as open ML training data. There is no
embargo: the finding rests on our own measurement against a self-owned local node.

## Reproduction

Reproduced against a self-owned single-validator CometBFT localnet using CometBFT's
own `p2p/conn.MakeSecretConnection` client (so the wire format is guaranteed
correct): dial, run the full STS exchange, close on completion, repeat from a
worker pool. The reproducer drives a locally-run node to demonstrate the CPU slope
and does not target any public or mainnet endpoint. Representative multi-modal
capture bundles are published in the
[`nr-bundles-public`](https://huggingface.co/datasets/NullRabbit/nr-bundles-public)
dataset (`family_id=compute_amp`).

## Provenance

NullRabbit original research (our own measurement on a self-owned lab node).
Cross-references: NullRabbit finding id `COSMOS_MCONN_PREAUTH`; detection primitive
`cometbft_mconn_handshake_burn` (family `compute_amp`).

## Contact

Simon Morley, NullRabbit — `simon@nullrabbit.ai`.
