# NR-2026-022 — Prysm: unbounded beacon-API pool-submission decode + per-element BLS work → compute-amplification DoS

**NullRabbit Operator Advisory** · Published 2026-07-08

## Summary

Three findings on the Prysm beacon-chain **HTTP Beacon API** pool-submission surface share one root cause:
a REST handler decodes an attacker-controlled JSON list (or an attacker-sized index vector) with **no
`http.MaxBytesReader` body cap, no list-length cap, and no authentication**, then performs **per-element
BLS work** on the decoded elements. A single well-formed request therefore converts a few MB of attacker
bandwidth into seconds of single-goroutine CPU on the target — a compute-amplification denial-of-service.
All three reach the expensive path pre-signature-verify, so the work is paid before the request is
rejected. This is an **availability issue only** — no funds, no consensus-safety break, no authentication
bypass. It affects operators who bind the Beacon API to a non-loopback address (block-explorer / staking-
indexer / MEV-relay / split validator-client deployments); the loopback default is not remotely reachable.

## Findings at a glance

| Finding | Primitive | Endpoint | Per-element work | Measured |
|---|---|---|---|---|
| `PRYSM_BLS_POOL_DECODE_BURN` | `prysm_bls_pool_decode_burn` | `POST /eth/v2/beacon/pool/attestations` | BLS G2 subgroup-check (~60 µs) | 5.81 s/req @ N=100k |
| `PRYSM_BLS_EXEC_CHANGE_DECODE_BURN` | `prysm_bls_exec_change_decode_burn` | `POST /eth/v1/beacon/pool/bls_to_execution_changes` | FULL BLS pairing verify (~616 µs, ~10× S1) | 6.16 s/req @ N=10k |
| `PRYSM_ATTESTER_SLASHING_PUBKEY_BURN` | `prysm_attester_slashing_pubkey_burn` | `POST /eth/v1/beacon/pool/attester_slashings_v2` | per-index pubkey deser + G1 subgroup-check (~23 µs cold) | 3.06 s/req @ N=131,072 (cold cache) |

- **Class:** compute-amplification DoS via unbounded REST decode + per-element crypto (`compute_amp`)
- **Reachability:** any remote client that can reach a non-loopback Beacon API port; no auth, no handshake
- **Severity:** availability-only DoS; **out of paid scope**, publish-track under NullRabbit's disclosure policy
- **Affected:** Prysm (`OffchainLabs/prysm`) HEAD as measured 2026-05-25/26; no CVE assigned
- **Mitigation:** `http.MaxBytesReader` body cap + spec-derived list/index cap + per-source rate-limit on the pool-submission endpoints. See Mitigation.

## Mechanism (source-cited, `OffchainLabs/prysm`)

Each endpoint is registered in `beacon-chain/rpc/endpoints.go` behind only `ContentTypeHandler` /
`AcceptHeaderHandler` / `AcceptEncodingHeaderHandler` — **no auth middleware and no body-size middleware.**

**1. `prysm_bls_pool_decode_burn` — `POST /eth/v2/beacon/pool/attestations`** (`SubmitAttestationsV2`,
`beacon-chain/rpc/eth/beacon/handlers_pool.go:132`). `json.NewDecoder(r.Body).Decode` reads an unbounded
`[]SingleAttestation` (no `MaxBytesReader` at :152; only a zero-length check at :209, no `> MAX_ATTESTATIONS`
cap). Each decoded element runs `bls.SignatureFromBytes` (G2 deserialize + subgroup-check, ~52 µs) in a
tight loop — so the per-element cost (~60 µs end-to-end) is paid on a **valid-shape** signature before any
aggregate verify. A random 96-byte signature fast-rejects at ~1.3 µs and does *not* reach the subgroup-check
— the amplification requires a real (published) block signature, which is public state.

**2. `prysm_bls_exec_change_decode_burn` — `POST /eth/v1/beacon/pool/bls_to_execution_changes`**
(`SubmitBLSToExecutionChanges`, `handlers_pool.go:600-668`). Same unbounded `[]SignedBLSToExecutionChange`
decode (no cap; spec bounds `MAX_BLS_TO_EXECUTION_CHANGES` at 16/block), but the per-element work is the
**full BLS pairing verify** via `signing.VerifySigningRoot` (`core/blocks/withdrawals.go:270`) — ~616 µs,
~10× finding 1. The SHA256 withdrawal-credentials gate at `withdrawals.go:117` does **not** filter an
attacker: validator pubkeys and withdrawal credentials are public mainnet state, so an attacker uses any
real validator's published pair to pass the gate, then a valid-format wrong-domain signature reaches (and
pays for) the pairing before it fails.

**3. `prysm_attester_slashing_pubkey_burn` — `POST /eth/v1/beacon/pool/attester_slashings_v2`**
(`SubmitAttesterSlashingsV2`, `handlers_pool.go:776`). One `AttesterSlashingElectra` per request, but
`VerifyIndexedAttestation` (`core/blocks/attestation.go:259`) loops over every `attesting_indices` entry
calling `bls.PublicKeyFromBytes` (G1 deserialize + subgroup-check) **before** the aggregate pairing
short-circuits. The only cap is the structural `IsValidAttestationIndices` ceiling of
`MAX_VALIDATORS_PER_COMMITTEE × MAX_COMMITTEES_PER_SLOT = 131,072` indices — and the `IsSlashableAttestationData`
double-vote gate before it is a pure data comparison, trivially satisfied by attacker-supplied
`AttestationData` with no key or signature work. Cold-cache cost ~23 µs/index (`crypto/bls/blst/public_key.go`
pubkey cache); an attacker sustains cold cache via recently-activated indices or a post-restart window.

## Measurement (fidelity: explicit)

Handler-level measurement on `OffchainLabs/prysm` HEAD, AMD Ryzen AI 9 HX 370, linear scaling validated:

| Finding | N | body | single-goroutine CPU/req | per-element |
|---|---|---|---|---|
| `prysm_bls_pool_decode_burn` | 100,000 | ~59 MB | **5.81 s** | ~60 µs |
| `prysm_bls_exec_change_decode_burn` | 10,000 | ~4.2 MB | **6.16 s** | ~616 µs |
| `prysm_attester_slashing_pubkey_burn` | 131,072 | ~2 MB | **3.06 s** (cold) / ~170 ms (warm) | ~23 µs cold / ~1.3 µs warm |

At single-host 1 Gbps, each sustains enough request rate to consume ~185–190 cores-worth of server CPU per
second — saturating standard 4–32-core validator hardware. The published corpus reproducers (primitives
`prysm_bls_pool_decode_burn`, `prysm_bls_exec_change_decode_burn`, `prysm_attester_slashing_pubkey_burn`;
family `compute_amp`, `source_class: original`, in `NullRabbit/nr-bundles-public`) capture the **attack
traffic** — a large, well-formed pool-submission POST against a local single-node Electra devnet, contrasted
with a small spec-cap-sized benign POST to the same endpoint. **This advisory stands on the source trace
and the handler-level measurement, not on the reproducer's devnet transport.**

## Scope

Availability / resource-cost only; no consensus-safety, no funds, no authentication break, no chain halt (a
healthy quorum keeps producing blocks; the harm is per-node CPU saturation of an exposed Beacon API). The
reproducers target a local self-owned single-node devnet, carry no public IPs or mainnet hostnames, and are
not a turnkey mainnet weapon. Loopback-bound Beacon APIs (the default) are not remotely reachable.

## Mitigation

- **Wrap `json.NewDecoder(r.Body)` on the pool-submission handlers with `http.MaxBytesReader`.** Spec-derived
  caps: attestations ≈ `MAX_ATTESTATIONS` (128) records; `bls_to_execution_changes` ≈
  `MAX_BLS_TO_EXECUTION_CHANGES` (16) records; attester-slashing `attesting_indices` far below the 131,072
  structural ceiling (a real slashing carries a small attesting set).
- **Add an explicit list-length / index-count check after unmarshal** — the 131,072 structural ceiling is a
  spec maximum, not a per-request expectation.
- **Rate-limit the pool-submission endpoints per source**, and consider auth-gating `attester_slashings` /
  `proposer_slashings` (real operator workflow rarely POSTs these; gossip handles propagation).
- A middleware-level body-size cap alongside the existing `ContentTypeHandler` chain would close the class
  across the REST surface.

## Disclosure & provenance

Availability-only, out-of-scope compute-amplification DoS on the public Beacon-API surface → **publish-track**
under NullRabbit's disclosure-scope policy. Vendor: **OffchainLabs / `OffchainLabs/prysm`** (notified;
coordinated-disclosure track for the separate, non-DoS Prysm findings is handled privately and is not part of
this advisory). NullRabbit original measurement; source-trace, per-finding measurement runs, and remediation
in `chains/ethereum/findings/PRYSM_BLS_POOL_DECODE_BURN/`,
`chains/ethereum/findings/PRYSM_BLS_EXEC_CHANGE_DECODE_BURN/`, and
`chains/ethereum/findings/PRYSM_ATTESTER_SLASHING_PUBKEY_BURN/`. Corpus primitives
`prysm_bls_pool_decode_burn`, `prysm_bls_exec_change_decode_burn`, and
`prysm_attester_slashing_pubkey_burn` are shipped in the public dataset `NullRabbit/nr-bundles-public`.
