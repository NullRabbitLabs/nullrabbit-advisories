# NR-2026-026 - Prysm beacon/validator-API: unauthenticated-write and fork-choice-integrity findings

**NullRabbit Operator Advisory** · Published 2026-07-08

## Summary

A focused pass over Prysm's HTTP Beacon and Validator API surface turned up four findings that are not
denial-of-service issues: three let an unauthenticated caller write state the node treats as trusted, and
one is a validator-API auth-middleware bypass that upstream has since fixed. Each is measured or
source-confirmed against `OffchainLabs/prysm` HEAD on the dates given below.

All four share one operator-decision surface: they are only remotely reachable if the operator binds the
Beacon API or the validator web API to a non-loopback interface. Prysm's default `--http-host` is
`127.0.0.1`; a loopback-bound API is not remotely reachable and is not affected. Operators who expose these
APIs beyond loopback (for monitoring, block-explorer, staking-indexer, MEV-relay, or split
validator-client deployments) without a reverse proxy that authenticates in front should treat this
advisory as action-relevant.

## Disclosure posture

These four are published as a plain operator advisory. A 2026-07-08 operator scope call placed them outside
the consensus-layer bounty scope (beacon/validator-API surface, single-node effect, or already-fixed
upstream), so there is no coordinated embargo on them and nothing to hold. One further, separate
fork-choice finding (a non-monotonic `unrealizedJustifiedCheckpoint` rewrite) is on a coordinated
disclosure track with the Ethereum Foundation and is deliberately not described here.

## Findings at a glance

| # | Finding | Endpoint | Class | Severity |
|---|---|---|---|---|
| 1 | Fee-recipient cache overwrite | `POST /eth/v1/validator/prepare_beacon_proposer` | auth-boundary + fee redirect | Critical |
| 2 | Unverified blob accepted as verified | `POST /prysm/v1/beacon/blobs` | auth-boundary + storage-invariant break | Critical |
| 3 | Fork-choice vote overwrite via unverified attestation | `POST /eth/v2/beacon/pool/attestations` | consensus-integrity, verification elision | High |
| 4 | Validator API auth-middleware bypass | `/v2/validator/*` | auth bypass (fixed in v7.1.3) | High exposed / Medium loopback |

Affected: `OffchainLabs/prysm`, measured/source-confirmed at HEAD on the per-finding dates. No CVE assigned
to findings 1-3; finding 4 was fixed upstream in v7.1.3 with no GHSA filed.

## Findings

### Finding 1: Fee-recipient cache overwrite (Critical)

`POST /eth/v1/validator/prepare_beacon_proposer` is registered in `beacon-chain/rpc/endpoints.go` behind
only the content-type and accept-header middleware: no auth, no ownership proof, no rate limit, no
body-size cap. The handler `PrepareBeaconProposer` (`beacon-chain/rpc/eth/validator/handlers.go:797-835`)
validates only that `validator_index` is a uint and `fee_recipient` is a correctly-sized hex string, then
writes each `(validator_index, fee_recipient)` tuple into `TrackedValidatorsCache` unconditionally.

At block-proposal time the beacon node reads that cache to set the execution-layer
`suggested_fee_recipient` (`beacon-chain/rpc/prysm/v1alpha1/validator/proposer_execution_payload.go:84`).
An attacker who reaches the endpoint can therefore set the fee recipient for any active validator index,
and whatever value is in the cache when the node builds the block becomes the on-chain fee recipient. The
honest validator client only re-pushes its fee recipients once per slot, so an attacker spraying the
endpoint races that per-slot push and wins some fraction of proposals outright, redirecting that block's
priority fees and MEV.

Confirmed empirically 2026-05-29 on Prysm v7 in a Kurtosis Electra devnet: at a 200 ms attacker cadence
against the honest per-slot push, 3 of 10 consecutive proposals (30 percent) carried the attacker's fee
recipient, across three distinct proposer indices. The beacon node's own metrics and debug log confirmed
the attacker writes reached the cache.

**Mitigation.** Require an `Authorization` header on `prepare_beacon_proposer` (a bearer token shared with
the validator client), or require a BLS signature over the request body proving control of the validator
key; and make cache writes commit-or-reject rather than race the validator-client push. Operators today
should bind the validator API routes to loopback or place an authenticating reverse proxy in front.

### Finding 2: Unverified blob accepted as verified (Critical)

`POST /prysm/v1/beacon/blobs` (`PublishBlobs`, `beacon-chain/rpc/prysm/beacon/handlers.go:190`) is
registered with no auth and no body-size cap. The handler calls `NewVerifiedROBlob`
(`consensus-types/blocks/roblob.go:96-104`), whose own doc comment says it should only be used by the
verification package: it is a type coercion that does no work, not a verification. No KZG proof, inclusion
proof, block-signature, proposer, subnet, or slot check runs. The handler then saves the blob through
`BlobReceiver.ReceiveBlob` into `BlobStorage`, whose `Get` contract
(`beacon-chain/db/filesystem/blob.go:254-256`) documents that storage only ever holds verified blobs, and
broadcasts it over gossipsub.

Two impacts follow. First, the node's own gossipsub broadcast of an invalid blob is rejected by peers, who
apply invalid-message peer-scoring penalties to the broadcasting node. Prysm's app-level bad-peer threshold
(`beacon-chain/p2p/peers/scorers/gossip_scorer.go:14`) is -100, and a single invalid blob delivery reaches
about -112 on the blob-sidecar topic, so one unauthenticated request can drive the operator's node toward
self-disconnect from its peers. A mixed-client devnet test on 2026-05-27 showed the attacked node's peer
count fall from 5 to 3 within 12 seconds as neighbouring clients transport-rejected the invalid blob.

Second, the blob's storage identity and the pruner floor are computed from the attacker-supplied slot. The
handler bounds the slot only by fork epoch, and with the upper fork epoch effectively unbounded an attacker
can claim a far-future slot. That pushes the pruner floor far above the current head and the async pruner
deletes older blobs. Confirmed 2026-05-29: a single request with a far-future slot drove the pruner to
delete all 20 of 20 planted blobs, matching the source-traced floor arithmetic exactly. For a
data-availability or archive node this is destructive deletion of retained blob history.

**Mitigation.** Run the real verification path (`newBlobVerifier` with the gossip requirements) before save
and broadcast; add auth and a body-size cap on the endpoint; compute the pruner-relevant epoch from the
current head, not from the attacker-supplied header slot; and reconsider whether this transitional endpoint
needs to exist for current operators.

### Finding 3: Fork-choice vote overwrite via unverified attestation (High)

`POST /eth/v2/beacon/pool/attestations` (`SubmitAttestationsV2`,
`beacon-chain/rpc/eth/beacon/handlers_pool.go:130-193`) parses a submitted attestation's signature with
`bls.SignatureFromBytes`, which is a format parse, not a pairing verify. The attestation flows through the
pool into fork-choice, and `OnAttestation` (`beacon-chain/blockchain/process_attestation.go:40-106`)
explicitly skips signature verification, with a source comment stating it assumes the caller already
verified (true for gossip-received attestations, which pass the gossip validator first, but false for
REST-injected ones). `ForkChoice.ProcessAttestation`
(`beacon-chain/forkchoice/doubly-linked-tree/forkchoice.go:86-109`) then writes
`f.votes[index].nextRoot` to the attacker-chosen block root.

The result is that an unauthenticated caller with no validator keys and no valid signatures can overwrite
the fork-choice latest-message vote of honest validators on a target node. Confirmed 2026-05-29 with a
debug-instrumented build (logging only) on Prysm v7.1.4: 54 vote-overwrite events across 50 distinct
validators were observed directly, each replacing an honest root with the single attacker-chosen root.

Scope of the claim, stated honestly: what is proven is the per-validator fork-choice vote overwrite. Whether
an achievable overwrite fraction is large enough to diverge a node's head (orphaned proposals,
inactivity-leak risk) is not demonstrated and is not claimed. The overwrite is a per-validator race won
only at that validator's own attestation slot, and the head-divergence question depends on a weighted
hijack fraction we did not measure. Severity is set to the confirmed floor, not the feared ceiling.

**Mitigation.** Verify the attestation signature before it can reach fork-choice: either add a BLS
pair-verify in the REST submit handler before the pool insert, or make the `OnAttestation` invariant
explicit so every caller path is required to have verified. The cost is one verify per submitted
attestation, acceptable for the observed volume.

### Finding 4: Validator API auth-middleware bypass (High exposed / Medium loopback, fixed in v7.1.3)

Included for operator awareness and completeness; upstream has already fixed this. In releases up to and
including v7.1.2, the `AuthTokenHandler` middleware (`validator/rpc/intercepter.go:41`) gated only requests
whose path contained the web-API prefix (`/api/v2/validator/`) or the keymanager prefix (`/eth/v1`). The
actual handler routes are registered at a different prefix (`/v2/validator/`,
`api/constants.go:4-6`), and a catch-all that strips `/api` and re-dispatches
(`validator/rpc/server.go:164-173`) meant every handler registered at the web prefix was reachable without
auth by hitting the direct, un-prefixed path.

That exposed 15 admin-class endpoints without auth, including account key backup (client-supplied password
returns keystores), voluntary exit for any managed pubkey, slashing-protection import (which can induce a
slashable double-sign), and wallet recover. Reachability depends on operator config: loopback-only by
default (Medium), directly reachable for operators who bind a non-loopback host (High), and unaffected
behind a reverse proxy that authenticates first.

Confirmed 2026-05-24 by a binary differential test on the middleware path: the direct `/v2/validator/*`
cases execute the wrapped handler without an `Authorization` header on the pre-fix commit, and are rejected
with 401 on the post-fix commit. Fixed upstream in `OffchainLabs/prysm#16226`, released in v7.1.3; no GHSA
was filed, so this is public-by-PR rather than novel disclosure. Operators running v7.1.2 or earlier should
upgrade.

This is one instance of a general pattern worth checking on any node with a web/admin API: an auth
middleware that allow-lists by a path-prefix string while the routes are registered under a different
prefix that the middleware does not enumerate.

## Scope

All four findings are only remotely reachable when the operator binds the affected API to a non-loopback
interface; the loopback default is not remotely reachable. Findings 1-3 are single-node effects: they bias
or redirect state on the exposed node, and a healthy network quorum keeps producing and finalising blocks.
Finding 3 does not demonstrate head divergence or any finality impact, and none is claimed. This advisory
carries source citations and measured results, not a turnkey attack tool; it does not target any live
network, and the measurements were run against local self-owned Kurtosis devnets with no public addresses.

## Mitigation summary

- Bind the Beacon API and validator web API to loopback, or place a reverse proxy that authenticates in
  front of them; do not expose these routes to untrusted networks.
- Upgrade to Prysm v7.1.3 or later to close finding 4.
- Vendor-side, the through-line for findings 1-3 is the same: do not treat unauthenticated REST input as
  trusted or pre-verified. Authenticate the write endpoints, and run the real verification before state is
  written or broadcast.

## Provenance

NullRabbit original research and measurement against `OffchainLabs/prysm`. Findings 1-3 are our own
measurement of unauthenticated-write and consensus-integrity defects; finding 4 is a source-confirmed
replication of an already-public upstream fix (`OffchainLabs/prysm#16226`). The availability /
compute-amplification findings on the same Beacon-API pool surface are published separately in NR-2026-022.
Vendor: OffchainLabs (`OffchainLabs/prysm`). Contact: simon@nullrabbit.ai.

<!--
NullRabbit registry cross-reference (findings covered by this advisory, in order):
  1 PRYSM_FEE_RECIPIENT_RACE_HIJACK
  2 PRYSM_PUBLISH_BLOBS_FAKE_VERIFICATION
  3 PRYSM_REST_ATTESTATION_FORKCHOICE_OVERRIDE
  4 PRYSM_VALIDATOR_API_AUTH_BYPASS
-->

