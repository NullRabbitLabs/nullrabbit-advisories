# NR-2026-036 — Internet Computer (replica ingress pool): per-`NodeId` quota mis-keyed to the carrier replica → public flood purges all legitimate ingress

**NullRabbit Operator Advisory** · Published 2026-07-09

## Summary

The Internet Computer replica's **ingress pool** enforces a per-peer quota
(`ingress_pool_max_count = 10000`, `ingress_pool_max_bytes = 100 MB`) intended to stop one noisy peer from
saturating ingress. The quota is keyed on `NodeId` — but for **HTTP-arriving** ingress the replica inserts
every message with `node_id = self.node_id`, **the carrier replica's own `NodeId`**, not the signing
principal (`rs/http_endpoints/public/src/call.rs:391`; the pool object then keys on that at
`rs/artifact_pool/src/ingress_pool.rs:240-242`). So **all** HTTP-arriving ingress on a replica buckets into a
**single shared quota** regardless of who signed it. Once that shared bucket trips `exceeds_limit`
(`ingress_pool.rs:226-232`, strict `>`), the ingress handler returns `RemoveFromUnvalidated` for the peer,
which — because every HTTP message shares the carrier `NodeId` — purges **all unvalidated HTTP-arriving
ingress** at the next `on_state_change` (~200 ms cadence, `ingress_handler.rs:60-76`). An unauthenticated
attacker who submits **10 001** valid signed ingress messages fills the bucket and repeatedly wipes every
legitimate user's in-flight ingress on that replica. The IC team's own `TODO` at
`rs/interfaces/src/ingress_pool.rs:22-25` acknowledges the mis-key. This is a **public-reach availability**
DoS; it is a quota-correctness/hardening class, **out of paid scope**, handled on NullRabbit's publish-track.

## Findings at a glance

| Finding | Primitive | Endpoint | Class | Severity |
|---|---|---|---|---|
| `IC_N1_INGRESS_POOL_QUOTA_MISKEY` | `ic_ingress_pool_quota_miskey` | `POST /api/v2/canister/<id>/call` (HTTP ingress) | `quota-miskey` + `http-tier` | HIGH |

- **Reachability:** **PUBLIC** — any HTTP client can submit valid signed ingress; no special role, no SOL/ICP
  balance beyond fees, no completed session.
- **Severity:** HIGH — 100 % of unvalidated HTTP-arriving ingress on the targeted replica is purged for as
  long as the attacker sustains the fill rate; parallelises across a subnet's replicas for
  ~40 MB total bandwidth on a 40-replica subnet; **out of paid scope**, publish-track.
- **Affected:** `dfinity/ic` replica ingress pool / HTTP call endpoint (source-traced at HEAD; measured against
  production caps 10000 / 100 MB).
- **Mitigation:** key the ingress quota on the **signing principal** (extract the signer from the signed
  ingress envelope), exactly as the in-repo `TODO` prescribes. See Mitigation.

## Mechanism (source-cited, `dfinity/ic`)

- **The mis-key.** `call.rs:391` sends every HTTP-arriving ingress down `ingress_tx` with
  `node_id = self.node_id` (the carrier replica's own id, set at `call.rs:104`) rather than the originating
  principal. `ingress_pool.rs:240-242` constructs the pool object with that `peer_id`; the per-peer counters
  (`peer_counter.rs:42-74`) therefore accumulate all HTTP ingress under one key.
- **The trip.** `exceeds_limit` (`ingress_pool.rs:226-232`) compares that shared bucket against
  `ingress_pool_max_count` / `ingress_pool_max_bytes` with a strict `>` — so exactly 10000 does **not** trip,
  and message 10 001 does.
- **The purge.** `ingress_handler.rs:60-76` — when `exceeds_limit` is true for a peer, the handler removes
  **all** unvalidated ingress originating from that peer at the next `on_state_change`. Since every HTTP message
  shares the carrier `NodeId`, that is **all** unvalidated HTTP ingress, including legitimate users' messages
  submitted in the same window.
- **Vendor acknowledges it.** `interfaces/src/ingress_pool.rs:22-25` carries a `TODO` to derive `originator_id`
  from the signature — which is available at the HTTP boundary (`HttpRequestEnvelope` carries `sender_sig`) but
  is not threaded through.

## Measurement (fidelity: explicit)

An in-process Rust harness instantiating `IngressPoolImpl` at the **exact production caps** (10000 messages /
100 000 000 bytes) and driving the real `insert` / `exceeds_limit` path:

- **Boundary confirmed:** 10000 HTTP-shape inserts → not over (strict `>`); **10001 → `exceeds_limit(carrier)`
  = true**, in **0.04 s** for 30 003 inserts across the three tests (release mode).
- **Principal-diversity is irrelevant:** inserts with deliberately diverse payloads/principals but the same
  carrier `peer_id` all bucket together — the quota does not distinguish signers.
- **Attacker cost:** one keypair signs 10 001 small (~250 B) messages; sub-second CPU + ~1 MB bandwidth per
  replica. Sustaining the wipe ≈ 50 000 signed-ingress/s (10 k per 200 ms cycle), ~100 Mbit/s at ~250 B/msg —
  feasible from a single host. Parallel across a 40-replica subnet ≈ 40 MB total.

The published corpus reproducer (primitive `ic_ingress_pool_quota_miskey`; `source_class: original`, shipped in
`NullRabbit/nr-bundles-public`) captures the **attack traffic** — a burst of small HTTP `POST
/api/v2/canister/<id>/call` requests each carrying a ~250 B signed-ingress-shaped envelope, across postures
(single-source low-volume/saturating, distributed across source IPs, paced mimicry); the flood count is scaled
for capture speed with the true 10001/0.04 s boundary preserved in bundle provenance. **This advisory stands on
the source trace (HTTP ingress keyed on the carrier `NodeId`, vendor `TODO` confirming it) and the
production-cap boundary measurement — not on the reproducer traffic alone.**

## Scope

Availability only (legitimate HTTP ingress purged on the targeted replica; subnet-wide by parallelisation).
No authentication bypass (the attacker uses genuinely valid signed messages), no funds, no state corruption,
no consensus halt — subnet liveness continues on already-validated work; the harm is that new user
transactions cannot land while the attack runs. The reproducer targets a local self-owned mock, carries no
public IPs or mainnet hostnames, and is not a turnkey mainnet weapon.

## Mitigation

- **Key the quota on the signer.** Extract the signing principal from the signed ingress envelope and use it as
  `originator_id`, exactly as the in-repo `TODO` at `interfaces/src/ingress_pool.rs:22-25` prescribes — a 1–3
  line change at `call.rs:391` to thread the signer through, plus the bookkeeping. This restores per-principal
  isolation so one submitter cannot evict another's ingress.
- **Interim, per-source-IP / per-principal admission limiting** at the boundary node in front of the replica
  bounds the fill rate an attacker can sustain (a rate cap, not a fix for the mis-key itself).

## Disclosure & provenance

Public-reach but availability-only, quota-correctness/hardening-mitigable ingress DoS →
**out of paid scope → publish-track** under NullRabbit's disclosure-scope policy. Vendor: **DFINITY
(`dfinity/ic`)**; this is our own (`source_class: original`) measurement of the ingress-pool quota mis-key
(which the vendor's own `TODO` already names), not a novel implementation flaw of ours or an assigned CVE. The
corpus primitive `ic_ingress_pool_quota_miskey` is **on-spec** (registered in the known-class provenance map)
and **on-HF** (shipped in `NullRabbit/nr-bundles-public`), so this advisory does not outpace its shipped
defensive artefact.
