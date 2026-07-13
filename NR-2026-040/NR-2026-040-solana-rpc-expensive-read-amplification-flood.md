# NR-2026-040 — Solana (Agave JSON-RPC): expensive-read + response-amplification + request-flood family on the operator-run RPC surface → availability DoS

**NullRabbit Operator Advisory** · Published 2026-07-13

## Summary

Agave's JSON-RPC surface exposes several **unauthenticated, operator-run read endpoints whose per-request cost
is bounded by ledger/account-store size rather than by the request, and whose response size is bounded by
on-chain data rather than by any pagination cap**. A remote caller can therefore turn a small, cheap request
into a large server-side read: a full account-store scan when a `getProgramAccounts` filter matches nothing
(`agave rpc.rs:2235-2251`), an unbounded account-set serialization when `getProgramAccounts` is called
unfiltered, an unbounded signature-history read from `getSignaturesForAddress`, and a ledger enumeration from
`getBlocks`/`getBlocksWithLimit`. Under sustained load these become **CPU-, memory-, and
request-capacity-exhaustion** vectors; the classic instance is the **September-2021 flood** in which a
sustained unauthenticated request flood congested the transaction/RPC ingress path. Agave's own
`SECURITY.md` **explicitly places RPC DoS and expensive reads out of scope** — RPC is an operator-run,
rate-limit-able, load-balancer-frontable surface — so this family is handled on NullRabbit's **publish-track**.
These are **availability-only** findings against the RPC node; the validator's consensus/TPU vote path is a
separate surface and is not implicated.

## Findings at a glance

| Finding | Primitive | Endpoint | Class | Severity |
|---|---|---|---|---|
| `SOL_GETSIGS_RESPONSE_AMP` | `sol_getsigs_response_amp` | `getSignaturesForAddress` | response-amplification DoS (expensive read) | MEDIUM |
| `SOL_GPA_COMPUTE_SCAN` | `sol_gpa_compute_scan` | `getProgramAccounts` (filter-miss) | compute-amplification DoS (expensive read) | MEDIUM |
| `SOL_GPA_RESPONSE_AMP` | `sol_gpa_response_amp` | `getProgramAccounts` (unfiltered) | response-amplification DoS (expensive read) | MEDIUM |
| `SOL_RPC_REQUEST_FLOOD` | `sol_rpc_request_flood` | TPU / RPC ingress | connection/request-capacity exhaustion DoS | MEDIUM |
| `SOL_GETBLOCKS_ENUM_SCAN` | `sol_getblocks_enum_scan` | `getBlocks` / `getBlocksWithLimit` | ledger-enumeration expensive read / reconnaissance | LOW |

- **Reachability:** any remote host that can reach the RPC (or TPU ingress) port; no auth, no signed request, a
  single caller suffices to trigger the expensive-read cases.
- **Severity:** MEDIUM for the three amplification/compute vectors and the request-flood; LOW for the ledger
  enumeration (primarily reconnaissance + expensive-read pressure). All **out of paid scope** per Agave's own
  `SECURITY.md`, publish-track. Ceiling is RPC-node availability, **not** a consensus break or a validator halt.
- **Affected:** Agave JSON-RPC (`getProgramAccounts`, `getSignaturesForAddress`, `getBlocks`/
  `getBlocksWithLimit`) and the RPC/TPU request-ingress path.
- **Mitigation:** per-method / per-caller rate limits, response-size caps, pagination bounds, gating or
  disabling the expensive methods on public endpoints, and running RPC on dedicated nodes off the validator
  identity. See Mitigation.

## Mechanism (source-cited, `anza-xyz/agave`)

- **`getProgramAccounts` filter-miss → full account-store scan (`SOL_GPA_COMPUTE_SCAN`).** In
  `rpc/src/rpc.rs:2235-2251`, `get_program_accounts` walks the program's account set and applies the
  caller-supplied `filters` (data-size / memcmp) **as a post-scan predicate**. A filter crafted to match
  nothing does not short-circuit the walk — the node still enumerates and evaluates the full candidate account
  store before returning an empty (or tiny) result. The server-side compute is bounded by the store size, not
  by the request or the response. This is **compute amplification**: cheap request → large server-side scan.

- **`getProgramAccounts` unfiltered → unbounded response (`SOL_GPA_RESPONSE_AMP`).** The same handler, called
  with no (or a broad) filter against a large program, serializes the **entire** matching account set into the
  response. There is no built-in pagination or hard response cap in the RPC layer; response bytes scale with
  the program's on-chain account footprint. Agave's `SECURITY.md` calls this out by name as an expensive read
  that operators are expected to rate-limit or disable. This is **response amplification**: small request →
  large response + large server-side serialization cost.

- **`getSignaturesForAddress` unbounded-history read (`SOL_GETSIGS_RESPONSE_AMP`).** The signatures-for-address
  handler reads confirmed-signature history for an address. A caller requesting a hot/high-cardinality address
  pulls a large signature set per request; the response (and the underlying index/ledger read) scale with the
  address's history rather than with the request. This is the same **response-amplification** expensive-read
  class — the request is a few bytes, the response and its backing read are not.

- **RPC / TPU request-flood congestion (`SOL_RPC_REQUEST_FLOOD`).** A sustained flood of unauthenticated
  requests against the RPC/TPU ingress path exhausts request-handling capacity (sockets, worker threads, the
  request queue) before any per-request cost even matters. This is the **connection/request-capacity
  exhaustion** class — the same root-cause family as the September-2021 network congestion event, whose RCA
  centered on unbounded unauthenticated ingress. The subsequent QUIC + stake-weighted QoS work on TPU is the
  upstream hardening for the vote/transaction ingress; the plain JSON-RPC surface still relies on the operator
  to impose admission control.

- **`getBlocks` / `getBlocksWithLimit` ledger enumeration (`SOL_GETBLOCKS_ENUM_SCAN`).** These enumerate
  confirmed block ranges from the ledger. A wide range (or repeated ranges) drives an expensive ledger read and
  yields a bulk enumeration useful for reconnaissance of the node's ledger extent. Lower impact than the
  amplification vectors, but the same operator-side-cost-unbounded-by-request shape.

## Measurement (fidelity: explicit)

Each finding ships as a **corpus reproducer that captures the RPC attack WIRE signature** — the request/response
pattern that characterizes the expensive read, the amplification, or the flood — across postures. The
reproducers stand on the request patterns and the source paths above (notably `rpc.rs:2235-2251` for the
filter-miss scan); they are **not** claims of a measured full-node OOM or a measured latency curve.

- **`SOL_GETSIGS_RESPONSE_AMP`:** the quoted **~224×** is **our measurement of the response-size ratio** — bytes
  returned versus bytes requested for an unbounded-history `getSignaturesForAddress` call — captured in the
  reproducer. It is a response-amplification ratio, **not** a claimed node-crash factor.
- **`SOL_GPA_RESPONSE_AMP` / `SOL_GPA_COMPUTE_SCAN`:** the reproducers capture the unfiltered / filter-miss
  request shapes that force the unbounded serialization and the full-store scan respectively; the compute-scan
  case is anchored to the post-scan-predicate code path at `rpc.rs:2235-2251`.
- **`SOL_RPC_REQUEST_FLOOD`:** the reproducer captures the sustained unauthenticated request-flood pattern (the
  September-2021-class ingress congestion signature), not a live production-node saturation number.
- **`SOL_GETBLOCKS_ENUM_SCAN`:** the reproducer captures the wide-range ledger-enumeration request pattern.

No latency or throughput figure is asserted beyond the response-size ratio above; where this advisory needs a
number, it is the measured amplification ratio, nothing more.

## Scope

Availability only, against the **RPC node**: CPU (full-store scans), memory / egress (unbounded responses), and
request capacity (flood). No consensus-safety break, no funds, no authentication bypass, no validator halt. The
validator's consensus and TPU vote path is a **separate** surface: RPC is typically fronted by an operator load
balancer and run on dedicated read nodes, and a public RPC endpoint that imposes per-method rate limits,
response-size caps, pagination bounds, and admission control is not affected. The reproducers target local
self-owned mocks, carry no public IPs or mainnet hostnames, and are not turnkey mainnet weapons.

## Mitigation

- **Front the RPC with per-method / per-caller rate limits** and an admission-control tier (reverse proxy or
  RPC gateway) so a single caller cannot force unbounded server-side work.
- **Cap response size and enforce pagination bounds** on `getProgramAccounts` and `getSignaturesForAddress`;
  reject or paginate unbounded-history / unfiltered requests.
- **Disable or gate the expensive methods on public endpoints** — restrict `getProgramAccounts` (and, where
  feasible, unbounded `getSignaturesForAddress` / wide-range `getBlocks`) to authenticated / allowlisted
  callers.
- **Run RPC on dedicated nodes off the validator identity**, so RPC-surface exhaustion cannot bleed into the
  consensus/vote path.
- **Apply the September-2021-class ingress hardening:** QUIC + stake-weighted QoS on the TPU path and explicit
  RPC admission control / connection caps at the ingress, so an unauthenticated flood cannot exhaust
  request-handling capacity.

## Disclosure & provenance

Availability-only, deployment/rate-limit-mitigable expensive-read, response-amplification, and request-flood
vectors on an **operator-run, unauthenticated RPC surface**. Agave's own `SECURITY.md` **explicitly lists RPC
DoS and expensive reads as out of scope** — the RPC surface is expected to be rate-limited and fronted by
operator infrastructure — so this family is **out of paid scope → publish-track** under NullRabbit's
disclosure-scope policy. These are our own measurements (`source_class: original`) of the Agave RPC
expensive-read / amplification / flood classes — not assigned CVEs and not novel implementation flaws of ours.

All five corpus primitives — `sol_getsigs_response_amp`, `sol_gpa_compute_scan`, `sol_gpa_response_amp`,
`sol_rpc_request_flood`, and `sol_getblocks_enum_scan` — are **on-spec** (registered in the known-class
provenance map) and **on-HF** (shipped in the `NullRabbit/nr-bundles-public` dataset, registered in
`HF_DATASET_PRIMITIVES`), so this advisory does not outpace its shipped defensive artefacts.
