# NR-2026-051 — Sui bridge validator signing server: unauthenticated, unthrottled signing port (availability)

**NullRabbit Operator Advisory** · Published 2026-07-15

## Summary

The **Sui bridge** validator **signing server** (`sui-bridge/src/server/mod.rs`, an `axum` HTTP service)
binds a deployment-supplied socket address (deployed `0.0.0.0`) and exposes its signing routes over
**plain, unauthenticated HTTP GETs** with **no per-source-IP rate limit, no `tower` `ConcurrencyLimit`/
`Timeout`, and no firewall to the committee CIDRs** — the router's only `.layer()` is
`reject_oversized_requests` (a request-body size check, inert against GET floods). Each GET to the signing
route `/sign/bridge_tx/eth/sui/{tx_hash}/{event_index}` dispatches `handle_eth_tx_hash`, which performs
**backend eth-RPC round-trips** to fetch and verify the referenced transaction/event *before* signing. So an
unauthenticated attacker converts one cheap ~100-byte HTTP GET into backend verification work on the signer;
with no admission gate a sustained request flood exhausts the signer's request-handling capacity. Denying
enough committee signers from assembling the signing threshold **halts bridge transfer signing**.
Availability/censorship only, on NullRabbit's publish-track.

## Findings at a glance

| Finding | Primitive | Chain | Class | Severity |
|---|---|---|---|---|
| `BRIDGE_SIGN_PORT_DOS` | `sui_bridge_sign_port_unauth_flood` | sui | `service-misconfig` (unauth, unthrottled signing port) | HIGH |

- **Reachability:** any host that can reach the bridge validator's signing-server port (deployment-configured,
  bound `0.0.0.0` in-repo) — no credentials, no committee membership, no valid transaction reference needed.
- **Severity:** HIGH availability — an unauthenticated request flood on the signing port exhausts signer
  request-handling capacity and can deny assembly of the committee signing threshold (bridge signing halt).
  **Bounded and recoverable:** it is a **censorship/availability** lever only — the port is the *inbound
  signing-request* path, **not** the *outbound eth-RPC read* the signer trusts, so it **cannot induce a false
  signature**; denying threshold assembly requires a large fraction (~63%) of committee signing power to be
  degraded simultaneously, and signing recovers when the flood stops. **Out of paid scope**, publish-track.
- **Affected:** Sui bridge validator (`sui-bridge`, `src/server/mod.rs` `run_server` → `axum` router) as
  deployed with the signing port reachable beyond the committee network. Deployments that firewall the
  signing port to committee CIDRs and/or front it with a rate limiter are not exposed.

## Mechanism (source-cited)

- `run_server` (`sui-bridge/src/server/mod.rs`) builds an `axum::Router` and serves it on a caller-supplied
  `SocketAddr` via `tokio::net::TcpListener::bind(...)` — deployed `0.0.0.0`, no TLS/auth wrapper.
- The router registers the signing routes (`/ping`, `/metrics_pub_key`,
  `/sign/bridge_tx/eth/sui/{tx_hash}/{event_index}`, `/sign/bridge_tx/sui/eth/{tx_digest}/{event_index}`, and
  the governance-action signing routes) as bare `get(handler)` entries. The **only** middleware layer is
  `reject_oversized_requests` (a body-size guard); there is **no authentication layer, no per-IP rate limit,
  no `tower` `ConcurrencyLimit`, and no `Timeout`**.
- `handle_eth_tx_hash` → `BridgeRequestHandlerTrait::handle_eth_tx_hash` performs **backend eth-RPC
  round-trips** (the source trace counts ~2 per request) to fetch and verify the referenced tx/event before
  producing a signature. So each unauthenticated GET amplifies into backend verification work on the signer.

An attacker floods unauthenticated GETs to the signing route with attacker-chosen (unverified) transaction
references (`connect → GET /sign/bridge_tx/eth/sui/<random 32B hash>/0 → repeat`); with no admission gate the
signer performs backend work per request until its request-handling capacity is saturated. (The unrelated
HTTP/2 rapid-reset vector on this service is separately **defended** by the pinned `h2 0.4.13`.)

## Measurement (fidelity: explicit)

The **unauthenticated signing-port request-flood traffic** is captured (fresh HTTP/1.1 connections each
issuing the byte-identical bridge signing GET) against a **loopback reproducer that serves the real signing
routes** and models the per-request backend eth-RPC verification cost — **without** standing up a full bridge
node + eth-RPC backend. Bundles `sui_bridge_sign_port_unauth_flood` (saturating + distributed) ship in
`NullRabbit/nr-bundles-public`; the captured requests carry the real route paths and a ~2× backend-RPC
work-amplification per request. **Honest split:** this is **source-confirmed** (the router has no
auth/rate-limit/concurrency layer, binds `0.0.0.0`, and the signing handler runs backend eth-RPC per request)
plus **class-representative captured traffic** — it is **not** an independent measurement of a live bridge
committee's signing-quorum halt, which depends on the committee's deployed exposure and signing-power
distribution.

## Scope

Availability/censorship only — unauthenticated request-flood exhaustion of the signer's request-handling
capacity. **No signature forgery** (the port is the inbound signing-request path, not the outbound eth-RPC
read the signer verifies against), no funds movement, no consensus-safety break, no memory corruption. The
reproducer targets a self-owned loopback mock, carries no public IPs or mainnet hostnames, and is not a
turnkey mainnet weapon.

## Mitigation

- **Firewall the signing port to the committee/infrastructure CIDRs** — the signing server is an
  internal committee service and should never be reachable from the public internet.
- **Add per-source-IP rate limiting and a `tower` `ConcurrencyLimit` + `Timeout`** in front of the signing
  routes so one source cannot saturate the signer's request-handling / backend-RPC capacity.
- **Bind the signing server to a non-`0.0.0.0` address** (loopback / private interface) by default and
  require explicit operator opt-in for any wider exposure.

## Disclosure & provenance

Availability-only, deployment/hardening-mitigable exposure of an unauthenticated, unthrottled internal
signing service → **out of paid scope → publish-track** under NullRabbit's disclosure-scope policy. Vendor:
Mysten Labs (`MystenLabs/sui`, `sui-bridge`). This is our own (`source_class: original`) source trace +
class-representative captured traffic of the unauthenticated signing-port request flood, not an assigned CVE.
The corpus primitive `sui_bridge_sign_port_unauth_flood` is **on-spec** and **on-HF** (shipped in
`NullRabbit/nr-bundles-public`), so this advisory does not outpace its shipped defensive artefact.
