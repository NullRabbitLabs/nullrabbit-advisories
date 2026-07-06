# NR-2026-013 — Cardano `cardano-submit-api`: no request-body-size cap → memory exhaustion

**NullRabbit Operator Advisory** · Published 2026-07-06

## Summary

`cardano-submit-api` (the HTTP transaction-submission service shipped with
`cardano-node`) starts its Warp HTTP server with **no request-body-size limit**, so
an unauthenticated `POST /api/submit/tx` with an oversized body is **buffered whole
in memory before it is rejected**. NullRabbit measured **~500 MB resident memory
pinned per request**; a modest number of concurrent oversized submissions (~32 ×
500 MB ≈ 16 GB) OOM-kills the service on commodity validator infrastructure. It is
an availability issue only — no funds or consensus impact.

## Findings at a glance

| Item | Detail |
|---|---|
| Class | Missing HTTP body-size cap → memory exhaustion (`memory_amp`) |
| Reachability | Remote, unauthenticated, public `cardano-submit-api` HTTP endpoint |
| Trigger | `POST /api/submit/tx` with an attacker-chosen oversized body |
| Measured | ~500 MB RSS pinned per request; N concurrent → OOM (≈32 × 500 MB ≈ 16 GB) |
| Severity | Medium (single-host remote memory exhaustion; deployment-dependent) |
| Affected | `cardano-node` `cardano-submit-api` with default Warp settings |
| Mitigation | Enforce a request-body-size limit at the Warp layer (reject early on `Content-Length` / streamed size) and/or front the service with a body-capping reverse proxy. See Mitigation |

## Mechanism (source-cited)

`cardano-submit-api/src/Cardano/TxSubmit/Rest/Types.hs:21`:

```haskell
toWarpSettings :: WebserverConfig -> Warp.Settings
toWarpSettings WebserverConfig {wcHost, wcPort} =
  Warp.defaultSettings & Warp.setHost wcHost & Warp.setPort wcPort
```

`toWarpSettings` chains only `setHost` and `setPort` onto `Warp.defaultSettings`;
there is **no body-size limit** configured. Warp's defaults do not impose a
request-body cap — the application must enforce one, and here it does not. The
submission handler buffers the full body before attempting to decode/reject it, so
memory scales with attacker-supplied body size regardless of the transaction being
invalid.

## Reproduction (fidelity: explicit)

The memory-pin is a server-side effect that scales with body size. The published
corpus reproducer (`chains/cardano/lab/drivers/known_class_cardano_body.py`,
primitive `cardano_submit_api_body_memory_pin` in `NullRabbit/nr-bundles-public`)
captures the wire signature — a single large `POST /api/submit/tx` with a huge
`Content-Length` + body streamed to a no-cap listener — using a **representative
scaled body** (16 MB); every bundle stamps `provenance.wire_fidelity =
"scaled_body_representative"` and records the measured ~500 MB RSS in
`attack_parameters`. **This advisory stands on the source trace above and the
measurement, not on the reproducer's scaled body size.**

## Mitigation

- **Set a Warp body-size limit** (or reject on `Content-Length` above a threshold)
  in `toWarpSettings` — a submitted transaction has a well-bounded maximum size, so
  the cap can be tight.
- **Front with a reverse proxy** (nginx `client_max_body_size`, etc.) that rejects
  oversized bodies before they reach the service.
- Bind `cardano-submit-api` to a trusted interface where the deployment permits.

## Disclosure & provenance

Availability-only finding (no funds/consensus impact). DoS/availability on the
`cardano-submit-api` HTTP surface is publish-track under NullRabbit's
disclosure-scope policy. Vendor: IntersectMBO / IOG. NullRabbit measurement;
source-trace and measurement in `chains/cardano/findings/CARDANO_SUBMIT_API_BODY`.
Corpus primitive `cardano_submit_api_body_memory_pin` shipped in
`NullRabbit/nr-bundles-public`.
