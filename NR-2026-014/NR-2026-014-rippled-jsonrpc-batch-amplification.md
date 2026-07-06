# NR-2026-014 — rippled JSON-RPC `batch` egress amplification (no per-element cap)

**NullRabbit Operator Advisory** · Published 2026-07-06

## Summary

rippled's JSON-RPC `batch` method runs an outer request of the form
`{ "method": "batch", "params": [<inner requests>] }` and iterates `params` with
**no per-element cap** — only the 1 MB total request-size limit (`kMaxRequestSize`)
bounds it. So a single ~1 MB request packing ~10,000 inner calls produces a **~28 MB
response** — a **~24.9× egress amplification** with linear CPU cost, on the public
HTTPS RPC port. Single-shot egress is capped at ~28 MB by the 1 MB request bound,
but a sustained stream of these pins ~½ a core per request/second and multiplies
outbound bandwidth. Availability only — no funds or consensus impact.

This is the rippled member of the Sui F10 / Aptos F10 RPC batch-amplification class
(NR-2026-004 / NR-2026-010 / NR-2026-012).

## Findings at a glance

| Item | Detail |
|---|---|
| Class | Response amplification (`response_amp`) — batch with no per-element cap |
| Reachability | Remote, unauthenticated, public rippled HTTPS JSON-RPC (port 5006) |
| Trigger | `{"method":"batch","params":[~10,000 inner requests]}` filling the 1 MB request cap |
| Measured | ~1 MB request → ~28 MB response → **24.9×** at N=10,000; linear CPU (~½ core per req/s) |
| Impact | Bounded single-shot (~28 MB by the 1 MB cap) but sustained egress + CPU amplification per cheap request |
| Severity | Medium (bounded per-request, but public + cheap + linear-scaling) |
| Affected | rippled with JSON-RPC batch enabled (tested v3.1.3) |
| Mitigation | Add a per-batch element cap (`params.size()`) independent of the 1 MB byte cap; account cost by inner-request count + response bytes. See Mitigation |

## Mechanism (source-cited)

`src/xrpld/rpc/detail/ServerHandler.cpp:627–642` — the batch dispatch reads
`method == "batch"`, requires `params` to be an array, and sets
`size = jsonOrig[jss::params].size()`:

```cpp
if (jsonOrig.isMember(jss::method) && jsonOrig[jss::method] == "batch") {
    batch = true;
    if (!jsonOrig.isMember(jss::params) || !jsonOrig[jss::params].isArray()) {
        httpReply(400, "Malformed batch request", output, rpcJ);
        return;
    }
    size = jsonOrig[jss::params].size();
}
...
for (unsigned i = 0; i < size; ++i) { /* run inner request i */ }
```

The loop runs `size` inner requests with **no per-element cap** — the only bound is
`kMaxRequestSize = 1 MB` (`Tuning.h:46`) on total request size. Because inner
requests are ~100 bytes but their responses (e.g. `account_info`, `server_info`) are
much larger, ~10,000 inner calls in a ~1 MB request yield a ~28 MB response.

## Reproduction

The corpus reproducer (`chains/xrp/lab/drivers/known_class_rippled_batch_amp.py`,
primitive `rippled_batch_response_amp`, published in `NullRabbit/nr-bundles-public`)
captures the wire signature over loopback: a ~1 MB `method="batch"` request with
~10,000 inner calls against a mock endpoint returning a ~28–30 MB batch response —
the small-request / large-response ratio on one TCP flow.

## Mitigation

- **Cap the batch element count** (`params.size()`) with a small limit, enforced
  before running any inner request — independent of the 1 MB byte cap.
- **Meter cost by inner-request count and response bytes**, not just request bytes,
  so a batch is charged for what it fans out to.
- Rate-limit outbound bytes per source at the RPC edge.

## Disclosure & provenance

Availability-only finding (no funds/consensus impact). DoS/availability on the public
rippled RPC surface is publish-track under NullRabbit's disclosure-scope policy.
Vendor: XRPLF. NullRabbit measurement vs rippled v3.1.3; source-trace and measurement
in `chains/xrp/findings/F10_RIP_BATCH_AMP`. Corpus primitive
`rippled_batch_response_amp` shipped in `NullRabbit/nr-bundles-public`.
