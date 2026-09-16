# NR-2026-064 — Sui: the gasless rate-limiter is a fixed window, so an unauthenticated sender admits 2× the operator's cap

**NullRabbit Operator Advisory** · Published 2026-09-10

## Summary

Sui's gasless transaction path is guarded by a rate limiter that decides, before signature verification,
how many free transactions a validator will admit per second. **Both of its layers are fixed windows.**
A fixed window resets its counter on a clock tick rather than tracking a rolling interval, so a sender who
straddles the boundary — one burst at the end of window *N*, an identical burst at the start of *N+1* —
is admitted twice inside a period shorter than the window the operator thought they configured.

Measured end-to-end against a real validator at `gasless_max_tps=5`: the first burst admitted 5, an
identical same-window burst admitted 0, and an identical burst across the boundary admitted a further 5.
**10 admitted in a ~1.3 s straddle, against a cap of 5/s.**

The gasless feature is live on Sui mainnet at protocol **v124**, the gate sits on the validator
transaction-submission path **before signature verification**, and no authentication or compromise is
required.

This is a **correctness defect in a safety limit**, not a denial-of-service headline. It does not halt a
network, and we say below exactly why it cannot.

## Findings at a glance

| Finding | Component | Class | Severity |
|---|---|---|---|
| `sui_GR02_gasless_rate_bypass` | `gasless_rate_limiter.rs` fixed-window layers | `rate_limiter_bypass` | MEDIUM |
| `sui_GR01_gasless_rate_fail_open` | `GaslessRateLimiter::try_acquire` unset-cap path | `rate_limiter_bypass`, `fail-open` | Historical — fixed in v121 |

- **Reachability:** remote, unauthenticated, no compromise. The admission gate runs ahead of signature
  verification on the validator ingress path (`authority_server.rs:752`).
- **Impact:** availability degradation, bounded. Not a halt — see *Why this is not a halt*.

## The defect

Two admission layers, both fixed windows, neither a sliding window or token bucket:

- `ConsensusGaslessCounter::record_commit` (`gasless_rate_limiter.rs:34-43`) keys on
  `commit_timestamp_ms / 1000` and resets `count` on the window tick.
- `FixedWindowCounter::try_acquire` (`gasless_rate_limiter.rs:57-63`) resets on a 1 s `Instant` tick.

Because each layer resets wholesale rather than ageing out individual admissions, the interval spanning
the last instant of one window and the first of the next admits a full quota twice. The bound the
operator selected via `gasless_max_tps` is therefore an upper bound on a *calendar second*, not on any
one-second interval — and an attacker chooses the interval.

### GR01 — the earlier fail-open, included for completeness

`GaslessRateLimiter::try_acquire` returned `true` unconditionally when `gasless_max_tps` was `None`.
Protocol v119–v120 testnet config set `enable_gasless=true` **without** setting `max_tps`, so for that
window the limiter admitted at unlimited rate. **This was fixed in v121** and is reported here only
because it is the same limiter and the same class of mistake: a safety limit whose absent or reset state
is permissive rather than restrictive.

## Measured

Two rails, both against `sui 1.74.0 @ 818f8d78` (MAX_PROTOCOL 125).

**Component** — a unit test inside `gasless_rate_limiter.rs` with both layers active asserts 2×`max_tps`
admitted across one real one-second boundary. Passes.

**End-to-end** — a real single-validator `TestCluster` at `gasless_max_tps=5`, GAS registered as a gasless
token, bursts submitted through the rate-limited validator ingress
(`auth_client.submit_transaction`): **5 admitted, then 0 in-window, then 5 across the boundary = 10 = 2×
the cap**, in roughly 1.3 s.

**Impact** — a separate run on a real 4-validator in-process committee at `gasless_max_tps=50`: a
sustained gasless flood at the cap made the *same* legitimate gas-paying transfers **3.0–4.3× slower**
across two runs while the network kept committing. The obvious objection to that number — that it is a
shared-runtime artifact — was checked and rejected: the box stayed ~80 % idle with ~20 cores free
throughout, so the crowding is real consensus/execution-pipeline contention that transfers to production.

## Why this is not a halt

We looked for the escalation and it is structurally prevented, so we are not claiming it.

Under load, uncommitted transactions accumulate in the writeback cache; past
`config.backpressure_threshold()` backpressure activates (`execution_cache/writeback_cache.rs:1114-1116`)
and the consensus handler awaits `await_no_backpressure()` at the top of its per-commit loop
(`consensus_handler.rs:1113`). That is the only route by which a transaction flood slows commits, and it
is deliberate flow control.

Critically the valve self-suppresses: `should_suppress_backpressure()` returns true once
`certified <= executed` (`authority/backpressure.rs:23`). So a sustained, bounded (≤ 2× `max_tps`) gasless
flood drives pending up → backpressure throttles commit processing → execution drains, since gasless
transactions are cheap and admission is capped → executed catches up to certified → the valve releases →
commits resume. The steady state is an **oscillating throttle**, not a freeze. A permanent freeze would
need execution throughput at ~0 with positive inflow, which a bounded flood of cheap transactions does not
produce.

**Consequence for severity:** MEDIUM as a defect; LOW on a strict blast-radius matrix. We are not calling
this HIGH and did not run a production-shape flood to chase one, because the source trace says that run
would confirm a negative at real cost.

## What the published artefacts do and do not show

Stated plainly, because it would be easy to misread the dataset:

**The corpus bundles do not demonstrate the bypass.** All 104 bundles across the two primitives were
captured at `historical_fidelity = fixed_version_v121` — the **patched** binary. On that build the fix is
in effect, every response is uniformly `gasless_accepted`, and the traffic is shape-wise indistinguishable
from ordinary public-RPC load. They are deliberately **attack-shape captures** — flood rate, burst cadence,
connection pattern — recorded for detector training, not vulnerability evidence.

The bypass evidence is the two measurement rails above, recorded in
`chains/sui/findings/GR02/reproducers/MEASURED-2026-06-04.md`. A true vulnerable-versus-patched
differential in the corpus would require pinned `v120` binaries and has not been captured.

Anyone citing this work for the 2× result should cite the measurement record, not the bundles.

## Affected versions

The fixed-window doubling is present in `sui 1.74.0 @ 818f8d78` (MAX_PROTOCOL 125) and the gasless feature
is mainnet-live at protocol **v124** (`enable_gasless` unconditional, with a populated stablecoin
allow-list). The GR01 fail-open affected protocol **v119–v120** and was fixed in **v121**.

## Fix

Replace the fixed windows with a **token bucket** or a **sliding-window log**. Either ages out individual
admissions instead of resetting a counter wholesale, which closes the boundary doubling directly. The cap
then means what the operator believes it means: a bound on any one-second interval, not on a calendar
second.

## Disclosure

MystenLabs runs its programme through HackenProof, which is impact-tiered and treats availability
degradation of this shape as out of scope for reward. That makes this a publication rather than a
coordinated-disclosure item; there is no embargo to run and no reward being sought. It is published
because operators choosing a `gasless_max_tps` value should know the number admits twice what it appears
to, and because the remedy is small.

## Credits

NullRabbit — measurement, source tracing and severity analysis.
Contact: simon@nullrabbit.ai

## References

- `chains/sui/findings/GR02/reproducers/MEASURED-2026-06-04.md` — the 2× end-to-end measurement
- `chains/sui/findings/GR02/reproducers/CHAIN-ALPHA-MEASURED-2026-06-04.md` — the 3.0–4.3× degradation run
- `chains/sui/findings/GR02/GR02A-SEVERITY-VERDICT-2026-06-05.md` — why MEDIUM and not HIGH
- Primitives: `sui_GR01_gasless_rate_fail_open`, `sui_GR02_gasless_rate_bypass`
