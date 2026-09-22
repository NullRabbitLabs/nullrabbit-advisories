# NR-2026-067 — SatLayer BVS: a legitimate slash burns zero via the withdrawal race

**NullRabbit Operator Advisory** · Published 2026-09-22 · **HIGH**

**Finding:** `SATLAYER_BVS_SLASH_ESCAPE` · **Affected:** `satlayer/satlayer-bvs` — CosmWasm
(`bvs-vault-router`, `bvs-vault-bank`, `bvs-vault-base`, `bvs-registry`) and Solidity
(`SLAYRouterV2.sol`, `SLAYVaultV2.sol`), current `main` `69a2f8e`.

> **Why we publish publicly.** This was disclosed privately to SatLayer's own documented
> channel on 2026-06-10 and chased on 2026-09-08. In 104 days there has been no reply of any
> kind. The disclosure window we stated in writing closed on 2026-09-22.
>
> **Basis, recorded 2026-09-22.** SatLayer's documentation directs issues outside the Sherlock
> programme to `bugs[at]satlayer.io` (https://docs.satlayer.xyz/security/bug-bounty, read
> 2026-06-10) and asks that public GitHub issues not be opened. That is the channel we used. No
> bug-bounty or audit-contest programme covers this codebase: Sherlock #50 scopes
> `satlayer/deposit-contract-public` only — `SatlayerPool.sol` and `ReceiptToken.sol`, which
> have no slashing, operators or vaults — and the strings `satlayer-bvs`, `slayrouter`,
> `slayvault`, `bvs-vault` and `bvs-registry` appear nowhere in its scope. Immunefi, Cantina,
> Code4rena and HackenProof list no SatLayer programme at all (surveyed 2026-06-10).
> `satlayer/satlayer-bvs` publishes no `SECURITY.md` and has GitHub private vulnerability
> reporting disabled (checked 2026-09-22).
>
> **Reproducers are deliberately withheld.** Working proofs of concept exist for both stacks and
> are not published here. The original disclosure stated impact and confirmation while
> withholding root cause and code pending acknowledgement; that acknowledgement never came, and
> the defect remains unfixed on current `main`. Withholding them publicly is the same position
> we have held since June. They will be published once a fix ships. Everything needed to
> **verify** the finding, and to **fix** it, is below.

## Summary

SatLayer is Bitcoin restaking with programmable per-BVS slashing. A misbehaving operator's
stake — or that of its restakers — **escapes a legitimate slash entirely** by exiting through
the normal, documented withdrawal flow. The slash then burns approximately zero.

Two facts combine:

1. There is **no on-chain invariant** tying the slashing `resolution_window` to the
   `withdrawal_lock_period`.
2. A pending slash does **not freeze withdrawals**.

A queued withdrawal can therefore mature and redeem — assets leave the vault — *before* the
slash is able to lock those assets.

In a multi-staker vault this inverts the loss: the bips of remaining stake that do get burned
fall on the **honest stakers who stayed**.

## Mechanism

**Slash lifecycle:** `request_slashing` → wait `resolution_window` → `lock_slashing` (the step
that actually pulls assets from the vaults; the amount is snapshotted at LOCK, not at request) →
`finalize_slashing`.

The slashable reach-back equals the withdrawal lock period. `bvs-vault-router/src/contract.rs:252`
carries the verbatim comment `// max_slashable_delay is equal to the withdrawal lock period`
(Solidity equivalent `SLAYRouterV2.sol:254-256`). `lock_slashing` is callable only at
`request_time + resolution_window` (`bvs-vault-router/src/contract.rs:462`;
`SLAYRouterV2.sol:318`).

**Withdrawal flow:** `queue_withdrawal` (burns shares; assets stay) → after
`withdrawal_lock_period`, `redeem_withdrawal` (assets leave). `redeem_withdrawal_to` gates only
on `unlock_timestamp = queue_time + withdrawal_lock_period`
(`bvs-vault-bank/src/contract.rs:215`; `SLAYVaultV2.sol` redeem/withdraw ~`:331-378`).
**There is no pending-slash check.**

**The race.** An offence occurs at `T`. The restaker queues a withdrawal at `T`, maturing at
`T + lock`. The service detects the offence late — anywhere inside the `lock`-length reach-back
is still a valid detection — and calls `request_slashing`. But `lock_slashing` is only callable
at `request_time + resolution_window`, which for a late request is later than `T + lock`. The
redeem completes first. The slash burns zero.

## The missing invariant

```
withdrawal_lock_period >= max_slashable_delay + resolution_window (+ request expiry)
```

Because `max_slashable_delay == withdrawal_lock_period`, this is violated for **any**
`resolution_window > 0`. The default registry value is `60 * MINUTES`.

This is not a misconfiguration. It fails at default configuration on both implementations.

## The guard that was never wired up

`assert_not_validating` (`crates/bvs-vault-base/src/router.rs:70`) appears intended to block
exactly this. It has **zero production callers** — it is referenced only by its own definition
and its unit tests.

The parameter validators do not close the gap either: `SlashingParameters::validate()` checks
only `max_slashing_bips <= 10000`, and `set_withdrawal_lock_period` checks only `> 0`.

## Confirmation

Confirmed at **default configuration** on both stacks, against the actual contracts, on current
`main` (`69a2f8e`):

- **CosmWasm**, default 7-day lock with a 1-day resolution window and no misconfiguration: a
  legitimate slash of a misbehaving operator burns 0.
- **Solidity**, 1-hour resolution window with late-but-valid detection: slashed = 0. A control
  case with instant detection slashes 100%, which establishes that the break is the timing
  relationship and not a parameter mistake.

## Relationship to prior audits

All five published SatLayer audits were read (Dedaub Phase-1, Coinspect Phase-1, Dedaub Phase-2
slashing, Dedaub EVM, token). This finding is distinct from every documented item:

- **Dedaub Phase-2 P2** (acknowledged, no fix) advises that `resolution_window` "should reflect
  the BVS's tolerance", framing the operator as initiating withdrawal at action time. It does
  not name the missing `lock >= delay + window` invariant, nor the two-step late-detection
  redeem race. The source carries the same advisory-only comment, unenforced
  (`bvs-registry/src/state.rs:222-225`, "recommended").
- **CosmWasm H1** (resolved) closed the atomic same-transaction deregister path — a different
  path. No atomic withdraw path remains; the two-step queue-and-redeem is unguarded.
- **EVM M1** (resolved) enforces `operatorDelay >= serviceMinDelay` — a different invariant.

No post-audit commit adds a pending-slash withdrawal freeze or the missing invariant, and
`assert_not_validating` remains unwired.

## Severity

**HIGH.** Permissionless — a restaker exits their own stake through the documented withdrawal
flow. Definite loss of the protocol's core security property. Confirmed at default configuration
on both implementations on current `main`.

SatLayer BVS is live on mainnet across Babylon Genesis, Ethereum, BSC and Sui, with aggregate
restaked TVL on the order of ~$1.1M at the time of measurement. The dollar figure is modest; the
broken invariant is the foundation of restaking economic security regardless of the amount
currently sitting behind it.

## Remediation

Either, or both:

1. **Freeze withdrawals** — queue and/or redeem — for any vault whose delegated operator has a
   pending or locked slash. The existing `assert_not_validating` can be wired into the redeem
   path, or the vault can query the router for a pending slash before releasing funds.
2. **Enforce the invariant** `withdrawal_lock_period >= max_slashable_delay + resolution_window
   + request-expiry` at registration and parameter-set time — in `SlashingParameters::validate`
   and `set_withdrawal_lock_period` — rather than leaving it as a recommendation in a comment.

## Scope

This advisory describes a defect in `satlayer/satlayer-bvs` and is not a turnkey exploit: the
working proofs of concept are withheld, as stated above. It does not target any deployed
instance, and no SatLayer system was tested against in production — both proofs run against the
contracts locally, in `cw-multi-test` and Foundry respectively.

## Timeline

| date | event |
|---|---|
| 2026-06-10 | Disclosed to `bugs@satlayer.io` — impact, dual-stack confirmation and PoC-in-hand stated; root cause and code withheld pending acknowledgement |
| 2026-07-10 | Day-30 follow-up due; missed on our side |
| 2026-09-08 | Chased. No reply |
| 2026-09-22 | Window closes. 104 days, no response of any kind. Published |

Corrections are welcome and will be made. If any part of this reading is wrong, write to
simon@nullrabbit.ai and it will be amended.
