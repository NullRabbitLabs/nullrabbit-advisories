# NR-2026-007 — CometBFT consensus-channel message floods (Proposal / Vote / BlockSync)

**NullRabbit Operator Advisory** · Published 2026-07-03

> **Why we publish publicly:** these are out-of-scope-for-bounty, no-embargo node-availability findings — analysis + reproducer only. See [Why we publish these findings publicly](../WHY-WE-PUBLISH.md).

## Summary

A peer that completes the CometBFT SecretConnection handshake can flood a
validator's consensus reactor with **valid-shape but unsigned** consensus
messages — `Proposal` (DataChannel `0x21`), `Vote` (VoteChannel `0x22`), and
`BlockResponse` (BlockSync `0x40`). Each message passes the reactor's
`ValidateBasic` (a length/shape check) and is queued for processing **before**
its signature is verified, so an attacker who never holds valid signing keys can
still drive sustained per-message server work.

This is an **availability / resource issue only, and its impact is bounded**:
against a multi-validator quorum, one targeted node's CPU rises but block
production continues at baseline — a single attacker does **not** halt the
chain. On a 4-validator localnet the attacked node's CPU rose while the other
three validators and quorum height were unaffected. **Severity: MEDIUM**
(single-node CPU load; no crash, no consensus-safety or funds impact).

## Scope

These are consensus-reactor DoS-hardening observations, not a crash or a
consensus-safety defect. They are **out of scope for direct CometBFT vendor
disclosure** (`no-direct-vendor`) and are published here as operator guidance and
as open ML training data.

## Findings at a glance

| id | channel | message | primitive_id |
|---|---|---|---|
| `COMETBFT_PROPOSAL_FLOOD` | `0x21` (Data) | ProposalMessage | `cometbft_proposal_flood` |
| `COMETBFT_VOTE_FLOOD` | `0x22` (Vote) | VoteMessage | `cometbft_vote_flood` |
| `COMETBFT_BLOCKSYNC_FLOOD` | `0x40` (BlockSync) | BlockResponse (oversized) | `cometbft_blocksync_flood` |

`PROPOSAL_FLOOD` is the family head; `VOTE_FLOOD` and `BLOCKSYNC_FLOOD` are the
siblings on the vote and block-sync channels.

## Mechanism

On each of these channels the consensus reactor's `Receive` path takes a
read-lock on consensus state and enqueues the message for the main loop **before**
the deferred signature verification runs. A valid-shape message with a
zero-filled signature passes `ValidateBasic` (length-only) and reaches that
queue; signature verification later rejects it, but the RLock + enqueue cost has
already been paid. `BlockResponse` additionally carries an oversized `LastCommit`
(up to ~9000 `CommitSig` entries), so the decode + validation cost per message is
large.

## Impact & mitigation

- **Impact:** elevated CPU on a targeted node under a sustained flood. Quorum
  block production is unaffected on multi-validator networks (measured). No
  memory corruption, no crash, no consensus or funds impact.
- **Mitigation:** rate-limit inbound consensus-channel messages per peer;
  peer-score and evict peers that send high volumes of signature-invalid
  messages; cap `BlockResponse` `LastCommit` size on the receive path.

## Reproduction

Reproduced against a live CometBFT / gaiad node using NullRabbit's `cometbft_p2p`
client (real SecretConnection + MConnection; a valid-shape flood per channel).
Representative multi-modal capture bundles for each primitive are published in the
[`nr-bundles-public`](https://huggingface.co/datasets/NullRabbit/nr-bundles-public)
dataset (`family_id=consensus_abuse`).
