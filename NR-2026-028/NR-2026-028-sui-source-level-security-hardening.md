# NR-2026-028 — Sui consensus checkpoint block-poisoning via malformed checkpoint signature (SUI_D03)

**NullRabbit Operator Advisory** · Published 2026-07-08

> **Why we publish publicly:** this is an out-of-scope-for-bounty consensus-correctness finding on the Sui node, source-traced only — the defect is a code/logic property with no network-observable wire signature, so unlike NR-2026-027 it ships no detection bundle. See [Why we publish these findings publicly](../WHY-WE-PUBLISH.md).

## Summary

`SUI_D03` is a consensus checkpoint-signature validation gap on the Sui node. A malformed checkpoint signature from a Byzantine proposer is not rejected cleanly; instead Mysticeti marks the proposer `bad_node` and routes around it. The measured impact is throughput degradation on the poisoning node's own stake-weighted share (self-harming); there is no committee-wide halt, no checkpoint lag on honest nodes, and it requires a compromised validator keypair, so it cannot force a halt below the Byzantine threshold. Severity Medium (~CVSS 5.3, revised down from an initial 7.4 by the finding's own measurement).

## Mechanism (source-cited, `MystenLabs/sui`)

A malformed checkpoint signature from a Byzantine committee member is handled by the Mysticeti proposer path marking the proposer `bad_node` and deprecating it from the leader schedule, rather than deterministically rejecting the malformed input at the point of validation. Because the bad proposer is routed around, honest nodes see no halt and no checkpoint lag; the attacker discards only its own stake-weighted throughput. The trigger requires a compromised validator keypair and cannot force a halt below the `f < n/3` Byzantine threshold. The remediation is to mirror the sibling validation path's per-item fallback so the malformed signature is rejected deterministically rather than tolerated-and-routed-around.

## Scope

Consensus-correctness / robustness on the Sui validator surface; no funds, no chain halt (self-mitigating, sub-threshold, self-harming), no authentication break. Requires a compromised validator keypair. Source-traced only: no turnkey reproducer against live infrastructure, no public IPs or mainnet hostnames.

## Provenance and disclosure

NullRabbit original source-level analysis (`provenance.source_class: original`). `SUI_D03` is a **security-class finding with no detector product** — the defect is a consensus-logic property with no network-observable signature, so unlike the availability findings in NR-2026-027 it ships no bundle to the public dataset. DoS / resource-exhaustion is out of scope on the Sui bug-bounty program (HackenProof) and the direct `security@sui.io` channel is unresponsive, so this is published as a source-traced operator advisory. Vendor: **MystenLabs / `MystenLabs/sui`**. Source trace and measurement in `chains/sui/findings/D03/`.

## Contact

Simon Morley, NullRabbit — `simon@nullrabbit.ai`.

If you operate Sui validator infrastructure and have applied the remediation above, or have measurements at variance with this, we would like to hear from you.
