# NR-2026-065 — Aleo Verulink bridge: NAY-vote encoding mismatch between Go attestor and Solidity recovery → compliance screening unenforceable

**NullRabbit Operator Advisory** · Published 2026-09-09 · **Updated 2026-09-10**

> ## Update 2026-09-10 — read this before the rest
>
> **If you run a released attestor (`v2.0.x`) against the current contracts, this advisory does not
> apply to you and no action is required.** The encoding was corrected in
> [`6d4eb56`](https://github.com/venture23-aleo/verulink/commit/6d4eb566e018bfa7bc36b99ad020f0c6ac17ec13)
> on 2025-08-14 and shipped in `v2.0.2`. We analysed `main`, which never received that commit. The
> advisory below describes `main`, not the deployed system.
>
> **If you build attestors from source, check which branch.** `main` — the repository's default
> branch — still encodes NAY as `0` today. An attestor built from it signs bundles that revert
> against the live contracts. Build from a release tag and confirm `getEthBoolByte` returns `2` for
> NAY.
>
> **The failure mode below is unchanged.** `ConsumedPacketManagerImpl._checkSignatures` is
> byte-identical to the version analysed: it attempts recovery as `NAY`, then as `YEA`, and if
> neither yields a registered attestor it reverts the **entire bundle** — no tolerance for one
> unrecoverable signature among many, even when the rest exceed threshold. The two components agree
> on the encoding today; nothing on-chain requires them to. Reverting that Go commit, adding a second
> attestor implementation, or introducing a signer in another language reinstates the revert with no
> contract change and no signal until a bundle fails.
>
> The mitigation in **Suggested fix** — a symmetric recovery that does not revert the batch on a
> single miss — is untouched by the Go change and closes the class rather than the instance.

## Summary

Verulink's off-chain Go attestor and its on-chain Solidity verifier disagree about how a **NAY**
vote is encoded into the message that attestors sign. The Go signing service packs a NAY as the
boolean byte `0x00`; the Solidity contract recovers it as the enum value `Vote.NAY = 0x02`. The two
pre-images differ, so the recovered address is not the attestor's, `_checkSignatures` hits
`require(_validateAttestor(...), "unknown signer")`, and **the entire bundle reverts**.

The consequence is not a dropped vote — it is that the sanctions/AML screening branch Verulink
advertises is **structurally unreachable**. Any bundle carrying at least one honest NAY reverts, so
a relayer must either strip NAY signatures before submission (defeating screening entirely, and
letting the YEA quorum from non-screening attestors process the packet) or submit and have the
bundle revert, stranding source-chain escrow until it is manually re-aggregated with the NAYs
removed. Operationally the first is the only workable choice, which means the compliance guarantee
is unenforceable on the Ethereum-destination side.

No attacker is required. Any honest attestor casting a NAY triggers this structurally.

## Findings at a glance

| Finding | Component | Class | Severity |
|---|---|---|---|
| NAY-vote encoding mismatch | Go attestor ↔ Solidity `ConsumedPacketManagerImpl` | cross-component encoding drift | **HIGH** |
| Stale-attestor signature revert (rotation race) | `AttestorManager.removeAttestor` | availability / same root cause | LOW |

- **Reachability:** permissionless in the sense that matters — no attacker action at all; an honest
  NAY is sufficient.
- **Affected:** `github.com/venture23-aleo/verulink` @ `main`, reviewed **after** the Veridise and  **— `main`. Released `v2.0.x` tags carry the encoding fix; see the update above.**
  zkSecurity V2 audits.
- **Scope note:** Verulink runs no Immunefi or HackerOne programme, and Aleo's Immunefi programme
  covers snarkVM/snarkOS only — bridge-application findings are explicitly out of scope. This was
  therefore a direct-to-vendor disclosure on the publish track from the outset.

## Mechanism (source-cited)

**Go side —** `attestor/signingService/chain/ethereum/hash.go:59,65-72`

The attestor signs `keccak256(packetHash, getEthBoolByte(IsWhite))`, where `getEthBoolByte(false)`
is `0x00`. A NAY — the sanctions/AML rejection — is therefore a **boolean false byte**.

**Solidity side —** `solidity/contracts/common/libraries/PacketLibrary.sol:9-13`

```solidity
enum Vote { NULL, YEA, NAY }   // NULL=0, YEA=1, NAY=2
```

`solidity/contracts/base/bridge/ConsumedPacketManagerImpl.sol:42-50` — `_recover` computes
`keccak256(abi.encodePacked(packetHash, tryVote))`, where `tryVote` is the **enum**, packed as one
byte for a three-value enum. A NAY is therefore `0x02`.

`_checkSignatures` (lines 87-123) tries NAY (`0x02`) recovery first, falls through to YEA (`0x01`),
and calls `require(_validateAttestor(...), "unknown signer")` when neither matches.

### Cryptographic proof

Computed with `cast keccak`, using `packet_hash = 0x4a9a0539…b81d` so the result is reproducible:

```
go_NAY_inner  (Go:  pkt || 0x00) = 0x7dd000e59bd4e7da0ea9cb91b570f2f802ab0018da51d2b205de74c1bc3f4571
sol_NAY_inner (Sol: pkt || 0x02) = 0xc8e2afaa8c95051c398fd380e371ef65359c82d084f1faae212c0afeded8b2d1
sol_YEA_inner (Sol: pkt || 0x01) = 0x506d104d0ecca00e140eb85f3cefaf59d0336d24d63a71a77668ea1c3ad4bcc0
```

All three differ. A Go-signed NAY recovers to the attestor's address under **neither** branch, so
the `require` fails and the bundle reverts.

### What this makes dead

The `Holding.lock` screening branch at `ConsumedPacketManagerImpl._consume` lines 100-109 is
**structurally dead code**. It cannot execute, because the only path that reaches it requires a NAY
signature to verify, and no honest NAY signature can.

## Impact

The original framing of this finding was "silent vote drop". That was **wrong**, and correcting it
matters: the actual failure mode is a **revert**, which is louder but worse. A silent drop would
lose one vote; a revert kills the whole bundle and forces the relayer into the choice described
above. The advisory records the correction because the distinction between `require`-revert and
silent-skip is exactly the sort of detail a reader needs in order to reason about the mitigation.

Live mainnet contracts at the time of the finding:

- Bridge: `0x7440176A6F367D3Fad1754519bD8033EAF173133`
- TokenService: `0x28E761500e7Fd17b5B0A21a1eAD29a8E22D73170`

## The LOW, and why it is here

`AttestorManager.removeAttestor` deletes an attestor and updates the quorum atomically, with no
grace window for in-flight bundles. A bundle collected at T0 with a signature from the removed
attestor reverts at consume time with the same `"unknown signer"` until it is re-aggregated.

It shares the HIGH's root cause: **one bad signature kills the entire bundle**. A single change at
`_checkSignatures` — a symmetric NAY/YEA attempt that does not revert on a miss, or a drain-window
invariant tied to `removeAttestor` — closes both.

## Mitigation

1. Align the two encodings. Either the Go signing service packs the enum value, or the Solidity
   recovery packs the boolean byte — but one of them must change, and the fix must be covered by a
   cross-component test that signs on the Go side and verifies on the Solidity side. A test that
   exercises only one side cannot catch this class at all, which is how it survived two audits.
2. Make `_checkSignatures` tolerant: attempt both vote encodings without reverting the bundle on a
   single unrecoverable signature, so one bad or stale signature degrades to one ignored vote
   rather than a dead bundle.
3. Give `removeAttestor` an in-flight grace window, or pause and drain before rotation.

## Refuted during this work

Eight candidate findings were examined and refuted with reasoning rather than left as
maybes — across the off-chain Go service, the Solidity bridge contracts, and the Aleo Leo programs.
Two are worth stating publicly because the reasoning is reusable:

- **"NAY-vote consume() skips the `in_packet_consumed` mapping write, enabling replay."** Refuted.
  In Leo, `return X then finalize(args)` does **not** make the finalize conditional; the bridge
  consume finalize enqueues unconditionally, so `Mapping::set(in_packet_consumed, …)` runs whether
  screening passed or not. Proven from snarkVM bytecode and a real-snarkVM test at
  `aleo/test/1_tokenBridge.test.ts:896-937`.
- **"Paused-bridge bypass on NAY consume."** Refuted. Aleo conditional-Future scheduling means
  `return screening_passed then finalize(args)` schedules the whole bundle — including the child
  program futures — only when `screening_passed` is true. On a NAY majority there is no state
  change, so the pause check is moot.

A fourth candidate — a latent byte-collision between NAY (`0x00`, Go encoding) and `Vote.NULL`
(`0x00`) — is **not** live: no `_recover(Vote.NULL)` call site exists in the repository. It is
recorded here as a fix-side hazard, because any change to the encoding must avoid reintroducing it.

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-06-11 | Finding confirmed and cryptographically proven against `main`, post-audit code |
| 2026-06-11 | Disclosed to `security@venture23.xyz`; impact and dual-side proof stated, root cause / file-and-line / verification script withheld pending acknowledgment; **90-day window proposed in writing** |
| 2026-06-13 | Re-sent to `security@venture23.io` |
| — | Vendor acknowledged out-of-band and **requested the technical detail** |
| — | Full root cause, file and line locations, and verification script **sent as promised** |
| — | No further response |
| 2026-09-09 | 90-day window expires. Published. |

The vendor received the complete material, on request, and did not respond. Publication follows the
window we set out at the start.

---

*NullRabbit publishes operator advisories for issues that fall outside paid bounty scope. This
advisory describes a defect in an availability- and compliance-critical control path; it contains no
exploit tooling beyond the encoding proof needed to demonstrate that the mismatch is real.*
