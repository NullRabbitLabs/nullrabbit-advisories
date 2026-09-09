# NR-2026-066 — Conflux: an unauthenticated snapshot chunk panics the network worker (conflux-rust < v3.1.0)

**NullRabbit Operator Advisory** · Published 2026-09-09

> **This is not a new vulnerability.** Conflux fixed it upstream in
> [PR #3560](https://github.com/Conflux-Chain/conflux-rust/pull/3560), merged 2026-07-02 and
> released in **v3.1.0** on 2026-08-10. It carried no CVE, no GHSA and no security release note.
> This advisory exists because the fix was published as an ordinary storage hardening change, and
> an operator reading the v3.1.0 notes had no way to learn that the version they were running could
> be crashed by any peer. We reproduced it on the wire to establish that, and we are saying so.

## Summary

A Conflux snapshot-sync **chunk** is RLP `[keys, values]` where the entries are **plain byte
strings**, not trie nodes. During state-sync restore those keys become snapshot-MPT paths, so a
path's length is simply the length of the key an attacker supplied. `FullSyncVerifier::restore_chunk`
validates key **ordering**, chunk **boundaries**, and that `keys[0] == lower_bound_incl` — but it
never bounds key **length**.

A 32 768-byte key is therefore an over-long `CompressedPathRaw` delivered inside an ordinary,
well-formed message. When the restore walks it, `calculate_path_steps` computes `path_size * 2` on a
`u16` with `overflow-checks = true`, and the multiply overflows:

```
compressed_path.rs:199   'attempt to multiply with overflow'
```

The panic lands on the network IO worker. **The victim's RPC goes down.** There is no authentication
anywhere on that path.

## Affected

| | |
|---|---|
| **Affected** | `conflux-rust` **< v3.1.0**, including v3.0.3 (2026-04-08) and v3.0.3-fix (2026-05-19) |
| **Fixed in** | **v3.1.0**, 2026-08-10 — fix commit `83e4dc68b`, merged as PR #3560 (`6060b8837`) |
| **Verified against** | v3.0.3 @ `f44f1cb` |
| **Reachability** | Unauthenticated remote peer, during snapshot sync |
| **Impact** | Availability — network worker panic, node RPC down |
| **Severity** | **HIGH** (our measurement; the vendor assigned none) |
| **CVE / GHSA** | none issued |

We confirmed the boundary in source rather than inferring it from release dates: the fix introduces
`CompressedPathRaw::MAX_PATH_BYTES` and rejects a longer path at decode. That constant is **absent**
in the v3.0.3 tree and **present** in v3.1.0.

## Mechanism (source-cited)

**The carrier —** `SnapshotChunkResponse`, cfx sync `msg_id 0x1c`.

**The sink —** `compressed_path.rs:98` states plainly that `path_steps()` runs during snapshot
*restore* (`mpt_node_path_to_db_key`, `compute_merkle`, `mpt_cursor`) — that is, while **chunks** are
being applied.

Observed stack, from the captured panic:

```
SocketWorker::work_loop
  → NetworkServiceInner::message
  → SynchronizationProtocolHandler::on_message
  → handle_rlp_message
  → SnapshotChunkResponse::handle
  → SnapshotChunkSync::handle_snapshot_chunk_response
  → FullSyncVerifier::restore_chunk
  → MptSliceVerifier::restore
  → MptCursor::open_path_for_key / pop_path_for_key / pop_nodes
  → ReadWritePathNode::commit
  → merkle::compute_merkle
  → calculate_path_steps          // path_size * 2, u16, overflow-checks = true
```

**Why the key is accepted.** `restore_chunk` requires the keys to sort correctly and to sit inside
the chunk's boundaries. Appending `0x00` bytes to a valid prefix produces a key that still sorts
after `lower_bound_incl` and stays below the right boundary, while being arbitrarily long. Restore
runs **per chunk on arrival**, so a single chunk is sufficient. The manifest is served genuine — the
attacker does not need to forge it.

## What we got wrong first, and why it is here

Our own earlier analysis named the wrong carrier: `SnapshotManifestResponse` (`0x1a`) →
`RangedManifest::validate` → `compute_merkle`. **That route does not exist**, and we refuted it in
source before publishing:

- `TrieProofNode::decode` is `Self(rlp.as_val()?)` and **bypasses** `TrieProofNode::new` — and
  `new()` is the only caller of `compute_merkle`.
- `TrieProof::new` indexes the **stored** `get_merkle()` and never recomputes.
- `RangedManifest::validate` calls only `get_merkle_root()` (stored) and `if_proves_key()`, whose
  walk compares via `path_slice()` / `path_mask()` and never touches `path_steps()`.

Confirmed empirically: a manifest carrying a 32 768-byte `CompressedPathRaw` in proof node 0 was
**accepted without panic**, and the victim proceeded to chunk download.

This matters beyond bookkeeping. A test that proves a defect by calling `TrieProofNode::new`
directly proves the defect **exists**; it does not prove any message **delivers** it. Those are
different claims, and only the second one is a vulnerability. We publish the correction because the
first version of this analysis would have sent an operator looking at the wrong message type.

## Reproduction

Wire-delivered and reproduced **twice, deterministically**, on 2026-08-20 against v3.0.3 @ `f44f1cb`,
via a MITM peer serving a crafted `SnapshotChunkResponse` after an honest manifest.

Three packet captures are published in the public dataset
[`NullRabbit/nr-bundles-public`](https://huggingface.co/datasets/NullRabbit/nr-bundles-public),
primitive `conflux_snapshot_chunk_overlong_key_path_steps_panic`, family `state_import_abuse`:

| bundle | packets |
|---|---|
| `crp_112394a584a14cab` | 228 |
| `crp_3bf9bf2169794de1` | 229 |
| `crp_f713e83b51ef401d` | 234 |

All three record `victim_panicked = true`.

## What operators should do

1. **Upgrade to v3.1.0 or later.** This is the whole fix. If you are on v3.0.3 or v3.0.3-fix — the
   current release for four months of 2026 — you are exposed to an unauthenticated remote panic.
2. **Do not read "no CVE" as "no security impact."** The fix shipped as a storage hardening change
   with no advisory attached. Version-based exposure tracking against CVE feeds alone will not
   surface this one.
3. If you cannot upgrade immediately, note that exposure is via **snapshot sync**: a node that is
   not performing state sync is not on this path.

## Why we are publishing a fixed bug

The defect is remediated upstream and has been for a month, so there is nothing here an attacker
gains that reading PR #3560 would not already give them. What is not public is that the pre-v3.1.0
path was **remotely reachable by an unauthenticated peer** and that reaching it takes one ordinary
message. A silent fix leaves every operator who has not upgraded believing a storage patch is
optional. It is not.

---

*NullRabbit publishes operator advisories for issues that fall outside paid bounty scope. This
advisory replicates a publicly fixed defect; it contains packet captures demonstrating reachability
and no exploit tooling beyond them.*
