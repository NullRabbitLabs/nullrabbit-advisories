# NR-2026-002 — Agave snapshot bootstrap crash via malformed AppendVec account length

**NullRabbit Operator Advisory** · Published 2026-07-02

> **Why we publish publicly:** these are out-of-scope-for-bounty, no-embargo node-availability findings — analysis + reproducer only. See [Why we publish these findings publicly](../WHY-WE-PUBLISH.md).

## Summary

A validator that bootstraps from a snapshot fetched from an untrusted peer —
the **default configuration** of `agave-validator run` when `--known-validators`
is not set — can be made to **panic and abort during snapshot loading** by a
single malformed field in the snapshot. A snapshot whose account-storage file
(AppendVec) declares one account with a `data_len` larger than the 10 MiB
per-account maximum triggers a fatal error in index generation, **before** the
snapshot hash is ever checked. The crash is deterministic and needs no valid
account data — a ~136-byte crafted storage file is sufficient.

This affects nodes **while they are loading a snapshot**: newly-joining
validators, and validators restarting without a local snapshot. It does not
affect a validator in steady state. It is an availability issue only — no
memory corruption, no funds/consensus impact.

**Operator mitigation is available today and does not require an upstream fix:
set `--known-validators`** so an attacker cannot be selected as your snapshot
source.

## Findings at a glance

| Item | Detail |
|---|---|
| Class | Malformed bulk-state import → reachable panic during snapshot index generation (`state_import_abuse`) |
| Reachability | Remote, unauthenticated, pre-consensus; gated on the victim being in snapshot-fetch state and on `--known-validators` being unset |
| Trigger | One AppendVec account with `StoredMeta.data_len > MAX_PERMITTED_DATA_LENGTH` (10 MiB) in the served snapshot |
| Impact | Deterministic crash/abort of the bootstrapping/restarting node, before the snapshot hash gate. Recoverable on restart; re-fetching from the same/colluding peer re-crashes (boot-loop) |
| Severity | High for availability of bootstrapping nodes in default config; not steady-state, not RCE |
| Mitigation | `--known-validators` (primary). Also: prefer a trusted local/known snapshot source when bootstrapping |

## Affected versions

- **v4.1.0** (current stable release) — the relevant code is byte-identical to the build the crash was
  measured against.
- **4.2.0-alpha.0** (`3e9a16d6e6`) — the build measured.
- **master** (as of 2026-07-01) — present and, if anything, easier to reach: the per-account layout
  sanitization was removed from the startup path (length is derived from the file size, so the skip is
  unconditional) and the alternate Mmap storage backing was removed (File-backed only, so the panic is
  the sole outcome — there is no silent-skip path).

## Mechanism (source-cited, agave v4.1.0)

Three trust assumptions compose:

1. **Reconstruction skips per-account validation.** When a snapshot storage is rebuilt,
   `AppendVec::new_for_startup` trusts the storage length and, when it equals the file size (which the
   attacker controls), returns **without** running `sanitize_layout_and_length()`. The per-account
   `sanitize()` checks only the executable byte and lamports — it never bounds `data_len`.
   (`accounts-db/src/append_vec.rs`; on master, length is taken from `FileInfo::size` and sanitization
   is skipped unconditionally.)

2. **Index generation treats an oversized `data_len` as a fatal error.** Building the accounts index
   reads every account (folding it into the accounts lattice hash) via the File-backed scan, using a
   reader whose buffer is capped at `STORE_META_OVERHEAD + MAX_PERMITTED_DATA_LENGTH`. The scan requests
   `STORE_META_OVERHEAD + data_len` bytes with no cap on `data_len`; when `data_len` exceeds 10 MiB the
   reader returns a quota error and the scan returns `Err`. `generate_index_for_slot` calls
   `.expect("must scan accounts storage")` on that result — so it **panics**. (`accounts-db/src/accounts_db.rs`.)

3. **This is before the hash gate.** The accounts lattice hash that snapshot verification checks is
   *produced by* the index generation that panics, so the hash gate never runs.

Index generation scans every storage, so one malicious AppendVec among many legitimate ones is enough.

## Reproduction

Two independent reproducers accompany this advisory (see `reproducers/`):

- **Unit-level (proves the crash):** two tests against the real Agave deserializer craft a 136-byte
  AppendVec with `data_len = MAX_PERMITTED_DATA_LENGTH + 1` and drive the exact index-generation call.
  Measured panic: `must scan accounts storage: Io(Custom { kind: QuotaExceeded, error: "requested more
  bytes than allowed capacity range" })`.
- **Traffic-level (shows the wire signature):** a driver that crafts the malicious snapshot archive,
  serves it over HTTP, and fetches it — the malformed account length is visible on the wire, in the
  snapshot download an untrusted peer would serve to a bootstrapping validator.

Neither reproducer is a turnkey attack against live infrastructure: they craft and drive the parser /
capture the download, not "crash an arbitrary mainnet validator."

## Vendor channel and scope

The canonical vendor policy for Agave is `anza-xyz/agave` `SECURITY.md`. This finding is **out of scope
for the Agave bug-bounty program** on two stated grounds: (1) node-stability issues during the bootstrap
phase that are trivially mitigated by configuration (`--known-validators`); and (2) maliciously-crafted
snapshots, which the policy declares a known trust-on-first-use limitation with an improvement effort
"actively underway." Because it is out of scope, it is **not** an embargoed vendor report — this operator
advisory exists precisely to give operators the mitigation now, since the class is acknowledged but not
treated as a program vulnerability. Operators should not wait for an upstream patch; set
`--known-validators`.

## Provenance

NullRabbit original research (our own measurement), grounded on the vendor-public `SECURITY.md`.
Cross-references: NullRabbit finding id `SOL_SNAPSHOT_APPENDVEC_OVERSIZED_DATALEN_INDEXGEN_PANIC`;
detection primitive `sol_snapshot_oversized_datalen_indexgen_panic` (family `state_import_abuse`).

## Contact

Simon Morley, NullRabbit — `simon@nullrabbit.ai`.
