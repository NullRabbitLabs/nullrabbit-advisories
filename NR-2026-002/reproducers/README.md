# NR-2026-002 reproducers

Two independent reproducers for the Agave snapshot bootstrap crash
(`state_import_abuse` / oversized AppendVec `data_len` → index-generation panic).

## 1. Unit-level — proves the crash (`append_vec_datalen_panic_tests.rs`)

Two tests against the real Agave deserializer. Drop them into
`accounts-db/src/append_vec.rs`'s `#[cfg(test)] mod tests` (they use in-crate,
`pub(crate)` items, so they must live inside the crate). Then, from an `agave`
checkout:

```
cargo test -p solana-accounts-db --lib --features dev-context-only-utils \
    append_vec::tests::test_malformed_snapshot_oversized_data_len -- --nocapture
```

- `test_malformed_snapshot_oversized_data_len_scan_errors` — the real
  `scan_accounts` (the call index generation makes) returns
  `Err(Io(QuotaExceeded))` on a crafted 136-byte AppendVec with
  `data_len = MAX_PERMITTED_DATA_LENGTH + 1`, opened via the real
  `new_for_startup` (the path that skips per-account sanitization).
- `test_malformed_snapshot_oversized_data_len_panics_index_gen` — the exact
  `scan_accounts(..).expect("must scan accounts storage")` pattern panics with
  the production message.

Measured against 4.2.0-alpha.0; the relevant functions are byte-identical in
v4.1.0 (current stable). On recent `master` the `new_for_startup` signature
changed (dropped the length/access-mode parameters) — the test bodies need a
one-line signature update to compile there; the mechanism is unchanged.

## 2. Traffic-level — the wire signature

A driver crafts the malicious snapshot archive (a `version` file, a bank-manifest
stub, and `accounts/<slot>.<id>` = the 136-byte AppendVec whose
`StoredMeta.data_len = MAX_PERMITTED_DATA_LENGTH + 1`), serves it over loopback
HTTP, and fetches it — reproducing the snapshot download an untrusted peer would
serve to a bootstrapping validator, with the malformed account length present on
the wire. The driver depends on NullRabbit's multimodal capture harness and is
maintained in the research tree; it is described here for completeness. It
captures the malicious serve/fetch (the traffic surface), not a live validator
crash — the crash itself is proven by reproducer #1.

## Scope

Neither reproducer is a turnkey attack against live infrastructure. They craft
and drive the parser / capture the download; they do not target or crash any
third-party validator.
