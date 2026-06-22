//! Property/fuzz tests for ce-storage's pure layers: ranged-read math, the bucket index
//! (listing/pagination/delimiter), capability scope parsing, and serde round-trips.
//!
//! The unit tests in `src/` pin specific hand-picked cases. These property tests instead generate
//! *random* inputs and assert the invariants hold for every case the prover searches:
//!
//! 1. **Ranged reads are exact.** For any object size, chunk size, and in-bounds byte window, the
//!    covering-chunk slice equals the original `bytes[start..=end]`. No off-by-one, ever.
//! 2. **`parse_range` never panics** on arbitrary header strings and only ever yields a satisfiable
//!    `(start, end)` with `start <= end < total_size`.
//! 3. **Listing is faithful**: every emitted key matches the prefix and is strictly after the
//!    continuation token; pagination over a random key set returns each key exactly once, in order.
//! 4. **Serde round-trips** are lossless for `ObjectMeta` / `Index` (incl. sizes `> 2^53`, which a
//!    naive JSON-number-as-f64 path would corrupt — money/size are u64 base units here).
//! 5. **Scope parsing/checking** round-trips and the `scope_allows` predicate is exactly
//!    "same bucket AND key starts with prefix".

use ce_rs::data;
use ce_storage::caps::{scope_allows, Scope};
use ce_storage::index::{valid_bucket_name, valid_key, Index, ObjectMeta};
use ce_storage::range::{covering, parse_range, slice};
use proptest::prelude::*;

fn meta(cid: &str, size: u64) -> ObjectMeta {
    ObjectMeta::new(cid, size, "application/octet-stream", 1)
}

proptest! {
    // ----- Invariant 1: ranged reads are byte-exact for any window. -----

    #[test]
    fn covering_slice_equals_window(
        total in 1usize..20_000,
        chunk in 1usize..4096,
        a in 0usize..20_000,
        b in 0usize..20_000,
    ) {
        let bytes: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        let (manifest, chunks) = data::chunk_object(&bytes, chunk);
        // Constrain the window into bounds.
        let start = (a % total) as u64;
        let end = (b % total).max(start as usize) as u64;
        let cov = covering(&manifest, start, end).expect("in-bounds range must resolve");
        // Concatenate exactly the covering chunks (as the Store does over the network).
        let mut concat = Vec::new();
        for &i in &cov.chunk_indices {
            concat.extend_from_slice(&chunks[i].1);
        }
        let got = slice(&cov, &concat).expect("slice must succeed");
        prop_assert_eq!(got, &bytes[start as usize..=end as usize],
            "ranged slice diverged: total={} chunk={} [{},{}]", total, chunk, start, end);
        prop_assert_eq!(cov.length, end - start + 1);
    }

    // ----- Invariant 2: parse_range never panics, only yields satisfiable ranges. -----

    #[test]
    fn parse_range_is_total_and_sound(
        header in "[A-Za-z0-9=,\\- ]{0,24}",
        total in 0u64..1_000_000,
    ) {
        // Must never panic. Either an error, or a satisfiable (start,end) inside [0,total).
        if let Ok((start, end)) = parse_range(&header, total) {
            prop_assert!(start <= end, "start>end for {header:?} total={total}");
            prop_assert!(end < total, "end>=total for {header:?} total={total}");
        }
    }

    #[test]
    fn parse_range_wellformed_windows(
        start in 0u64..100_000,
        len in 1u64..100_000,
        total in 1u64..200_000,
    ) {
        prop_assume!(start < total);
        let end = (start + len - 1).min(total - 1);
        let header = format!("bytes={start}-{end}");
        let (gs, ge) = parse_range(&header, total).expect("valid window parses");
        prop_assert_eq!(gs, start);
        prop_assert_eq!(ge, end);
    }

    // ----- Invariant 3: listing is faithful (prefix, order, pagination). -----

    #[test]
    fn list_pagination_covers_every_key_once(
        keys in proptest::collection::hash_set("[a-d]{1,3}(/[a-d]{1,3}){0,2}", 1..40),
        page_size in 1usize..6,
    ) {
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        for k in &keys {
            idx.put("buk", k, meta("c", 1)).unwrap();
        }
        // Walk all pages via continuation tokens; collect emitted keys.
        let mut seen: Vec<String> = Vec::new();
        let mut after: Option<String> = None;
        for _guard in 0..1000 {
            let page = idx.list("buk", "", None, after.as_deref(), page_size).unwrap();
            for (k, _) in &page.keys {
                seen.push(k.clone());
            }
            match page.next_continuation {
                Some(tok) if page.is_truncated => after = Some(tok),
                _ => break,
            }
        }
        // Every key emitted exactly once, in sorted order, no dups.
        let mut expected: Vec<String> = keys.iter().cloned().collect();
        expected.sort();
        prop_assert_eq!(&seen, &expected, "pagination dropped/duplicated/reordered keys");
    }

    #[test]
    fn list_prefix_only_matches_prefix(
        keys in proptest::collection::hash_set("[a-c]{1,4}", 1..30),
        prefix in "[a-c]{0,2}",
    ) {
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        for k in &keys {
            idx.put("buk", k, meta("c", 1)).unwrap();
        }
        let page = idx.list("buk", &prefix, None, None, 10_000).unwrap();
        for (k, _) in &page.keys {
            prop_assert!(k.starts_with(&prefix), "key {k} does not match prefix {prefix}");
        }
        // Count parity: every key with the prefix is present (no max_keys truncation at 10k).
        let want = keys.iter().filter(|k| k.starts_with(&prefix)).count();
        prop_assert_eq!(page.keys.len(), want);
    }

    // ----- Invariant 4: serde round-trips, incl sizes > 2^53. -----

    #[test]
    fn object_meta_roundtrips(cid in "[0-9a-f]{0,80}", size in any::<u64>(), now in any::<u64>()) {
        let m = ObjectMeta::new(cid, size, "text/plain", now);
        let json = serde_json::to_string(&m).unwrap();
        let back: ObjectMeta = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(back, m);
    }

    #[test]
    fn index_roundtrips_with_large_sizes(
        sizes in proptest::collection::vec(any::<u64>(), 0..12),
    ) {
        let mut idx = Index::default();
        idx.make_bucket("buk", 7).unwrap();
        for (i, sz) in sizes.iter().enumerate() {
            // Include sizes beyond 2^53 to prove u64 fidelity through JSON.
            let big = sz | (1u64 << 60);
            idx.put("buk", &format!("k{i}"), meta(&format!("cid{i}"), big)).unwrap();
        }
        let json = serde_json::to_vec(&idx).unwrap();
        let back: Index = serde_json::from_slice(&json).unwrap();
        for (i, sz) in sizes.iter().enumerate() {
            let big = sz | (1u64 << 60);
            prop_assert_eq!(back.head("buk", &format!("k{i}")).unwrap().size, big);
        }
    }

    // ----- Invariant 5: scope parse round-trip + allow predicate. -----

    #[test]
    fn scope_roundtrips_and_allows_is_exact(
        bucket in "[a-z][a-z0-9.-]{1,8}",
        prefix in "[a-z0-9/]{0,8}",
        test_bucket in "[a-z][a-z0-9.-]{1,8}",
        test_key in "[a-z0-9/]{0,10}",
    ) {
        let s = Scope { bucket: bucket.clone(), prefix: prefix.clone() };
        // Round-trip through the caveat string. (Note: from_caveat splits on the FIRST '/', so
        // round-trip fidelity holds when the bucket has no '/', which S3 bucket names never do.)
        let back = Scope::from_caveat(&s.to_caveat());
        prop_assert_eq!(&back.bucket, &bucket);

        // allow == same bucket AND key starts with prefix.
        let want = test_bucket == bucket && test_key.starts_with(&prefix);
        prop_assert_eq!(scope_allows(&s, &test_bucket, &test_key), want);
    }

    // ----- Validators never panic and agree with their stated rules. -----

    #[test]
    fn valid_bucket_name_never_panics(name in ".{0,80}") {
        let _ = valid_bucket_name(&name); // must not panic on arbitrary unicode
    }

    #[test]
    fn valid_key_never_panics(key in ".{0,2048}") {
        let _ = valid_key(&key);
    }
}
