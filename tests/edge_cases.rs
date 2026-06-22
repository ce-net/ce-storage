//! Edge-case and failure-mode coverage for ce-storage's public library API that the in-module unit
//! tests don't reach: malformed ranges, empty objects, delimiter/continuation corner cases, key and
//! bucket validation boundaries, and capability inspection of malformed tokens.

use ce_storage::caps::{inspect_link, Scope};
use ce_storage::index::{valid_bucket_name, valid_key, Index, ObjectMeta};
use ce_storage::range::parse_range;

fn meta(cid: &str, size: u64) -> ObjectMeta {
    ObjectMeta::new(cid, size, "application/octet-stream", 1)
}

// ---------- range parsing edge cases ----------

#[test]
fn range_suffix_larger_than_object_clamps_to_whole() {
    // bytes=-1000 against a 100-byte object → the whole object.
    assert_eq!(parse_range("bytes=-1000", 100).unwrap(), (0, 99));
}

#[test]
fn range_start_at_last_byte_is_satisfiable() {
    assert_eq!(parse_range("bytes=99-99", 100).unwrap(), (99, 99));
    assert_eq!(parse_range("bytes=99-", 100).unwrap(), (99, 99));
}

#[test]
fn range_start_past_end_unsatisfiable() {
    assert!(parse_range("bytes=100-", 100).is_err());
    assert!(parse_range("bytes=100-200", 100).is_err());
}

#[test]
fn range_rejects_garbage_and_negatives() {
    assert!(parse_range("bytes=abc-def", 100).is_err());
    assert!(parse_range("bytes=-", 100).is_err());
    assert!(parse_range("bytes=10-5", 100).is_err()); // start>end
    assert!(parse_range("", 100).is_err());
    assert!(parse_range("bytes=", 100).is_err());
}

#[test]
fn range_zero_suffix_unsatisfiable() {
    assert!(parse_range("bytes=-0", 100).is_err());
}

#[test]
fn range_whitespace_tolerated() {
    assert_eq!(parse_range("  bytes=0-9  ", 100).unwrap(), (0, 9));
}

// ---------- bucket/key validation boundaries ----------

#[test]
fn bucket_name_length_boundaries() {
    assert!(valid_bucket_name(&"a".repeat(2)).is_err()); // < 3
    assert!(valid_bucket_name(&"a".repeat(3)).is_ok()); // == 3
    assert!(valid_bucket_name(&"a".repeat(63)).is_ok()); // == 63
    assert!(valid_bucket_name(&"a".repeat(64)).is_err()); // > 63
}

#[test]
fn bucket_name_rejects_uppercase_and_underscore() {
    assert!(valid_bucket_name("Bucket").is_err());
    assert!(valid_bucket_name("bad_name").is_err());
    assert!(valid_bucket_name("good.name-1").is_ok());
}

#[test]
fn key_validation_boundaries() {
    assert!(valid_key("").is_err());
    assert!(valid_key("k").is_ok());
    assert!(valid_key(&"k".repeat(1024)).is_ok());
    assert!(valid_key(&"k".repeat(1025)).is_err());
    assert!(valid_key("has\0nul").is_err());
    // unicode keys are allowed (byte length is what counts)
    assert!(valid_key("naïve/key/✓").is_ok());
}

// ---------- listing edge cases ----------

#[test]
fn list_empty_bucket_is_empty_page() {
    let mut idx = Index::default();
    idx.make_bucket("buk", 1).unwrap();
    let page = idx.list("buk", "", None, None, 100).unwrap();
    assert!(page.keys.is_empty());
    assert!(page.common_prefixes.is_empty());
    assert!(!page.is_truncated);
    assert!(page.next_continuation.is_none());
}

#[test]
fn list_missing_bucket_errors() {
    let idx = Index::default();
    assert!(idx.list("nope", "", None, None, 100).is_err());
}

#[test]
fn list_max_keys_zero_treated_as_one() {
    let mut idx = Index::default();
    idx.make_bucket("buk", 1).unwrap();
    for k in ["a", "b", "c"] {
        idx.put("buk", k, meta("c", 1)).unwrap();
    }
    let page = idx.list("buk", "", None, None, 0).unwrap();
    assert_eq!(page.keys.len(), 1, "max_keys 0 is clamped to 1");
    assert!(page.is_truncated);
}

#[test]
fn list_delimiter_counts_prefixes_toward_max_keys() {
    let mut idx = Index::default();
    idx.make_bucket("buk", 1).unwrap();
    for k in ["x/1", "y/1", "z/1"] {
        idx.put("buk", k, meta("c", 1)).unwrap();
    }
    // 3 distinct folders, max_keys 2 → truncated after 2 common prefixes.
    let page = idx.list("buk", "", Some("/"), None, 2).unwrap();
    assert_eq!(page.common_prefixes.len(), 2);
    assert!(page.is_truncated);
    assert!(page.next_continuation.is_some());
    // continue from the token: the remaining folder appears.
    let cont = page.next_continuation.unwrap();
    let page2 = idx.list("buk", "", Some("/"), Some(&cont), 100).unwrap();
    assert_eq!(page2.common_prefixes, vec!["z/".to_string()]);
}

#[test]
fn list_mixed_keys_and_folders_under_prefix() {
    let mut idx = Index::default();
    idx.make_bucket("buk", 1).unwrap();
    // "photos/cover.jpg" is a direct key; "photos/2026/x" rolls into a folder.
    for k in ["photos/cover.jpg", "photos/2026/a", "photos/2026/b", "photos/2025/c"] {
        idx.put("buk", k, meta("c", 1)).unwrap();
    }
    let page = idx.list("buk", "photos/", Some("/"), None, 100).unwrap();
    assert_eq!(page.keys.len(), 1, "cover.jpg is a direct key");
    assert_eq!(page.keys[0].0, "photos/cover.jpg");
    assert_eq!(
        page.common_prefixes,
        vec!["photos/2025/".to_string(), "photos/2026/".to_string()]
    );
}

#[test]
fn copy_from_missing_source_errors() {
    let mut idx = Index::default();
    idx.make_bucket("buk", 1).unwrap();
    assert!(idx.copy("buk", "ghost", "b", "dst", 1).is_err());
}

#[test]
fn put_into_missing_bucket_errors() {
    let mut idx = Index::default();
    assert!(idx.put("nope", "k", meta("c", 1)).is_err());
}

#[test]
fn head_missing_key_errors() {
    let mut idx = Index::default();
    idx.make_bucket("buk", 1).unwrap();
    assert!(idx.head("buk", "absent").is_err());
}

// ---------- index persistence robustness ----------

#[test]
fn load_missing_file_yields_empty_index() {
    let path = std::env::temp_dir().join(format!("ce-storage-noexist-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let idx = Index::load(&path).unwrap();
    assert!(idx.buckets.is_empty());
}

#[test]
fn load_corrupt_file_errors_not_panics() {
    let path = std::env::temp_dir().join(format!("ce-storage-corrupt-{}.json", std::process::id()));
    std::fs::write(&path, b"{ this is not valid json ][").unwrap();
    let r = Index::load(&path);
    assert!(r.is_err(), "corrupt index must error, not panic");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn save_load_preserves_large_sizes() {
    // A size beyond 2^53 must survive JSON (u64, not f64).
    let path = std::env::temp_dir().join(format!("ce-storage-big-{}.json", std::process::id()));
    let big: u64 = (1u64 << 60) + 12345;
    let mut idx = Index::default();
    idx.make_bucket("buk", 1).unwrap();
    idx.put("buk", "k", meta("cid", big)).unwrap();
    idx.save(&path).unwrap();
    let back = Index::load(&path).unwrap();
    assert_eq!(back.head("buk", "k").unwrap().size, big);
    let _ = std::fs::remove_file(&path);
}

// ---------- capability token inspection robustness ----------

#[test]
fn inspect_garbage_token_errors_not_panics() {
    assert!(inspect_link("not a hex token").is_err());
    assert!(inspect_link("").is_err());
    assert!(inspect_link("deadbeef").is_err());
}

#[test]
fn scope_from_caveat_without_slash_is_whole_bucket() {
    let s = Scope::from_caveat("just-bucket");
    assert_eq!(s.bucket, "just-bucket");
    assert_eq!(s.prefix, "");
}
