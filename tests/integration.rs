//! Integration test for the network-facing object verbs against the operator's **default** node on
//! `http://127.0.0.1:8844`. It stays `#[ignore]` because it targets that fixed shared node (which an
//! automated run must not disturb). The equivalent coverage — full content-addressed round trip,
//! multi-chunk object, ranged GET, dedup, copy, list, delete — now runs **un-ignored** against fresh
//! ephemeral nodes in `tests/live.rs`, so this file is kept only as the "point me at an existing
//! node" smoke test you can opt into with:
//!
//! ```text
//! ce start &                       # or point CE_API_TOKEN at a node you control
//! cargo test -p ce-storage --test integration -- --ignored --nocapture
//! ```

use ce_storage::store::Store;
use std::path::PathBuf;

fn temp_index() -> PathBuf {
    std::env::temp_dir().join(format!(
        "ce-storage-it-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

#[tokio::test]
#[ignore = "requires a running CE node on :8844"]
async fn full_object_roundtrip_against_node() {
    let index_path = temp_index();
    let _ = std::fs::remove_file(&index_path);
    let mut store = Store::open(index_path.clone()).expect("open store");

    // unique bucket so reruns do not collide
    let bucket = format!(
        "it-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );
    store.make_bucket(&bucket).expect("mb");

    // A 2.5 MiB object spans multiple 1 MiB chunks, exercising the manifest path.
    let payload: Vec<u8> = (0..2_500_000u32).map(|i| (i % 251) as u8).collect();

    let meta = store
        .put_object(&bucket, "data/blob.bin", &payload, "application/octet-stream")
        .await
        .expect("put_object");
    assert_eq!(meta.size, payload.len() as u64);
    assert_eq!(meta.etag, meta.cid, "ETag is the content address");

    // Full GET round-trips byte-for-byte.
    let got = store.get_object(&bucket, "data/blob.bin").await.expect("get");
    assert_eq!(got.bytes, payload, "full object must match");

    // Ranged GET returns exactly the requested window, fetching only covering chunks.
    let ranged = store
        .get_object_range(&bucket, "data/blob.bin", "bytes=1048570-1048580")
        .await
        .expect("ranged get");
    assert_eq!(ranged.range, Some((1_048_570, 1_048_580)));
    assert_eq!(ranged.bytes, payload[1_048_570..=1_048_580]);

    // Dedup: identical bytes under a second key resolve to the same CID.
    let meta2 = store
        .put_object(&bucket, "data/copy.bin", &payload, "application/octet-stream")
        .await
        .expect("put dup");
    assert_eq!(meta.cid, meta2.cid, "identical bytes share a content address");

    // CopyObject shares the CID with no upload.
    store
        .copy_object(&bucket, "data/blob.bin", &bucket, "data/linked.bin")
        .expect("copy");
    assert_eq!(
        store.head_object(&bucket, "data/linked.bin").unwrap().cid,
        meta.cid
    );

    // List with the shared prefix sees all three keys.
    let page = store
        .list_objects(&bucket, "data/", Some("/"), None, 100)
        .expect("list");
    assert_eq!(page.keys.len(), 3, "blob, copy, linked");

    // Delete one key; the others remain.
    store.delete_object(&bucket, "data/copy.bin").expect("rm");
    assert!(store.head_object(&bucket, "data/copy.bin").is_err());

    let _ = std::fs::remove_file(&index_path);
}
