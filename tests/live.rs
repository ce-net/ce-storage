//! Live integration tests for ce-storage against a real ephemeral CE node.
//!
//! These exercise the *actual* content-addressed blob round trip through the node's `/objects` +
//! `/blobs` API — the path the `src/` unit tests deliberately stub out. A fresh ephemeral node is
//! stood up per test (never the operator's :8844 node), and we assert:
//!
//! * put/get/list/delete round-trip, including an object spanning **more than one chunk** (the
//!   manifest path), byte-for-byte;
//! * **CID integrity** — the ETag is the content address, identical bytes dedup to the same CID, and
//!   a flipped byte yields a different CID;
//! * ranged GET fetches only the covering chunks and returns the exact window;
//! * **capability bucket scope** — a `storage:read` link scoped to one bucket/prefix authorizes a key
//!   under it and rejects keys outside it, verified offline.
//!
//! If the release `ce` binary isn't built, every test logs the reason and returns early (pass), so
//! the suite is green on a machine that can't run a node and meaningful where one exists.
//!
//! Run with: `cargo test -p ce-storage --test live -- --nocapture`
//! Disable explicitly with: `CE_NO_LIVE=1 cargo test`.

mod harness;

use std::path::PathBuf;

use ce_storage::caps::{ABILITY_READ, ABILITY_WRITE, Scope, mint_link, verify_link};
use ce_storage::store::{Preconditions, PutOptions, Store};
use harness::{Node, live_available};

fn temp_index(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ce-storage-live-{}-{}-{tag}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

/// Full S3-verb round trip over a live node, with a multi-chunk object exercising the manifest path.
#[tokio::test]
async fn live_full_object_lifecycle_multichunk() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    let node = Node::start(None).await?;
    let index_path = temp_index("life");
    let _ = std::fs::remove_file(&index_path);
    let mut store = Store::with_client(node.client.clone(), index_path.clone())?;

    let bucket = "live-objects";
    store.make_bucket(bucket)?;

    // 2.5 MiB spans multiple 1 MiB chunks → forces the manifest/chunk path.
    let payload: Vec<u8> = (0..2_500_000u32).map(|i| (i % 251) as u8).collect();

    let meta = store
        .put_object(
            bucket,
            "data/blob.bin",
            &payload,
            "application/octet-stream",
        )
        .await?;
    assert_eq!(meta.size, payload.len() as u64);
    assert_eq!(meta.etag, meta.cid, "ETag must be the content address");

    // Full GET round-trips byte-for-byte.
    let got = store.get_object(bucket, "data/blob.bin").await?;
    assert_eq!(
        got.bytes, payload,
        "full multi-chunk object must match exactly"
    );
    assert_eq!(got.etag, meta.cid);

    // Ranged GET across a chunk boundary returns exactly the window.
    let ranged = store
        .get_object_range(bucket, "data/blob.bin", "bytes=1048570-1048580")
        .await?;
    assert_eq!(ranged.range, Some((1_048_570, 1_048_580)));
    assert_eq!(ranged.bytes, payload[1_048_570..=1_048_580]);

    // A tiny (single inline blob) object also round-trips and ranges.
    let small = b"hello world".to_vec();
    store
        .put_object(bucket, "small.txt", &small, "text/plain")
        .await?;
    let sg = store.get_object(bucket, "small.txt").await?;
    assert_eq!(sg.bytes, small);
    let sr = store
        .get_object_range(bucket, "small.txt", "bytes=0-4")
        .await?;
    assert_eq!(sr.bytes, b"hello");

    // List with the shared prefix sees both data/ keys (not small.txt).
    let page = store.list_objects(bucket, "data/", Some("/"), None, 100)?;
    assert_eq!(page.keys.len(), 1, "blob.bin");

    // Delete one key; the other remains.
    store.delete_object(bucket, "data/blob.bin")?;
    assert!(store.head_object(bucket, "data/blob.bin").is_err());
    assert!(store.head_object(bucket, "small.txt").is_ok());

    let _ = std::fs::remove_file(&index_path);
    Ok(())
}

/// CID integrity: identical bytes dedup to one CID; a single flipped byte changes it; CopyObject
/// shares the CID with no upload.
#[tokio::test]
async fn live_cid_integrity_and_dedup() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    let node = Node::start(None).await?;
    let index_path = temp_index("cid");
    let _ = std::fs::remove_file(&index_path);
    let mut store = Store::with_client(node.client.clone(), index_path.clone())?;
    let bucket = "cid-bucket";
    store.make_bucket(bucket)?;

    let a: Vec<u8> = (0..1_500_000u32).map(|i| (i % 97) as u8).collect();
    let mut b = a.clone();
    b[123_456] ^= 0xff; // flip one byte deep inside

    let m_a = store
        .put_object(bucket, "a.bin", &a, "application/octet-stream")
        .await?;
    let m_a2 = store
        .put_object(bucket, "a-copy.bin", &a, "application/octet-stream")
        .await?;
    let m_b = store
        .put_object(bucket, "b.bin", &b, "application/octet-stream")
        .await?;

    assert_eq!(
        m_a.cid, m_a2.cid,
        "identical bytes must share a content address (dedup)"
    );
    assert_ne!(m_a.cid, m_b.cid, "one flipped byte must change the CID");

    // CopyObject shares the CID; both keys resolve to the same bytes.
    store.copy_object(bucket, "a.bin", bucket, "linked.bin")?;
    assert_eq!(store.head_object(bucket, "linked.bin")?.cid, m_a.cid);
    let via_copy = store.get_object(bucket, "linked.bin").await?;
    assert_eq!(via_copy.bytes, a);

    let _ = std::fs::remove_file(&index_path);
    Ok(())
}

/// A get on a missing key / missing bucket errors gracefully (no panic), and a put into a missing
/// bucket short-circuits with an error before any network call.
#[tokio::test]
async fn live_missing_objects_error_gracefully() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    let node = Node::start(None).await?;
    let index_path = temp_index("missing");
    let _ = std::fs::remove_file(&index_path);
    let mut store = Store::with_client(node.client.clone(), index_path.clone())?;

    assert!(store.get_object("ghost-bucket", "k").await.is_err());
    store.make_bucket("present")?;
    assert!(store.get_object("present", "absent-key").await.is_err());
    assert!(
        store
            .put_object("ghost-bucket", "k", b"x", "text/plain")
            .await
            .is_err()
    );

    let _ = std::fs::remove_file(&index_path);
    Ok(())
}

/// Versioning, user metadata, and conditional requests round-trip against a real node.
#[tokio::test]
async fn live_versioning_metadata_and_conditionals() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    let node = Node::start(None).await?;
    let index_path = temp_index("vmc");
    let _ = std::fs::remove_file(&index_path);
    let mut store = Store::with_client(node.client.clone(), index_path.clone())?;
    store.make_bucket("vb")?;
    store.set_versioning("vb", true)?;

    // Put with user metadata + cache-control.
    let mut meta_map = std::collections::BTreeMap::new();
    meta_map.insert("author".to_string(), "leif".to_string());
    let opts = PutOptions {
        content_type: "text/plain".into(),
        metadata: meta_map.clone(),
        cache_control: Some("max-age=30".into()),
        ..Default::default()
    };
    let v1 = store.put_object_opts("vb", "k", b"one", &opts).await?;
    let _v2 = store.put_object("vb", "k", b"two", "text/plain").await?;

    // Current is "two"; the old version "one" is retrievable by id, with its metadata.
    let cur = store.get_object("vb", "k").await?;
    assert_eq!(cur.bytes, b"two");
    let old = store
        .get_object_opts("vb", "k", Some(&v1.version_id), &Preconditions::default())
        .await?;
    assert_eq!(old.bytes, b"one");
    assert_eq!(old.metadata.get("author").map(String::as_str), Some("leif"));
    assert_eq!(old.cache_control.as_deref(), Some("max-age=30"));

    // Conditional GET: If-None-Match with the current etag → NotModified.
    let pc = Preconditions {
        if_none_match: Some(cur.etag.clone()),
        ..Default::default()
    };
    let r = store.get_object_opts("vb", "k", None, &pc).await;
    assert!(
        matches!(r, Err(ce_storage::store::StorageError::NotModified)),
        "matching If-None-Match must be NotModified"
    );

    // Delete adds a marker; current hidden, old version survives.
    store.delete_object("vb", "k")?;
    assert!(store.head_object("vb", "k").is_err());
    let still = store
        .get_object_opts("vb", "k", Some(&v1.version_id), &Preconditions::default())
        .await?;
    assert_eq!(still.bytes, b"one");

    let _ = std::fs::remove_file(&index_path);
    Ok(())
}

/// Capability bucket-scope: a read link scoped to one bucket/prefix authorizes a covered key and
/// rejects keys outside the bucket or prefix. Verified entirely offline (the node is up only to
/// prove the pieces compose in a live context). This is the "presigned-equivalent" story.
#[tokio::test]
async fn live_capability_bucket_scope() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    // The node existing proves the app boots against a real node; cap verification is pure crypto.
    let node = Node::start(None).await?;

    // Load the node's own identity (the bucket owner / trust root for this scope).
    let owner = ce_identity::Identity::load_or_generate(&node.data_dir_path.join("identity"))?;

    let scope = Scope {
        bucket: "photos".into(),
        prefix: "2026/".into(),
    };
    let token = mint_link(&owner, owner.node_id(), ABILITY_READ, &scope, 0, 1)?;
    let never = |_: &ce_identity::NodeId, _: u64| false;

    // In scope: read photos/2026/* → ok.
    assert!(
        verify_link(
            &owner.node_id(),
            &[],
            &[],
            1000,
            &owner.node_id(),
            ABILITY_READ,
            "photos",
            "2026/sunset.jpg",
            &token,
            &never,
        )
        .is_ok()
    );

    // Wrong prefix → denied.
    assert!(
        verify_link(
            &owner.node_id(),
            &[],
            &[],
            1000,
            &owner.node_id(),
            ABILITY_READ,
            "photos",
            "2025/private.jpg",
            &token,
            &never,
        )
        .is_err()
    );

    // Wrong bucket → denied.
    assert!(
        verify_link(
            &owner.node_id(),
            &[],
            &[],
            1000,
            &owner.node_id(),
            ABILITY_READ,
            "documents",
            "2026/sunset.jpg",
            &token,
            &never,
        )
        .is_err()
    );

    // Wrong ability (write against a read link) → denied.
    assert!(
        verify_link(
            &owner.node_id(),
            &[],
            &[],
            1000,
            &owner.node_id(),
            ABILITY_WRITE,
            "photos",
            "2026/sunset.jpg",
            &token,
            &never,
        )
        .is_err()
    );

    drop(node);
    Ok(())
}

/// Lifecycle / TTL expiry against a live node: a real object is stored, a short TTL rule is set,
/// and after the TTL elapses `sweep_expired` actually deletes it (and is idempotent). A fresh object
/// written after the sweep survives. Exercises the real put → index → sweep → delete path end to end.
#[tokio::test]
async fn live_lifecycle_sweep_expires_objects() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    let node = Node::start(None).await?;
    let index_path = temp_index("lifecycle");
    let _ = std::fs::remove_file(&index_path);
    let mut store = Store::with_client(node.client.clone(), index_path.clone())?;

    let bucket = "live-lifecycle";
    store.make_bucket(bucket)?;

    // Store a real object through the node (content-addressed).
    store
        .put_object(bucket, "tmp/ephemeral.txt", b"will expire", "text/plain")
        .await?;
    assert!(store.head_object(bucket, "tmp/ephemeral.txt").is_ok());

    // 1-second TTL over the tmp/ prefix.
    store.set_lifecycle(
        bucket,
        vec![ce_storage::index::LifecycleRule {
            prefix: "tmp/".into(),
            expiration_secs: 1,
        }],
    )?;

    // Before the TTL elapses nothing is expired.
    assert!(store.expired_keys(bucket)?.is_empty(), "not yet expired");

    // Wait out the TTL, then sweep — the object must be deleted.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let deleted = store.sweep_expired(bucket)?;
    assert_eq!(deleted, vec!["tmp/ephemeral.txt".to_string()]);
    assert!(
        store.head_object(bucket, "tmp/ephemeral.txt").is_err(),
        "swept object is gone"
    );

    // Idempotent: a second sweep deletes nothing.
    assert!(store.sweep_expired(bucket)?.is_empty());

    // A freshly written object under the same prefix is not immediately expired.
    store
        .put_object(bucket, "tmp/fresh.txt", b"new", "text/plain")
        .await?;
    assert!(store.sweep_expired(bucket)?.is_empty(), "fresh object kept");
    assert!(store.head_object(bucket, "tmp/fresh.txt").is_ok());

    drop(node);
    Ok(())
}
