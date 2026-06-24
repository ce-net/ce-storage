//! Live end-to-end tests for the two object features whose node-touching paths the unit tests
//! deliberately stub: **multipart / resumable upload** and **sealed (client-side encrypted) objects**.
//!
//! The `src/multipart.rs` and `src/seal.rs` unit tests cover the pure logic (manifest assembly, the
//! AEAD construction). What they cannot exercise is the actual blob round trip through a node:
//! storing each part's chunks, assembling a combined manifest, binding it, and reading the assembled
//! object back byte-for-byte (including a ranged read that spans across two parts' chunks); and
//! sealing → storing ciphertext → fetching → unsealing, proving the host never sees plaintext and a
//! wrong key is rejected. Those are what this file asserts against a fresh ephemeral node.
//!
//! If the release `ce` binary isn't built, every test logs the reason and returns early (pass), so
//! the suite is green where a node cannot run and meaningful where one exists.
//!
//! Run with: `cargo test -p ce-storage --test live_multipart_seal -- --nocapture`
//! Disable explicitly with: `CE_NO_LIVE=1 cargo test`.

mod harness;

use std::path::PathBuf;

use ce_storage::store::{PutOptions, Store};
use harness::{Node, live_available};

const MIB: usize = 1024 * 1024;

fn temp_index(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ce-storage-mps-{}-{}-{tag}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

/// A deterministic byte pattern so equality failures are easy to localise.
fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

/// Full multipart flow against a live node: create → upload two whole-MiB parts + a short final
/// part → complete → read back byte-for-byte → ranged read across a part boundary. The assembled
/// object's CID must equal the CID of the same bytes stored via a single `put_object` (the manifest
/// is content-addressed and order-preserving), proving multipart is a zero-copy reassembly.
#[tokio::test]
async fn live_multipart_upload_roundtrip() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    let node = Node::start(None).await?;
    let index_path = temp_index("mp");
    let _ = std::fs::remove_file(&index_path);
    let mut store = Store::with_client(node.client.clone(), index_path.clone())?;
    let bucket = "mp-bucket";
    store.make_bucket(bucket)?;

    // Three parts: 2 MiB, 2 MiB (both whole multiples of the 1 MiB part chunk → valid non-final),
    // then a 500 KiB short final part. Total 4.5 MiB + 500 KiB.
    let p1 = pattern(2 * MIB);
    let p2 = pattern(2 * MIB)
        .iter()
        .map(|b| b ^ 0x5a)
        .collect::<Vec<_>>();
    let p3 = pattern(500 * 1024)
        .iter()
        .map(|b| b.wrapping_add(7))
        .collect::<Vec<_>>();
    let whole: Vec<u8> = p1.iter().chain(&p2).chain(&p3).copied().collect();

    let opts = PutOptions::of_type("application/octet-stream");
    let upload_id = store
        .create_multipart_upload(bucket, "big/object.bin", &opts)
        .await?;

    let e1 = store.upload_part(&upload_id, 1, &p1).await?;
    let e2 = store.upload_part(&upload_id, 2, &p2).await?;
    let e3 = store.upload_part(&upload_id, 3, &p3).await?;

    // Parts are listed in number order with their content-addressed etags.
    let parts = store.list_parts(&upload_id)?;
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0].etag, e1);
    assert_eq!(parts[2].size, p3.len() as u64);

    let meta = store
        .complete_multipart_upload(
            &upload_id,
            &[(1, e1.clone()), (2, e2.clone()), (3, e3.clone())],
        )
        .await?;
    assert_eq!(meta.size, whole.len() as u64);

    // The upload record is gone after completion.
    assert!(
        store.list_parts(&upload_id).is_err(),
        "completed upload is no longer listable"
    );

    // Read the assembled object back byte-for-byte.
    let got = store.get_object(bucket, "big/object.bin").await?;
    assert_eq!(
        got.bytes, whole,
        "assembled multipart object must match exactly"
    );

    // Ranged read straddling the part-1/part-2 boundary (offset 2 MiB) returns the exact window,
    // fetching only the covering chunks of the assembled manifest.
    let start = 2 * MIB - 5;
    let end = 2 * MIB + 5;
    let ranged = store
        .get_object_range(bucket, "big/object.bin", &format!("bytes={start}-{end}"))
        .await?;
    assert_eq!(ranged.range, Some((start as u64, end as u64)));
    assert_eq!(
        ranged.bytes,
        whole[start..=end],
        "cross-part ranged read exact"
    );

    // The assembled CID equals the CID of a single-shot put of identical bytes (content-addressed,
    // zero-copy reassembly): same chunks in the same order → same manifest → same hash.
    let single = store
        .put_object(bucket, "single.bin", &whole, "application/octet-stream")
        .await?;
    assert_eq!(
        meta.cid, single.cid,
        "multipart assembly is byte-identical to a single put"
    );

    let _ = std::fs::remove_file(&index_path);
    Ok(())
}

/// Aborting a multipart upload drops the record; completing a non-existent upload errors; a part
/// whose size is not a whole multiple of the part chunk (and is not last) is rejected at completion.
#[tokio::test]
async fn live_multipart_abort_and_validation() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    let node = Node::start(None).await?;
    let index_path = temp_index("mpabort");
    let _ = std::fs::remove_file(&index_path);
    let mut store = Store::with_client(node.client.clone(), index_path.clone())?;
    store.make_bucket("ab")?;

    let opts = PutOptions::default();
    let upload_id = store.create_multipart_upload("ab", "x", &opts).await?;
    // A non-final part that is NOT a whole multiple of the 1 MiB chunk (1.5 MiB).
    let odd = pattern(MIB + MIB / 2);
    let final_part = pattern(10);
    let oe = store.upload_part(&upload_id, 1, &odd).await?;
    let fe = store.upload_part(&upload_id, 2, &final_part).await?;
    // Completing with the 1.5 MiB part as non-final must be rejected (uniform-part rule).
    let bad = store
        .complete_multipart_upload(&upload_id, &[(1, oe.clone()), (2, fe.clone())])
        .await;
    assert!(bad.is_err(), "non-multiple non-final part must be rejected");

    // The upload still exists (completion failed, did not consume it); abort it.
    assert!(store.list_parts(&upload_id).is_ok());
    store.abort_multipart_upload(&upload_id)?;
    assert!(
        store.list_parts(&upload_id).is_err(),
        "aborted upload is gone"
    );
    // Abort is idempotent.
    store.abort_multipart_upload(&upload_id)?;

    // Completing an unknown upload id errors rather than panics.
    assert!(
        store
            .complete_multipart_upload("does-not-exist", &[(1, "etag".into())])
            .await
            .is_err()
    );

    let _ = std::fs::remove_file(&index_path);
    Ok(())
}

/// Sealed objects against a live node: encrypt-before-store means the node holds only ciphertext.
/// We seal, then read the raw stored bytes (which are the ciphertext) and assert the plaintext does
/// not appear; then unseal with the right key (exact round trip) and confirm a wrong key is rejected.
#[tokio::test]
async fn live_sealed_object_roundtrip() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    let node = Node::start(None).await?;
    let index_path = temp_index("seal");
    let _ = std::fs::remove_file(&index_path);
    let mut store = Store::with_client(node.client.clone(), index_path.clone())?;
    store.make_bucket("vault")?;

    let plaintext = b"the launch codes are 0000 (do not tell anyone)".repeat(64);
    let key = b"correct horse battery staple";
    let opts = PutOptions::default();
    let meta = store
        .put_object_sealed("vault", "secret.bin", &plaintext, key, &opts)
        .await?;
    // The stored object is marked sealed and opaque.
    assert_eq!(meta.content_type, ce_storage::seal::SEALED_CONTENT_TYPE);
    assert_eq!(
        meta.metadata.get("ce-sealed").map(String::as_str),
        Some("1")
    );

    // The RAW stored bytes (what the host sees) are ciphertext — the plaintext must not appear, and
    // the stored size is the ciphertext size (larger than plaintext: version+salt+tag overhead).
    let raw = store.get_object("vault", "secret.bin").await?;
    assert!(
        raw.bytes.len() > plaintext.len(),
        "ciphertext carries auth overhead"
    );
    assert!(
        !raw.bytes
            .windows(plaintext.len())
            .any(|w| w == plaintext.as_slice()),
        "plaintext must never appear in the stored bytes"
    );

    // Unseal with the right key → exact plaintext, reported as the plaintext length.
    let opened = store
        .get_object_sealed("vault", "secret.bin", key, None)
        .await?;
    assert_eq!(opened.bytes, plaintext, "sealed object round-trips");
    assert_eq!(opened.total_size, plaintext.len() as u64);

    // A wrong key is rejected (authentication fails) — never returns garbage plaintext.
    assert!(
        store
            .get_object_sealed("vault", "secret.bin", b"wrong key", None)
            .await
            .is_err(),
        "wrong key must fail authentication"
    );

    let _ = std::fs::remove_file(&index_path);
    Ok(())
}

/// Sealed objects compose with versioning: two seals of the same key under a versioned bucket keep
/// both versions, each independently openable by its version id.
#[tokio::test]
async fn live_sealed_object_versioned() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    let node = Node::start(None).await?;
    let index_path = temp_index("sealver");
    let _ = std::fs::remove_file(&index_path);
    let mut store = Store::with_client(node.client.clone(), index_path.clone())?;
    store.make_bucket("vv")?;
    store.set_versioning("vv", true)?;

    let key = b"shared key";
    let opts = PutOptions::default();
    let v1 = store
        .put_object_sealed("vv", "k", b"first secret", key, &opts)
        .await?;
    let v2 = store
        .put_object_sealed("vv", "k", b"second secret", key, &opts)
        .await?;
    assert_ne!(v1.version_id, v2.version_id, "distinct sealed versions");

    // Current unseals to "second secret".
    let cur = store.get_object_sealed("vv", "k", key, None).await?;
    assert_eq!(cur.bytes, b"second secret");
    // The older version unseals to "first secret" by its version id.
    let old = store
        .get_object_sealed("vv", "k", key, Some(&v1.version_id))
        .await?;
    assert_eq!(old.bytes, b"first secret");

    let _ = std::fs::remove_file(&index_path);
    Ok(())
}
