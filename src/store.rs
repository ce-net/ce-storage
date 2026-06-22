//! The [`Store`] — the library API that maps S3 verbs onto the CE blob layer + the local bucket
//! index. This is what the CLI and the optional HTTP gateway both drive.
//!
//! Object bytes are content-addressed in the CE blob store via `ce-rs`:
//! `put_object` splits into 1 MiB chunks, stores each, and returns the manifest CID;
//! `get_object` resolves the manifest, pulls and hash-verifies every chunk, and reassembles.
//! The bucket index ([`crate::index`]) records `bucket/key -> manifest CID + size/etag/time`.
//! S3 verbs are then:
//!
//! | S3 verb           | CE mapping                                                                |
//! |-------------------|---------------------------------------------------------------------------|
//! | `PutObject`       | `put_object(bytes) -> CID`, then bind `key -> CID` in the index           |
//! | `GetObject`       | look up CID in index, `get_object(CID)` (chunks verified on the way)       |
//! | `GetObject`+Range | look up CID, fetch only covering chunks, slice the window                  |
//! | `HeadObject`      | index lookup (no bytes moved)                                             |
//! | `ListObjectsV2`   | prefix/delimiter/continuation walk over the sorted index                  |
//! | `DeleteObject`    | drop `key` from the index (bytes stay content-addressed; GC is separate)  |
//! | `CopyObject`      | share the CID — free, no bytes move                                       |
//!
//! Durability note: binding a key to a CID does not by itself replicate the bytes. The companion
//! `ce-pin` app pins a CID across N hosts for content availability; [`Store::pin_hint`] documents
//! that handoff. Within this crate, durability == "the bytes exist in the local blob store and are
//! announced to the DHT for replication" (what `put_blob` already does).

use crate::index::{Index, ListPage, ObjectMeta};
use crate::range;
use anyhow::{Context, Result};
use ce_rs::{data, CeClient, Manifest};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// The object store: a CE client + the on-disk bucket index + its path.
pub struct Store {
    ce: CeClient,
    index: Index,
    index_path: PathBuf,
}

/// Result of a `GetObject` (full or ranged).
#[derive(Debug, Clone)]
pub struct GetResult {
    /// The bytes returned (the whole object, or just the requested range).
    pub bytes: Vec<u8>,
    /// Total object size (the full object's size, regardless of range).
    pub total_size: u64,
    /// Content type recorded at put time.
    pub content_type: String,
    /// ETag (the object CID).
    pub etag: String,
    /// If this was a ranged read, the inclusive `(start, end)` actually served.
    pub range: Option<(u64, u64)>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Store {
    /// Open a store against the local CE node, loading the index from `index_path`.
    pub fn open(index_path: PathBuf) -> Result<Self> {
        let index = Index::load(&index_path)?;
        Ok(Self {
            ce: CeClient::local(),
            index,
            index_path,
        })
    }

    /// Open against a specific CE client (used by tests/gateway with a non-default endpoint).
    pub fn with_client(ce: CeClient, index_path: PathBuf) -> Result<Self> {
        let index = Index::load(&index_path)?;
        Ok(Self {
            ce,
            index,
            index_path,
        })
    }

    /// Immutable view of the index (for listing buckets, inspection).
    pub fn index(&self) -> &Index {
        &self.index
    }

    fn flush(&self) -> Result<()> {
        self.index.save(&self.index_path)
    }

    // ---- bucket verbs ----

    /// `CreateBucket` (mb). Persists immediately.
    pub fn make_bucket(&mut self, bucket: &str) -> Result<()> {
        self.index.make_bucket(bucket, now())?;
        self.flush()
    }

    /// `DeleteBucket` (rb). `force` removes a non-empty bucket too.
    pub fn remove_bucket(&mut self, bucket: &str, force: bool) -> Result<()> {
        self.index.remove_bucket(bucket, force)?;
        self.flush()
    }

    /// List bucket names.
    pub fn list_buckets(&self) -> Vec<String> {
        self.index.list_buckets()
    }

    // ---- object verbs ----

    /// `PutObject`: store `bytes` content-addressed, then bind `bucket/key -> CID`. Returns the
    /// object metadata (including the CID/ETag). Re-uploading identical bytes is free (dedup): the
    /// CID is unchanged and chunks already present are not re-stored.
    pub async fn put_object(
        &mut self,
        bucket: &str,
        key: &str,
        bytes: &[u8],
        content_type: &str,
    ) -> Result<ObjectMeta> {
        // ensure bucket exists
        if !self.index.buckets.contains_key(bucket) {
            anyhow::bail!("no such bucket: {bucket}");
        }
        let cid = self
            .ce
            .put_object(bytes)
            .await
            .context("storing object in CE blob layer")?;
        let meta = ObjectMeta::new(cid, bytes.len() as u64, content_type, now());
        self.index.put(bucket, key, meta.clone())?;
        self.flush()?;
        Ok(meta)
    }

    /// `HeadObject`: metadata only, no bytes.
    pub fn head_object(&self, bucket: &str, key: &str) -> Result<ObjectMeta> {
        self.index.head(bucket, key).cloned()
    }

    /// `GetObject` (full): resolve the CID and fetch+verify+reassemble the whole object.
    pub async fn get_object(&self, bucket: &str, key: &str) -> Result<GetResult> {
        let meta = self.index.head(bucket, key)?.clone();
        let bytes = self
            .ce
            .get_object(&meta.cid)
            .await
            .context("fetching object from CE blob layer")?;
        Ok(GetResult {
            bytes,
            total_size: meta.size,
            content_type: meta.content_type,
            etag: meta.etag,
            range: None,
        })
    }

    /// `GetObject` with an HTTP `Range` header (e.g. `"bytes=0-1023"`): fetch only the covering
    /// chunks and slice the exact window. Falls back to a full fetch if the object was stored as a
    /// single inline blob whose manifest is unavailable.
    pub async fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        range_header: &str,
    ) -> Result<GetResult> {
        let meta = self.index.head(bucket, key)?.clone();
        let (start, end) = range::parse_range(range_header, meta.size)?;

        // Resolve the manifest so we can fetch only the covering chunks.
        match self.fetch_manifest(&meta.cid).await {
            Ok(manifest) => {
                let cov = range::covering(&manifest, start, end)?;
                let mut concat = Vec::new();
                for &i in &cov.chunk_indices {
                    let chunk_cid = &manifest.chunks[i];
                    let chunk = self
                        .ce
                        .get_blob(chunk_cid)
                        .await
                        .with_context(|| format!("fetching chunk {chunk_cid}"))?;
                    // verify chunk against its CID (defense in depth; get_blob may hit the mesh)
                    if data::cid(&chunk) != *chunk_cid {
                        anyhow::bail!("chunk {chunk_cid} failed content verification");
                    }
                    concat.extend_from_slice(&chunk);
                }
                let window = range::slice(&cov, &concat)?.to_vec();
                Ok(GetResult {
                    bytes: window,
                    total_size: meta.size,
                    content_type: meta.content_type,
                    etag: meta.etag,
                    range: Some((start, end)),
                })
            }
            Err(_) => {
                // Manifest not resolvable as such (tiny inline object): fetch whole, then slice.
                let full = self.ce.get_object(&meta.cid).await?;
                let window = full
                    .get(start as usize..=end as usize)
                    .context("range out of bounds of fetched object")?
                    .to_vec();
                Ok(GetResult {
                    bytes: window,
                    total_size: meta.size,
                    content_type: meta.content_type,
                    etag: meta.etag,
                    range: Some((start, end)),
                })
            }
        }
    }

    /// `DeleteObject`: drop the key from the index. Idempotent. Bytes remain content-addressed in
    /// the blob store (a separate GC/unpin step reclaims unreferenced CIDs — see `ce-pin`).
    pub fn delete_object(&mut self, bucket: &str, key: &str) -> Result<()> {
        self.index.delete(bucket, key)?;
        self.flush()
    }

    /// `CopyObject`: bind `dst` to `src`'s CID — free, no bytes move (dedup by content address).
    pub fn copy_object(
        &mut self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
    ) -> Result<()> {
        self.index
            .copy(src_bucket, src_key, dst_bucket, dst_key, now())?;
        self.flush()
    }

    /// `ListObjectsV2`: see [`Index::list`].
    pub fn list_objects(
        &self,
        bucket: &str,
        prefix: &str,
        delimiter: Option<&str>,
        start_after: Option<&str>,
        max_keys: usize,
    ) -> Result<ListPage> {
        self.index
            .list(bucket, prefix, delimiter, start_after, max_keys)
    }

    /// The CID an object resolves to, for handing to `ce-pin` to replicate across N hosts. The
    /// durability story is: bind here, pin there. Returns an error if the key is unknown.
    pub fn pin_hint(&self, bucket: &str, key: &str) -> Result<String> {
        Ok(self.index.head(bucket, key)?.cid.clone())
    }

    /// Resolve an object CID to its manifest by fetching the manifest blob and parsing it. An object
    /// CID *is* the manifest's blob hash, so this is a single `get_blob` + JSON parse.
    async fn fetch_manifest(&self, object_cid: &str) -> Result<Manifest> {
        let bytes = self.ce.get_blob(object_cid).await?;
        let manifest: Manifest =
            serde_json::from_slice(&bytes).context("parsing object manifest")?;
        if !manifest.is_v1() {
            anyhow::bail!("unsupported manifest kind: {}", manifest.kind);
        }
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The index/listing logic is exercised in index.rs and range.rs without a node. Here we cover
    // the pure index-facing methods of Store that don't require a live CE node: bucket lifecycle,
    // head/copy/delete/list against a hand-seeded index. Network verbs (put/get) are covered by the
    // ignored integration test in tests/ that runs against an ephemeral node.

    fn temp_index_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ce-storage-store-{tag}-{}.json", std::process::id()))
    }

    fn store(tag: &str) -> Store {
        let p = temp_index_path(tag);
        let _ = std::fs::remove_file(&p);
        Store::open(p).unwrap()
    }

    #[test]
    fn bucket_lifecycle() {
        let mut s = store("life");
        s.make_bucket("photos").unwrap();
        assert_eq!(s.list_buckets(), vec!["photos".to_string()]);
        assert!(s.make_bucket("photos").is_err());
        s.remove_bucket("photos", false).unwrap();
        assert!(s.list_buckets().is_empty());
    }

    #[test]
    fn head_copy_delete_via_seeded_index() {
        let mut s = store("seed");
        s.make_bucket("buk").unwrap();
        // seed an object directly in the index (simulating a prior put without a node)
        s.index
            .put("buk", "a/x", ObjectMeta::new("cid1", 12, "text/plain", 1))
            .unwrap();
        s.flush().unwrap();

        assert_eq!(s.head_object("buk", "a/x").unwrap().cid, "cid1");
        s.copy_object("buk", "a/x", "buk", "a/y").unwrap();
        assert_eq!(s.head_object("buk", "a/y").unwrap().cid, "cid1");

        let page = s.list_objects("buk", "a/", None, None, 100).unwrap();
        assert_eq!(page.keys.len(), 2);

        s.delete_object("buk", "a/x").unwrap();
        assert!(s.head_object("buk", "a/x").is_err());
        assert_eq!(s.pin_hint("buk", "a/y").unwrap(), "cid1");
    }

    #[test]
    fn put_into_missing_bucket_errors_fast() {
        // put_object short-circuits before touching the node when the bucket is missing.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut s = store("nobucket");
        let r = rt.block_on(s.put_object("ghost", "k", b"hi", "text/plain"));
        assert!(r.is_err());
    }
}
