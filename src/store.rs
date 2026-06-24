//! The [`Store`] — the library API that maps S3 verbs onto the CE blob layer + the local bucket
//! index. This is what the CLI and the optional HTTP gateway both drive.
//!
//! Object bytes are content-addressed in the CE blob store via `ce-rs`:
//! `put_object` splits into 1 MiB chunks, stores each, and returns the manifest CID;
//! `get_object` resolves the manifest, pulls and hash-verifies every chunk, and reassembles.
//! The bucket index ([`crate::index`]) records `bucket/key -> manifest CID + size/etag/time/meta`.
//!
//! | S3 verb           | CE mapping                                                                |
//! |-------------------|---------------------------------------------------------------------------|
//! | `PutObject`       | `put_object(bytes) -> CID`, then bind `key -> CID` in the index           |
//! | `GetObject`       | look up CID in index, `get_object(CID)` (chunks verified on the way)       |
//! | `GetObject`+Range | look up CID, fetch only covering chunks, slice the window                  |
//! | `HeadObject`      | index lookup (no bytes moved)                                             |
//! | `ListObjectsV2`   | prefix/delimiter/continuation walk over the sorted index                  |
//! | `DeleteObject`    | drop `key` (or append a delete marker on a versioned bucket)              |
//! | `CopyObject`      | share the CID — free, no bytes move                                       |
//!
//! ## Concurrency & limits
//!
//! Mutating ops take an advisory [`crate::lock::FileLock`] around `reload → mutate → save`, so two
//! processes sharing one index file cannot lose updates. [`Store::put_object`] rejects bodies larger
//! than the configured [`Store::max_object_size`] *before* buffering them, closing the OOM/DoS vector
//! a single huge PUT would otherwise open.
//!
//! ## Durability
//!
//! Binding a key to a CID does not by itself replicate the bytes beyond the local node. The bytes
//! live in the local content-addressed blob store and are announced to the DHT for opportunistic
//! replication (what `put_blob` already does). True multi-host pinning (an N-of-M replication factor)
//! is the companion `ce-pin` app's job; this crate exposes the CID via [`Store::pin_hint`] for that
//! handoff. This is documented honestly rather than faked: ce-storage does not silently pin.

use crate::index::{Index, ListPage, ObjectMeta};
use crate::lock::FileLock;
use crate::multipart::{self, MultipartState, Part, Upload};
use crate::range;
use crate::seal;
use anyhow::Result;
use ce_rs::{CeClient, Manifest, data};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default maximum object size accepted by [`Store::put_object`]: 5 GiB (S3's single-PUT ceiling).
/// Configurable per-store via [`Store::with_max_object_size`].
pub const DEFAULT_MAX_OBJECT_SIZE: u64 = 5 * 1024 * 1024 * 1024;

/// A typed storage error, so callers (notably the gateway) can map failures to the right HTTP status
/// instead of collapsing every error into a 404. The `Backend` variant carries node/IO failures
/// (real 5xx), keeping them distinct from a missing key (404) or a failed precondition (412).
#[derive(Debug)]
pub enum StorageError {
    /// The bucket does not exist.
    NoSuchBucket(String),
    /// The key (or requested version) does not exist / is a delete marker.
    NoSuchKey(String),
    /// The requested byte range is not satisfiable for the object's size.
    InvalidRange(String),
    /// A conditional precondition (If-Match / If-Unmodified-Since) was not met.
    PreconditionFailed(String),
    /// The condition for a 304 (If-None-Match / If-Modified-Since) was met — the object is unchanged.
    NotModified,
    /// The request was malformed or violated a limit (oversize body, bad key, bad metadata).
    InvalidRequest(String),
    /// An underlying node/IO error (network failure, blob store error) — a real 5xx, not a 404.
    Backend(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::NoSuchBucket(b) => write!(f, "no such bucket: {b}"),
            StorageError::NoSuchKey(k) => write!(f, "no such key: {k}"),
            StorageError::InvalidRange(m) => write!(f, "invalid range: {m}"),
            StorageError::PreconditionFailed(m) => write!(f, "precondition failed: {m}"),
            StorageError::NotModified => write!(f, "not modified"),
            StorageError::InvalidRequest(m) => write!(f, "invalid request: {m}"),
            StorageError::Backend(m) => write!(f, "backend error: {m}"),
        }
    }
}

impl std::error::Error for StorageError {}

/// Conditional-request preconditions (a subset of S3 / HTTP conditional headers). All `None` means
/// unconditional. Evaluated against the object's ETag (CID) and last-modified time.
#[derive(Debug, Clone, Default)]
pub struct Preconditions {
    /// `If-Match`: proceed only if the ETag matches (else 412). `*` matches any existing object.
    pub if_match: Option<String>,
    /// `If-None-Match`: proceed only if the ETag does NOT match (else 304 on GET/HEAD, 412 on PUT).
    /// `*` matches any existing object.
    pub if_none_match: Option<String>,
    /// `If-Modified-Since` (unix seconds): proceed only if modified strictly after this (else 304).
    pub if_modified_since: Option<u64>,
    /// `If-Unmodified-Since` (unix seconds): proceed only if NOT modified after this (else 412).
    pub if_unmodified_since: Option<u64>,
}

impl Preconditions {
    /// True if any precondition is set.
    pub fn any(&self) -> bool {
        self.if_match.is_some()
            || self.if_none_match.is_some()
            || self.if_modified_since.is_some()
            || self.if_unmodified_since.is_some()
    }

    /// Evaluate the preconditions for a read (GET/HEAD) against the current object's etag/mtime.
    /// Returns `Ok(())` to proceed, `Err(NotModified)` for a 304, or `Err(PreconditionFailed)` for a
    /// 412 (S3 evaluates If-Match/If-Unmodified-Since as 412 and If-None-Match/If-Modified-Since as
    /// 304 on reads).
    pub fn check_read(&self, etag: &str, last_modified: u64) -> Result<(), StorageError> {
        if let Some(m) = &self.if_match
            && m != "*"
            && m.trim_matches('"') != etag
        {
            return Err(StorageError::PreconditionFailed(format!(
                "If-Match {m} != {etag}"
            )));
        }
        if let Some(s) = self.if_unmodified_since
            && last_modified > s
        {
            return Err(StorageError::PreconditionFailed(
                "object modified after If-Unmodified-Since".into(),
            ));
        }
        if let Some(m) = &self.if_none_match
            && (m == "*" || m.trim_matches('"') == etag)
        {
            return Err(StorageError::NotModified);
        }
        if let Some(s) = self.if_modified_since
            && last_modified <= s
        {
            return Err(StorageError::NotModified);
        }
        Ok(())
    }

    /// Evaluate the preconditions for a write (PUT). `existing` is the current object's etag, if any.
    /// `If-None-Match: *` means "only create if absent" (write-once); `If-Match` means "only
    /// overwrite this exact version" (optimistic concurrency). Both failures are 412.
    pub fn check_write(&self, existing: Option<&str>) -> Result<(), StorageError> {
        if let Some(m) = &self.if_none_match {
            if m == "*" && existing.is_some() {
                return Err(StorageError::PreconditionFailed(
                    "If-None-Match: * but object exists".into(),
                ));
            }
            if m != "*"
                && let Some(e) = existing
                && m.trim_matches('"') == e
            {
                return Err(StorageError::PreconditionFailed(
                    "If-None-Match matched existing etag".into(),
                ));
            }
        }
        if let Some(m) = &self.if_match {
            match existing {
                Some(e) if m == "*" || m.trim_matches('"') == e => {}
                _ => {
                    return Err(StorageError::PreconditionFailed(
                        "If-Match did not match existing object".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Optional inputs for a `PutObject`: content type, user metadata, and standard caching headers.
#[derive(Debug, Clone, Default)]
pub struct PutOptions {
    /// MIME type; defaults to `application/octet-stream` when empty.
    pub content_type: String,
    /// Arbitrary user metadata (S3 `x-amz-meta-*`).
    pub metadata: BTreeMap<String, String>,
    /// `Cache-Control` to record and serve.
    pub cache_control: Option<String>,
    /// `Content-Disposition` to record and serve.
    pub content_disposition: Option<String>,
    /// `Content-Encoding` to record and serve.
    pub content_encoding: Option<String>,
    /// Conditional preconditions (optimistic concurrency / write-once).
    pub preconditions: Preconditions,
}

impl PutOptions {
    /// Convenience constructor for a content type with no metadata/headers.
    pub fn of_type(content_type: impl Into<String>) -> Self {
        Self {
            content_type: content_type.into(),
            ..Default::default()
        }
    }
}

/// The object store: a CE client + the on-disk bucket index + its path + limits.
pub struct Store {
    ce: CeClient,
    index: Index,
    index_path: PathBuf,
    max_object_size: u64,
}

/// Path of the multipart-upload state file, a sibling of the index (`<index>.multipart.json`).
fn multipart_path(index_path: &Path) -> PathBuf {
    let mut s = index_path.as_os_str().to_os_string();
    s.push(".multipart.json");
    PathBuf::from(s)
}

/// Generate a random hex upload id (128 bits of entropy mixed from several OS sources). Used to name
/// in-flight multipart uploads.
fn random_upload_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut h = Sha256::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    h.update(now.to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    h.update(COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    let marker = 0u8;
    h.update((&marker as *const u8 as usize).to_le_bytes());
    hex::encode(&h.finalize()[..16])
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
    /// Version id served (the CID).
    pub version_id: String,
    /// User metadata recorded at put time.
    pub metadata: BTreeMap<String, String>,
    /// Recorded `Cache-Control`, if any.
    pub cache_control: Option<String>,
    /// Recorded `Content-Disposition`, if any.
    pub content_disposition: Option<String>,
    /// Recorded `Content-Encoding`, if any.
    pub content_encoding: Option<String>,
    /// Last-modified unix seconds.
    pub last_modified: u64,
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
            max_object_size: DEFAULT_MAX_OBJECT_SIZE,
        })
    }

    /// Open against a specific CE client (used by tests/gateway with a non-default endpoint).
    pub fn with_client(ce: CeClient, index_path: PathBuf) -> Result<Self> {
        let index = Index::load(&index_path)?;
        Ok(Self {
            ce,
            index,
            index_path,
            max_object_size: DEFAULT_MAX_OBJECT_SIZE,
        })
    }

    /// Set the maximum object size accepted by `put_object` (builder style).
    pub fn with_max_object_size(mut self, max: u64) -> Self {
        self.max_object_size = max;
        self
    }

    /// The configured maximum object size.
    pub fn max_object_size(&self) -> u64 {
        self.max_object_size
    }

    /// Immutable view of the index (for listing buckets, inspection).
    pub fn index(&self) -> &Index {
        &self.index
    }

    /// Acquire the cross-process lock and reload the index from disk so we mutate the freshest state.
    /// Returned guard must be kept alive across the mutate + save.
    fn lock_and_reload(&mut self) -> Result<FileLock> {
        let guard = FileLock::acquire(&self.index_path)?;
        self.index = Index::load(&self.index_path)?;
        Ok(guard)
    }

    fn flush(&self) -> Result<()> {
        self.index.save(&self.index_path)
    }

    // ---- bucket verbs ----

    /// `CreateBucket` (mb). Persists immediately.
    pub fn make_bucket(&mut self, bucket: &str) -> Result<()> {
        let _g = self.lock_and_reload()?;
        self.index.make_bucket(bucket, now())?;
        self.flush()
    }

    /// `DeleteBucket` (rb). `force` removes a non-empty bucket too.
    pub fn remove_bucket(&mut self, bucket: &str, force: bool) -> Result<()> {
        let _g = self.lock_and_reload()?;
        self.index.remove_bucket(bucket, force)?;
        self.flush()
    }

    /// `PutBucketVersioning`: enable or disable version history on a bucket.
    pub fn set_versioning(&mut self, bucket: &str, enabled: bool) -> Result<()> {
        let _g = self.lock_and_reload()?;
        self.index.set_versioning(bucket, enabled)?;
        self.flush()
    }

    /// Whether a bucket has versioning enabled.
    pub fn is_versioned(&self, bucket: &str) -> Result<bool> {
        self.index.is_versioned(bucket)
    }

    /// List bucket names.
    pub fn list_buckets(&self) -> Vec<String> {
        self.index.list_buckets()
    }

    /// `PutBucketLifecycleConfiguration`: set (or clear, with an empty vec) a bucket's lifecycle
    /// (TTL/expiration) rules. Persists immediately.
    pub fn set_lifecycle(
        &mut self,
        bucket: &str,
        rules: Vec<crate::index::LifecycleRule>,
    ) -> Result<()> {
        let _g = self.lock_and_reload()?;
        self.index.set_lifecycle(bucket, rules)?;
        self.flush()
    }

    /// `GetBucketLifecycleConfiguration`: a bucket's current lifecycle rules.
    pub fn lifecycle(&self, bucket: &str) -> Result<Vec<crate::index::LifecycleRule>> {
        Ok(self.index.lifecycle(bucket)?.to_vec())
    }

    /// The keys in `bucket` currently expired under its lifecycle rules (as of now). Pure inspection;
    /// no deletion. Use [`Store::sweep_expired`] to actually delete them.
    pub fn expired_keys(&self, bucket: &str) -> Result<Vec<String>> {
        self.index.expired_keys(bucket, now())
    }

    /// Run the lifecycle sweeper for `bucket`: delete every object whose TTL has elapsed, atomically
    /// under the cross-process lock (and against the freshest on-disk index, so a concurrent writer's
    /// new objects are seen). On a versioned bucket an expiry appends a delete marker (S3 semantics);
    /// on an unversioned bucket the key is removed. Returns the keys deleted. Idempotent: a second
    /// sweep with nothing newly expired deletes nothing.
    pub fn sweep_expired(&mut self, bucket: &str) -> Result<Vec<String>> {
        let _g = self.lock_and_reload()?;
        let t = now();
        let expired = self.index.expired_keys(bucket, t)?;
        for k in &expired {
            self.index.delete(bucket, k, t)?;
        }
        if !expired.is_empty() {
            self.flush()?;
        }
        Ok(expired)
    }

    /// Sweep lifecycle expirations across **all** buckets in one locked pass. Returns
    /// `bucket -> deleted keys` for the buckets that had expirations. A background daemon can call
    /// this on an interval.
    pub fn sweep_all(&mut self) -> Result<BTreeMap<String, Vec<String>>> {
        let _g = self.lock_and_reload()?;
        let t = now();
        let buckets: Vec<String> = self.index.list_buckets();
        let mut report = BTreeMap::new();
        let mut any = false;
        for b in buckets {
            let expired = self.index.expired_keys(&b, t)?;
            if expired.is_empty() {
                continue;
            }
            for k in &expired {
                self.index.delete(&b, k, t)?;
            }
            any = true;
            report.insert(b, expired);
        }
        if any {
            self.flush()?;
        }
        Ok(report)
    }

    // ---- object verbs ----

    /// `PutObject` with options (content type, metadata, headers, preconditions). Stores `bytes`
    /// content-addressed, then binds `bucket/key -> CID`. Rejects bodies larger than
    /// [`Store::max_object_size`] before touching the node. Re-uploading identical bytes is free
    /// (dedup): the CID is unchanged and chunks already present are not re-stored.
    pub async fn put_object_opts(
        &mut self,
        bucket: &str,
        key: &str,
        bytes: &[u8],
        opts: &PutOptions,
    ) -> Result<ObjectMeta, StorageError> {
        if bytes.len() as u64 > self.max_object_size {
            return Err(StorageError::InvalidRequest(format!(
                "object size {} exceeds max {} bytes",
                bytes.len(),
                self.max_object_size
            )));
        }
        crate::index::valid_key(key).map_err(|e| StorageError::InvalidRequest(e.to_string()))?;
        crate::index::validate_user_metadata(&opts.metadata)
            .map_err(|e| StorageError::InvalidRequest(e.to_string()))?;

        let _g = self
            .lock_and_reload()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        if !self.index.buckets.contains_key(bucket) {
            return Err(StorageError::NoSuchBucket(bucket.to_string()));
        }
        // Preconditions evaluated against the current object (optimistic concurrency / write-once).
        if opts.preconditions.any() {
            let existing = self.index.head(bucket, key).ok().map(|m| m.etag.clone());
            opts.preconditions.check_write(existing.as_deref())?;
        }

        let ct = if opts.content_type.is_empty() {
            "application/octet-stream"
        } else {
            &opts.content_type
        };
        let cid = self
            .ce
            .put_object(bytes)
            .await
            .map_err(|e| StorageError::Backend(format!("storing object: {e}")))?;
        let meta = ObjectMeta::new(cid, bytes.len() as u64, ct, now())
            .with(
                opts.metadata.clone(),
                opts.cache_control.clone(),
                opts.content_disposition.clone(),
                opts.content_encoding.clone(),
            )
            .map_err(|e| StorageError::InvalidRequest(e.to_string()))?;
        self.index
            .put(bucket, key, meta.clone())
            .map_err(|e| StorageError::InvalidRequest(e.to_string()))?;
        self.flush()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(meta)
    }

    /// `PutObject` (simple): store `bytes` with a content type, no metadata/preconditions.
    pub async fn put_object(
        &mut self,
        bucket: &str,
        key: &str,
        bytes: &[u8],
        content_type: &str,
    ) -> Result<ObjectMeta> {
        Ok(self
            .put_object_opts(bucket, key, bytes, &PutOptions::of_type(content_type))
            .await?)
    }

    /// `HeadObject`: current metadata only, no bytes.
    pub fn head_object(&self, bucket: &str, key: &str) -> Result<ObjectMeta> {
        self.index.head(bucket, key).cloned()
    }

    /// `HeadObject?versionId=`: a specific version's metadata.
    pub fn head_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<ObjectMeta> {
        self.index.head_version(bucket, key, version_id).cloned()
    }

    /// List all non-delete-marker versions of a key (newest first).
    pub fn list_versions(&self, bucket: &str, key: &str) -> Result<Vec<ObjectMeta>> {
        self.index.list_versions(bucket, key)
    }

    fn meta_for(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<ObjectMeta, StorageError> {
        let r = match version_id {
            Some(v) => self.index.head_version(bucket, key, v),
            None => self.index.head(bucket, key),
        };
        r.cloned().map_err(|e| {
            // Distinguish missing bucket from missing key for accurate status mapping.
            if self.index.buckets.contains_key(bucket) {
                StorageError::NoSuchKey(format!("{bucket}/{key}: {e}"))
            } else {
                StorageError::NoSuchBucket(bucket.to_string())
            }
        })
    }

    fn result_from(meta: ObjectMeta, bytes: Vec<u8>, range: Option<(u64, u64)>) -> GetResult {
        GetResult {
            bytes,
            total_size: meta.size,
            content_type: meta.content_type,
            etag: meta.etag,
            version_id: meta.version_id,
            metadata: meta.metadata,
            cache_control: meta.cache_control,
            content_disposition: meta.content_disposition,
            content_encoding: meta.content_encoding,
            last_modified: meta.last_modified,
            range,
        }
    }

    /// `GetObject` (full): resolve the CID and fetch+verify+reassemble the whole object. Honors
    /// `version_id` and conditional `preconditions` (304/412).
    pub async fn get_object_opts(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        preconditions: &Preconditions,
    ) -> Result<GetResult, StorageError> {
        let meta = self.meta_for(bucket, key, version_id)?;
        preconditions.check_read(&meta.etag, meta.last_modified)?;
        let bytes = self
            .ce
            .get_object(&meta.cid)
            .await
            .map_err(|e| StorageError::Backend(format!("fetching object: {e}")))?;
        Ok(Self::result_from(meta, bytes, None))
    }

    /// `GetObject` (full, unconditional). See [`Store::get_object_opts`] for versions/preconditions.
    pub async fn get_object(&self, bucket: &str, key: &str) -> Result<GetResult> {
        Ok(self
            .get_object_opts(bucket, key, None, &Preconditions::default())
            .await?)
    }

    /// `GetObject` with an HTTP `Range` header (e.g. `"bytes=0-1023"`): fetch only the covering
    /// chunks and slice the exact window. Honors `version_id`. For the inline-blob path (no parseable
    /// manifest) it streams the (already size-bounded) object once and slices — never an unbounded
    /// fetch, because every object passed the put-time size cap.
    pub async fn get_object_range_opts(
        &self,
        bucket: &str,
        key: &str,
        range_header: &str,
        version_id: Option<&str>,
    ) -> Result<GetResult, StorageError> {
        let meta = self.meta_for(bucket, key, version_id)?;
        let (start, end) = range::parse_range(range_header, meta.size)
            .map_err(|e| StorageError::InvalidRange(e.to_string()))?;

        match self.fetch_manifest(&meta.cid).await {
            Ok(manifest) => {
                let cov = range::covering(&manifest, start, end)
                    .map_err(|e| StorageError::InvalidRange(e.to_string()))?;
                let mut concat = Vec::new();
                for &i in &cov.chunk_indices {
                    let chunk_cid = &manifest.chunks[i];
                    let chunk = self.ce.get_blob(chunk_cid).await.map_err(|e| {
                        StorageError::Backend(format!("fetching chunk {chunk_cid}: {e}"))
                    })?;
                    if data::cid(&chunk) != *chunk_cid {
                        return Err(StorageError::Backend(format!(
                            "chunk {chunk_cid} failed content verification"
                        )));
                    }
                    concat.extend_from_slice(&chunk);
                }
                let window = range::slice(&cov, &concat)
                    .map_err(|e| StorageError::Backend(e.to_string()))?
                    .to_vec();
                Ok(Self::result_from(meta, window, Some((start, end))))
            }
            Err(_) => {
                // Inline (single-blob) object: fetch whole (size-bounded), then slice.
                let full = self
                    .ce
                    .get_object(&meta.cid)
                    .await
                    .map_err(|e| StorageError::Backend(format!("fetching object: {e}")))?;
                let window = full
                    .get(start as usize..=end as usize)
                    .ok_or_else(|| StorageError::InvalidRange("range out of bounds".into()))?
                    .to_vec();
                Ok(Self::result_from(meta, window, Some((start, end))))
            }
        }
    }

    /// `GetObject`+Range (unconditional, current version).
    pub async fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        range_header: &str,
    ) -> Result<GetResult> {
        Ok(self
            .get_object_range_opts(bucket, key, range_header, None)
            .await?)
    }

    /// `DeleteObject`: drop the key from the index (or append a delete marker on a versioned bucket).
    /// Idempotent. Bytes remain content-addressed in the blob store (a separate GC/unpin step
    /// reclaims unreferenced CIDs — see `ce-pin`).
    pub fn delete_object(&mut self, bucket: &str, key: &str) -> Result<()> {
        let _g = self.lock_and_reload()?;
        self.index.delete(bucket, key, now())?;
        self.flush()
    }

    /// `DeleteObject?versionId=`: permanently remove a specific version.
    pub fn delete_object_version(
        &mut self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<()> {
        let _g = self.lock_and_reload()?;
        self.index.delete_version(bucket, key, version_id)?;
        self.flush()
    }

    /// `DeleteObjects` (bulk): delete many keys in one locked transaction. Returns per-key results so
    /// callers can report partial success (S3's `DeleteObjects` returns Deleted/Error lists).
    pub fn delete_objects(
        &mut self,
        bucket: &str,
        keys: &[String],
    ) -> Result<Vec<(String, Result<()>)>> {
        let _g = self.lock_and_reload()?;
        let t = now();
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            let r = self.index.delete(bucket, k, t);
            out.push((k.clone(), r));
        }
        self.flush()?;
        Ok(out)
    }

    /// `CopyObject`: bind `dst` to `src`'s CID — free, no bytes move (dedup by content address).
    pub fn copy_object(
        &mut self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
    ) -> Result<()> {
        let _g = self.lock_and_reload()?;
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

    // ---- sealed (client-side encrypted) objects ----

    /// `PutObject` of a **sealed** object: encrypt `plaintext` under `user_key` ([`crate::seal`])
    /// *before* it touches the node, store the ciphertext content-addressed, and bind the key. The
    /// recorded content type is opaque ([`seal::SEALED_CONTENT_TYPE`]); the object is useless to the
    /// host (or any replicating peer) without `user_key`. The CID/ETag is the ciphertext's hash. The
    /// size limit is checked against the *plaintext* so a caller cannot bypass it via encryption
    /// overhead.
    pub async fn put_object_sealed(
        &mut self,
        bucket: &str,
        key: &str,
        plaintext: &[u8],
        user_key: &[u8],
        opts: &PutOptions,
    ) -> Result<ObjectMeta, StorageError> {
        if plaintext.len() as u64 > self.max_object_size {
            return Err(StorageError::InvalidRequest(format!(
                "object size {} exceeds max {} bytes",
                plaintext.len(),
                self.max_object_size
            )));
        }
        if user_key.is_empty() {
            return Err(StorageError::InvalidRequest(
                "sealed objects require a non-empty key".into(),
            ));
        }
        let sealed = seal::seal(plaintext, user_key);
        // Mark the object sealed via user metadata so a reader knows to unseal, and record the
        // plaintext size for the caller's convenience (the stored size is the ciphertext size).
        let mut opts = opts.clone();
        opts.content_type = seal::SEALED_CONTENT_TYPE.to_string();
        opts.metadata
            .insert("ce-sealed".to_string(), "1".to_string());
        opts.metadata
            .insert("ce-plaintext-size".to_string(), plaintext.len().to_string());
        self.put_object_opts(bucket, key, &sealed, &opts).await
    }

    /// `GetObject` of a sealed object: fetch the ciphertext record and decrypt it under `user_key`.
    /// Authentication is enforced ([`seal::unseal`]): a wrong key or tampered bytes is an error, never
    /// returned plaintext. The returned [`GetResult::bytes`] is the recovered plaintext; `total_size`
    /// reflects the plaintext length.
    pub async fn get_object_sealed(
        &self,
        bucket: &str,
        key: &str,
        user_key: &[u8],
        version_id: Option<&str>,
    ) -> Result<GetResult, StorageError> {
        let mut res = self
            .get_object_opts(bucket, key, version_id, &Preconditions::default())
            .await?;
        let plaintext = seal::unseal(&res.bytes, user_key)
            .map_err(|e| StorageError::InvalidRequest(format!("unsealing object: {e}")))?;
        res.total_size = plaintext.len() as u64;
        res.bytes = plaintext;
        Ok(res)
    }

    // ---- multipart / resumable upload ----

    /// Load the multipart state under the index lock (returns the guard so the caller mutates against
    /// the freshest on-disk state, like [`Store::lock_and_reload`] does for the index).
    fn lock_and_load_multipart(&self) -> Result<(FileLock, MultipartState)> {
        let guard = FileLock::acquire(&self.index_path)?;
        let st = MultipartState::load(&multipart_path(&self.index_path))?;
        Ok((guard, st))
    }

    /// `CreateMultipartUpload`: begin an upload to `bucket/key`, returning a fresh upload id. The
    /// bucket must exist and the key valid. The agreed per-part chunk size is the blob layer's 1 MiB
    /// (every non-final part must be a whole multiple of it on completion).
    pub async fn create_multipart_upload(
        &mut self,
        bucket: &str,
        key: &str,
        opts: &PutOptions,
    ) -> Result<String, StorageError> {
        crate::index::valid_key(key).map_err(|e| StorageError::InvalidRequest(e.to_string()))?;
        crate::index::validate_user_metadata(&opts.metadata)
            .map_err(|e| StorageError::InvalidRequest(e.to_string()))?;
        let (_g, mut st) = self
            .lock_and_load_multipart()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        // Bucket existence is checked against the freshest index.
        self.index =
            Index::load(&self.index_path).map_err(|e| StorageError::Backend(e.to_string()))?;
        if !self.index.buckets.contains_key(bucket) {
            return Err(StorageError::NoSuchBucket(bucket.to_string()));
        }
        let id = random_upload_id();
        let ct = if opts.content_type.is_empty() {
            "application/octet-stream".to_string()
        } else {
            opts.content_type.clone()
        };
        let upload = Upload {
            bucket: bucket.to_string(),
            key: key.to_string(),
            part_chunk: multipart::DEFAULT_PART_CHUNK,
            content_type: ct,
            metadata: opts.metadata.clone(),
            created: now(),
            parts: BTreeMap::new(),
        };
        st.create(id.clone(), upload)
            .map_err(|e| StorageError::InvalidRequest(e.to_string()))?;
        st.save(&multipart_path(&self.index_path))
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(id)
    }

    /// `UploadPart`: store the `part_number`-th part's `bytes` content-addressed and record it. The
    /// part's ETag is the CID of its bytes (so re-uploading an identical part is free and idempotent).
    /// Returns the part ETag. Part size/number are bounded; the uniform-size rule is enforced at
    /// completion.
    pub async fn upload_part(
        &mut self,
        upload_id: &str,
        part_number: u32,
        bytes: &[u8],
    ) -> Result<String, StorageError> {
        if bytes.len() as u64 > self.max_object_size {
            return Err(StorageError::InvalidRequest(format!(
                "part size {} exceeds max {} bytes",
                bytes.len(),
                self.max_object_size
            )));
        }
        // Chunk the part client-side to capture its chunk CIDs, then store each chunk + the part's
        // own manifest so the part is a retrievable object in its own right (its etag is that CID).
        let (_g, mut st) = self
            .lock_and_load_multipart()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        if !st.uploads.contains_key(upload_id) {
            return Err(StorageError::NoSuchKey(format!(
                "multipart upload {upload_id}"
            )));
        }
        let (manifest, chunks) = data::chunk_object(bytes, multipart::DEFAULT_PART_CHUNK as usize);
        let chunk_cids: Vec<String> = manifest.chunks.clone();
        for (chunk_cid, chunk) in chunks {
            let stored = self
                .ce
                .put_blob(chunk)
                .await
                .map_err(|e| StorageError::Backend(format!("storing part chunk: {e}")))?;
            if stored != chunk_cid {
                return Err(StorageError::Backend(format!(
                    "blob store returned {stored} for chunk {chunk_cid}"
                )));
            }
        }
        let manifest_bytes = serde_json::to_vec(&manifest)
            .map_err(|e| StorageError::Backend(format!("serializing part manifest: {e}")))?;
        let etag = self
            .ce
            .put_blob(manifest_bytes)
            .await
            .map_err(|e| StorageError::Backend(format!("storing part manifest: {e}")))?;
        let part = Part {
            part_number,
            etag: etag.clone(),
            size: bytes.len() as u64,
            chunk_cids,
        };
        st.put_part(upload_id, part)
            .map_err(|e| StorageError::InvalidRequest(e.to_string()))?;
        st.save(&multipart_path(&self.index_path))
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(etag)
    }

    /// `ListParts`: the parts recorded for an in-flight upload, in part-number order.
    pub fn list_parts(&self, upload_id: &str) -> Result<Vec<Part>> {
        let st = MultipartState::load(&multipart_path(&self.index_path))?;
        st.list_parts(upload_id)
    }

    /// `ListMultipartUploads`: ids of in-flight uploads (optionally filtered to one bucket).
    pub fn list_multipart_uploads(&self, bucket: Option<&str>) -> Result<Vec<(String, Upload)>> {
        let st = MultipartState::load(&multipart_path(&self.index_path))?;
        Ok(st
            .uploads
            .into_iter()
            .filter(|(_, u)| bucket.map(|b| u.bucket == b).unwrap_or(true))
            .collect())
    }

    /// `CompleteMultipartUpload`: assemble the requested `(part_number, etag)` parts into one
    /// combined object manifest, store it, bind `bucket/key -> CID`, and drop the upload record. No
    /// bytes are copied — the parts' chunks are already stored; the manifest just references them in
    /// order. Returns the completed object's metadata. The parts must be ascending and every part
    /// except the last must be a whole multiple of the part chunk size (S3's uniform-part rule).
    pub async fn complete_multipart_upload(
        &mut self,
        upload_id: &str,
        parts: &[(u32, String)],
    ) -> Result<ObjectMeta, StorageError> {
        let (_g, mut st) = self
            .lock_and_load_multipart()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let upload = st
            .get(upload_id)
            .map_err(|_| StorageError::NoSuchKey(format!("multipart upload {upload_id}")))?
            .clone();
        let manifest = multipart::assemble_manifest(&upload, parts)
            .map_err(|e| StorageError::InvalidRequest(e.to_string()))?;
        if manifest.total_size > self.max_object_size {
            return Err(StorageError::InvalidRequest(format!(
                "assembled object size {} exceeds max {} bytes",
                manifest.total_size, self.max_object_size
            )));
        }
        // Store the assembled manifest as a blob; its hash is the object CID.
        let manifest_bytes = serde_json::to_vec(&manifest)
            .map_err(|e| StorageError::Backend(format!("serializing object manifest: {e}")))?;
        let cid = self
            .ce
            .put_blob(manifest_bytes)
            .await
            .map_err(|e| StorageError::Backend(format!("storing object manifest: {e}")))?;

        // Bind the key into the index under the index lock (reload to mutate freshest state).
        self.index =
            Index::load(&self.index_path).map_err(|e| StorageError::Backend(e.to_string()))?;
        if !self.index.buckets.contains_key(&upload.bucket) {
            return Err(StorageError::NoSuchBucket(upload.bucket.clone()));
        }
        let meta = ObjectMeta::new(cid, manifest.total_size, &upload.content_type, now())
            .with(upload.metadata.clone(), None, None, None)
            .map_err(|e| StorageError::InvalidRequest(e.to_string()))?;
        self.index
            .put(&upload.bucket, &upload.key, meta.clone())
            .map_err(|e| StorageError::InvalidRequest(e.to_string()))?;
        self.flush()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        // Drop the upload record now that it is committed.
        st.remove(upload_id);
        st.save(&multipart_path(&self.index_path))
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(meta)
    }

    /// `AbortMultipartUpload`: drop the in-flight upload record. Idempotent (aborting an unknown id
    /// succeeds). The orphaned part chunks are reclaimed by the same GC/unpin path as deleted objects.
    pub fn abort_multipart_upload(&mut self, upload_id: &str) -> Result<()> {
        let (_g, mut st) = self.lock_and_load_multipart()?;
        st.remove(upload_id);
        st.save(&multipart_path(&self.index_path))?;
        Ok(())
    }

    /// Resolve an object CID to its manifest by fetching the manifest blob and parsing it. An object
    /// CID *is* the manifest's blob hash, so this is a single `get_blob` + JSON parse.
    async fn fetch_manifest(&self, object_cid: &str) -> Result<Manifest> {
        let bytes = self.ce.get_blob(object_cid).await?;
        let manifest: Manifest = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("parsing object manifest: {e}"))?;
        if !manifest.is_v1() {
            anyhow::bail!("unsupported manifest kind: {}", manifest.kind);
        }
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_index_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ce-storage-store-{tag}-{}.json",
            std::process::id()
        ))
    }

    fn store(tag: &str) -> Store {
        let p = temp_index_path(tag);
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(format!("{}.lock", p.display()));
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
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut s = store("nobucket");
        let r = rt.block_on(s.put_object("ghost", "k", b"hi", "text/plain"));
        assert!(r.is_err());
    }

    #[test]
    fn oversize_put_rejected_before_node() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut s = store("oversize");
        s = s.with_max_object_size(8);
        s.make_bucket("buk").unwrap();
        // 9 bytes > 8-byte cap → rejected without touching the (absent) node.
        let r = rt.block_on(s.put_object_opts("buk", "k", b"123456789", &PutOptions::default()));
        assert!(matches!(r, Err(StorageError::InvalidRequest(_))));
    }

    #[test]
    fn delete_objects_bulk_reports_per_key() {
        let mut s = store("bulk");
        s.make_bucket("buk").unwrap();
        for k in ["a", "b", "c"] {
            s.index
                .put("buk", k, ObjectMeta::new("c", 1, "x", 1))
                .unwrap();
        }
        s.flush().unwrap();
        let res = s
            .delete_objects("buk", &["a".into(), "b".into(), "missing".into()])
            .unwrap();
        assert_eq!(res.len(), 3);
        assert!(res.iter().all(|(_, r)| r.is_ok()), "delete is idempotent");
        let page = s.list_objects("buk", "", None, None, 100).unwrap();
        assert_eq!(page.keys.len(), 1, "only c remains");
    }

    #[test]
    fn sweep_expired_deletes_only_aged_objects() {
        use crate::index::LifecycleRule;
        let mut s = store("sweep");
        s.make_bucket("buk").unwrap();
        // Seed two objects: an old one (last_modified far in the past) and a fresh one (now).
        s.index
            .put("buk", "old", ObjectMeta::new("c", 1, "x", 1))
            .unwrap();
        s.index
            .put("buk", "fresh", ObjectMeta::new("c", 1, "x", now()))
            .unwrap();
        s.flush().unwrap();
        // TTL of 10s over the whole bucket: "old" (mtime 1) is long expired; "fresh" is not.
        s.set_lifecycle(
            "buk",
            vec![LifecycleRule {
                prefix: String::new(),
                expiration_secs: 10,
            }],
        )
        .unwrap();
        let expired = s.expired_keys("buk").unwrap();
        assert_eq!(expired, vec!["old".to_string()]);
        let deleted = s.sweep_expired("buk").unwrap();
        assert_eq!(deleted, vec!["old".to_string()]);
        assert!(s.head_object("buk", "old").is_err(), "old swept");
        assert!(s.head_object("buk", "fresh").is_ok(), "fresh kept");
        // Idempotent: a second sweep deletes nothing.
        assert!(s.sweep_expired("buk").unwrap().is_empty());
    }

    #[test]
    fn sweep_all_reports_per_bucket() {
        use crate::index::LifecycleRule;
        let mut s = store("sweepall");
        // Create both buckets first (each make_bucket reloads from disk), then seed objects in
        // memory and flush once so neither seed is clobbered by a reload.
        s.make_bucket("one").unwrap();
        s.make_bucket("two").unwrap();
        for b in ["one", "two"] {
            s.index
                .put(b, "stale", ObjectMeta::new("c", 1, "x", 1))
                .unwrap();
        }
        s.flush().unwrap();
        s.set_lifecycle(
            "one",
            vec![LifecycleRule {
                prefix: String::new(),
                expiration_secs: 1,
            }],
        )
        .unwrap();
        // "two" has no rules → nothing expires there.
        let report = s.sweep_all().unwrap();
        assert_eq!(report.len(), 1, "only bucket 'one' had expirations");
        assert_eq!(report["one"], vec!["stale".to_string()]);
        assert!(s.head_object("two", "stale").is_ok());
    }

    #[test]
    fn lifecycle_get_set_roundtrip() {
        use crate::index::LifecycleRule;
        let mut s = store("lcset");
        s.make_bucket("buk").unwrap();
        assert!(s.lifecycle("buk").unwrap().is_empty());
        s.set_lifecycle(
            "buk",
            vec![LifecycleRule {
                prefix: "logs/".into(),
                expiration_secs: 3600,
            }],
        )
        .unwrap();
        let got = s.lifecycle("buk").unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].prefix, "logs/");
        // clearing
        s.set_lifecycle("buk", Vec::new()).unwrap();
        assert!(s.lifecycle("buk").unwrap().is_empty());
    }

    #[test]
    fn precondition_write_once_and_if_match() {
        let mut pc = Preconditions {
            if_none_match: Some("*".into()),
            ..Default::default()
        };
        // create-if-absent: no existing → ok; existing → 412
        assert!(pc.check_write(None).is_ok());
        assert!(matches!(
            pc.check_write(Some("abc")),
            Err(StorageError::PreconditionFailed(_))
        ));
        // if-match optimistic concurrency
        pc = Preconditions {
            if_match: Some("abc".into()),
            ..Default::default()
        };
        assert!(pc.check_write(Some("abc")).is_ok());
        assert!(matches!(
            pc.check_write(Some("xyz")),
            Err(StorageError::PreconditionFailed(_))
        ));
        assert!(matches!(
            pc.check_write(None),
            Err(StorageError::PreconditionFailed(_))
        ));
    }

    #[test]
    fn precondition_read_not_modified_and_failed() {
        let pc = Preconditions {
            if_none_match: Some("etag1".into()),
            ..Default::default()
        };
        // matching etag → 304 NotModified
        assert!(matches!(
            pc.check_read("etag1", 100),
            Err(StorageError::NotModified)
        ));
        // non-matching → proceed
        assert!(pc.check_read("etag2", 100).is_ok());
        let pc = Preconditions {
            if_match: Some("etagX".into()),
            ..Default::default()
        };
        assert!(matches!(
            pc.check_read("etagY", 100),
            Err(StorageError::PreconditionFailed(_))
        ));
        let pc = Preconditions {
            if_modified_since: Some(200),
            ..Default::default()
        };
        // not modified since 200 (mtime 100 <= 200) → 304
        assert!(matches!(
            pc.check_read("e", 100),
            Err(StorageError::NotModified)
        ));
        assert!(pc.check_read("e", 250).is_ok());
    }
}
