//! The bucket index — `bucket -> { key -> ObjectEntry }`, the durable map that turns CE's flat,
//! content-addressed blob store into named buckets, keys, and (optionally) versions.
//!
//! In the design stub a bucket is "a ce-coord map of key -> CID". ce-coord's `RMap` is a
//! single-writer replicated collection; for a self-contained store whose owner is the writer we
//! keep the same shape (`key -> CID` plus size/etag/time/metadata) but persist it locally as JSON.
//! The on-disk file is the source of truth for the owning node.
//!
//! ## Concurrency model
//!
//! The index is a **single-writer** structure. To make concurrent *processes* (e.g. a CLI
//! invocation while the gateway runs) safe, every mutating [`Store`](crate::store::Store) op takes
//! an advisory [`lock::FileLock`] around `load → mutate → save`, so a second process blocks until
//! the first finishes rather than clobbering it (lost-update). Within one process the gateway also
//! serialises behind a mutex. See [`crate::store`].
//!
//! ## Versioning
//!
//! A bucket may be marked **versioned**. Each `key` then keeps an ordered history of
//! [`ObjectVersion`]s (newest last); the version id *is* the object's content address (CID), a
//! perfect, collision-resistant generation id. `DeleteObject` on a versioned bucket appends a
//! **delete marker** instead of removing the key, so prior versions remain retrievable by
//! `version_id`. On an unversioned bucket a put overwrites in place and a delete removes the key —
//! classic S3 behaviour. The on-disk schema carries a [`SCHEMA_VERSION`] so future migrations stay
//! forward-compatible.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// On-disk schema version. Bumped when the persisted JSON shape changes incompatibly; [`Index::load`]
/// reads older versions transparently where it can and errors clearly where it cannot.
pub const SCHEMA_VERSION: u32 = 2;

/// Maximum number of user metadata entries on one object (S3 caps user-metadata size; we cap count
/// and per-entry length to bound memory and the index file).
pub const MAX_USER_METADATA_ENTRIES: usize = 64;
/// Maximum byte length of a single user-metadata key or value.
pub const MAX_USER_METADATA_LEN: usize = 2048;

/// Metadata recorded for one stored object version under a key. The object's bytes live in the CE
/// blob store under `cid` (the manifest CID for multi-chunk objects, or the single blob hash); this
/// struct is the index entry that maps a human key to that content address plus headers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectMeta {
    /// Content id of the object: the `put_object` manifest CID (or `put_blob` hash for tiny inline
    /// objects). This is the durable, verifiable handle to the bytes — and the version id.
    pub cid: String,
    /// Total object size in bytes.
    pub size: u64,
    /// S3-style entity tag. Content-addressed, so we use the CID directly (a strong validator):
    /// equal `etag` ⇒ identical bytes, which is exactly what callers want for caching/dedup.
    pub etag: String,
    /// Caller-supplied content type (best-effort; `application/octet-stream` if unknown).
    pub content_type: String,
    /// Unix seconds the object was last written.
    pub last_modified: u64,
    /// Version id of this object — the CID. Stable across the object's lifetime; distinct bytes get
    /// a distinct version id. Used by `GetObject?versionId=` on a versioned bucket.
    #[serde(default)]
    pub version_id: String,
    /// Arbitrary user metadata (S3 `x-amz-meta-*`). Bounded by [`MAX_USER_METADATA_ENTRIES`] /
    /// [`MAX_USER_METADATA_LEN`].
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    /// `Cache-Control` header to serve with the object, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<String>,
    /// `Content-Disposition` header to serve with the object, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_disposition: Option<String>,
    /// `Content-Encoding` header to serve with the object, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
}

impl ObjectMeta {
    /// Build metadata for an object stored at `cid` with `size` bytes. The ETag and version id are
    /// the CID. Optional headers/user-metadata default to empty; set them via [`ObjectMeta::with`].
    pub fn new(
        cid: impl Into<String>,
        size: u64,
        content_type: impl Into<String>,
        now: u64,
    ) -> Self {
        let cid = cid.into();
        Self {
            etag: cid.clone(),
            version_id: cid.clone(),
            cid,
            size,
            content_type: content_type.into(),
            last_modified: now,
            metadata: BTreeMap::new(),
            cache_control: None,
            content_disposition: None,
            content_encoding: None,
        }
    }

    /// Attach optional standard headers + user metadata, validating the metadata bounds.
    pub fn with(
        mut self,
        metadata: BTreeMap<String, String>,
        cache_control: Option<String>,
        content_disposition: Option<String>,
        content_encoding: Option<String>,
    ) -> Result<Self> {
        validate_user_metadata(&metadata)?;
        self.metadata = metadata;
        self.cache_control = cache_control;
        self.content_disposition = content_disposition;
        self.content_encoding = content_encoding;
        Ok(self)
    }
}

/// One stored version of an object: its metadata, plus whether it is a delete marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectVersion {
    /// The object metadata for this version. For a delete marker the `cid`/`size` are a sentinel and
    /// `is_delete_marker` is true.
    pub meta: ObjectMeta,
    /// True if this version is a delete marker (the key was deleted on a versioned bucket).
    pub is_delete_marker: bool,
}

/// The full history for one key: an ordered list of versions, newest **last**. On an unversioned
/// bucket there is exactly one (non-delete-marker) version; on a versioned bucket the list grows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectEntry {
    /// Versions in write order (newest last).
    pub versions: Vec<ObjectVersion>,
}

impl ObjectEntry {
    /// The current (newest) version, or `None` if the key has no versions.
    pub fn current(&self) -> Option<&ObjectVersion> {
        self.versions.last()
    }

    /// Look up a specific version by its version id (CID).
    pub fn by_version(&self, version_id: &str) -> Option<&ObjectVersion> {
        self.versions
            .iter()
            .rev()
            .find(|v| v.meta.version_id == version_id)
    }
}

/// Maximum number of lifecycle rules on one bucket (bounds the index file and sweep cost).
pub const MAX_LIFECYCLE_RULES: usize = 64;

/// One lifecycle rule: objects whose key starts with `prefix` expire `expiration_secs` seconds after
/// they were last written. An empty `prefix` matches the whole bucket. This is the S3
/// "Expiration / TTL" lifecycle action, modelled in seconds (S3 uses whole days; seconds let tests
/// and fine-grained policies work without changing the data model).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleRule {
    /// Key prefix the rule applies to (empty = whole bucket).
    pub prefix: String,
    /// Age in seconds after `last_modified` at which a matching object expires.
    pub expiration_secs: u64,
}

impl LifecycleRule {
    /// Does this rule cover `key`? Prefix match (empty prefix = all keys).
    pub fn matches(&self, key: &str) -> bool {
        self.prefix.is_empty() || key.starts_with(&self.prefix)
    }

    /// Is an object last written at `last_modified` expired as of `now`? An `expiration_secs` of 0
    /// means "never expire" (a disabled rule), matching the intuition that a zero TTL is a no-op
    /// rather than "expire immediately on write".
    pub fn is_expired(&self, last_modified: u64, now: u64) -> bool {
        self.expiration_secs != 0 && now >= last_modified.saturating_add(self.expiration_secs)
    }
}

/// Validate a set of lifecycle rules: bounded count and per-rule prefix length, no NUL.
pub fn validate_lifecycle(rules: &[LifecycleRule]) -> Result<()> {
    if rules.len() > MAX_LIFECYCLE_RULES {
        anyhow::bail!(
            "too many lifecycle rules: {} (max {})",
            rules.len(),
            MAX_LIFECYCLE_RULES
        );
    }
    for r in rules {
        if r.prefix.len() > 1024 {
            anyhow::bail!("lifecycle rule prefix must be <= 1024 bytes");
        }
        if r.prefix.contains('\0') {
            anyhow::bail!("lifecycle rule prefix must not contain NUL");
        }
    }
    Ok(())
}

/// One bucket: an ordered `key -> ObjectEntry` map plus a versioning flag. `BTreeMap` keeps keys
/// sorted, which is exactly what `ListObjectsV2` needs (lexicographic order, prefix ranges,
/// delimiter rollups, continuation tokens that are just "start after this key").
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Bucket {
    /// Unix seconds the bucket was created.
    pub created: u64,
    /// Whether new writes keep version history (true) or overwrite in place (false).
    #[serde(default)]
    pub versioning: bool,
    /// Lifecycle (TTL/expiration) rules; empty = no expiry. The first matching rule wins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lifecycle: Vec<LifecycleRule>,
    /// key -> object entry (version history), kept sorted for prefix/range listing.
    pub objects: BTreeMap<String, ObjectEntry>,
}

/// The whole index: all buckets owned by this node, persisted as one JSON file with a schema tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Index {
    /// On-disk schema version (see [`SCHEMA_VERSION`]).
    #[serde(default = "default_schema")]
    pub schema: u32,
    /// bucket name -> bucket.
    pub buckets: BTreeMap<String, Bucket>,
}

fn default_schema() -> u32 {
    SCHEMA_VERSION
}

impl Default for Index {
    fn default() -> Self {
        Self {
            schema: SCHEMA_VERSION,
            buckets: BTreeMap::new(),
        }
    }
}

/// A page of `ListObjectsV2` results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPage {
    /// Object keys in this page (full keys + current metadata, sorted).
    pub keys: Vec<(String, ObjectMeta)>,
    /// Common prefixes rolled up by the delimiter (the "directory" entries).
    pub common_prefixes: Vec<String>,
    /// If the listing was truncated, the key to pass as `start_after` for the next page.
    pub next_continuation: Option<String>,
    /// Whether more results exist beyond this page.
    pub is_truncated: bool,
    /// Number of keys returned in this page (S3 `KeyCount` counts keys + common prefixes).
    pub key_count: usize,
    /// The effective `max_keys` cap applied.
    pub max_keys: usize,
}

impl Index {
    /// Load the index from `path`, returning an empty index if the file does not yet exist.
    /// Forward-compatible: a future schema is read as far as serde allows; an unknown *higher*
    /// schema number errors clearly rather than silently misinterpreting fields.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let idx: Index =
                    serde_json::from_slice(&bytes).context("parsing bucket index JSON")?;
                if idx.schema > SCHEMA_VERSION {
                    anyhow::bail!(
                        "bucket index schema v{} is newer than this build supports (v{}); upgrade ce-storage",
                        idx.schema,
                        SCHEMA_VERSION
                    );
                }
                Ok(idx)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Index::default()),
            Err(e) => Err(e).context("reading bucket index"),
        }
    }

    /// Persist the index to `path` (creating parent directories) atomically via a temp file +
    /// rename. The temp file is unique per process so two writers never share it. `fsync` is best
    /// effort (errors are surfaced) so a crash leaves either the old or the new file, never a
    /// half-written one.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("creating index directory")?;
        }
        let bytes = serde_json::to_vec_pretty(self).context("serializing index")?;
        let tmp = with_tmp_suffix(path);
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp).context("creating index temp file")?;
            f.write_all(&bytes).context("writing index temp file")?;
            f.sync_all().context("fsyncing index temp file")?;
        }
        std::fs::rename(&tmp, path).context("renaming index into place")?;
        Ok(())
    }

    /// Create a bucket; errors if it already exists. Bucket names follow the S3 rule subset enforced
    /// by [`valid_bucket_name`].
    pub fn make_bucket(&mut self, name: &str, now: u64) -> Result<()> {
        valid_bucket_name(name)?;
        if self.buckets.contains_key(name) {
            anyhow::bail!("bucket already exists: {name}");
        }
        self.buckets.insert(
            name.to_string(),
            Bucket {
                created: now,
                versioning: false,
                lifecycle: Vec::new(),
                objects: BTreeMap::new(),
            },
        );
        Ok(())
    }

    /// Remove a bucket. With `force=false` an attempt to remove a non-empty bucket errors (S3
    /// semantics); with `force=true` it is removed along with its keys.
    pub fn remove_bucket(&mut self, name: &str, force: bool) -> Result<()> {
        let b = self
            .buckets
            .get(name)
            .with_context(|| format!("no such bucket: {name}"))?;
        if !force && !b.objects.is_empty() {
            anyhow::bail!("bucket not empty: {name} ({} objects)", b.objects.len());
        }
        self.buckets.remove(name);
        Ok(())
    }

    /// Enable or disable versioning on a bucket. S3 never lets you go back to "unversioned" once
    /// enabled (only "suspended"); we model that as a boolean flag and keep existing history intact.
    pub fn set_versioning(&mut self, name: &str, enabled: bool) -> Result<()> {
        let b = self
            .buckets
            .get_mut(name)
            .with_context(|| format!("no such bucket: {name}"))?;
        b.versioning = enabled;
        Ok(())
    }

    /// Whether a bucket has versioning enabled.
    pub fn is_versioned(&self, name: &str) -> Result<bool> {
        Ok(self
            .buckets
            .get(name)
            .with_context(|| format!("no such bucket: {name}"))?
            .versioning)
    }

    /// Replace a bucket's lifecycle (TTL/expiration) rules. Validates the rule set. An empty set
    /// clears all rules (no expiry).
    pub fn set_lifecycle(&mut self, name: &str, rules: Vec<LifecycleRule>) -> Result<()> {
        validate_lifecycle(&rules)?;
        let b = self
            .buckets
            .get_mut(name)
            .with_context(|| format!("no such bucket: {name}"))?;
        b.lifecycle = rules;
        Ok(())
    }

    /// A bucket's current lifecycle rules.
    pub fn lifecycle(&self, name: &str) -> Result<&[LifecycleRule]> {
        Ok(&self
            .buckets
            .get(name)
            .with_context(|| format!("no such bucket: {name}"))?
            .lifecycle)
    }

    /// Compute the keys in `bucket` whose current (non-delete-marker) version has expired as of
    /// `now` under the bucket's lifecycle rules. Pure: no mutation, no network. The first matching
    /// rule wins (S3 evaluates rules in order). Returns keys sorted (BTreeMap order).
    pub fn expired_keys(&self, bucket: &str, now: u64) -> Result<Vec<String>> {
        let b = self
            .buckets
            .get(bucket)
            .with_context(|| format!("no such bucket: {bucket}"))?;
        if b.lifecycle.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for (k, entry) in &b.objects {
            // Only live (non-delete-marker) current versions are eligible for expiry.
            let lm = match entry.current() {
                Some(v) if !v.is_delete_marker => v.meta.last_modified,
                _ => continue,
            };
            if let Some(rule) = b.lifecycle.iter().find(|r| r.matches(k))
                && rule.is_expired(lm, now)
            {
                out.push(k.clone());
            }
        }
        Ok(out)
    }

    /// List bucket names, sorted.
    pub fn list_buckets(&self) -> Vec<String> {
        self.buckets.keys().cloned().collect()
    }

    /// Bind `key -> meta` in `bucket` (PutObject index step). On a versioned bucket this appends a
    /// new version; on an unversioned bucket it replaces the single current version. Errors if the
    /// bucket is missing or the key/metadata is invalid.
    pub fn put(&mut self, bucket: &str, key: &str, meta: ObjectMeta) -> Result<()> {
        valid_key(key)?;
        validate_user_metadata(&meta.metadata)?;
        let b = self
            .buckets
            .get_mut(bucket)
            .with_context(|| format!("no such bucket: {bucket}"))?;
        let version = ObjectVersion {
            meta,
            is_delete_marker: false,
        };
        let entry = b.objects.entry(key.to_string()).or_default();
        if b.versioning {
            entry.versions.push(version);
        } else {
            entry.versions.clear();
            entry.versions.push(version);
        }
        Ok(())
    }

    /// Look up the current object's metadata (HeadObject / GetObject index step). Errors if the key
    /// is missing or the current version is a delete marker.
    pub fn head(&self, bucket: &str, key: &str) -> Result<&ObjectMeta> {
        let entry = self.entry(bucket, key)?;
        match entry.current() {
            Some(v) if !v.is_delete_marker => Ok(&v.meta),
            Some(_) => anyhow::bail!("no such key: {bucket}/{key} (delete marker)"),
            None => anyhow::bail!("no such key: {bucket}/{key}"),
        }
    }

    /// Look up a specific *version* of an object by its version id (CID). Returns the metadata even
    /// if it is not the current version, but never a delete marker's sentinel.
    pub fn head_version(&self, bucket: &str, key: &str, version_id: &str) -> Result<&ObjectMeta> {
        let entry = self.entry(bucket, key)?;
        match entry.by_version(version_id) {
            Some(v) if !v.is_delete_marker => Ok(&v.meta),
            Some(_) => anyhow::bail!("version {version_id} of {bucket}/{key} is a delete marker"),
            None => anyhow::bail!("no such version {version_id} of {bucket}/{key}"),
        }
    }

    /// The raw entry (version history) for a key.
    pub fn entry(&self, bucket: &str, key: &str) -> Result<&ObjectEntry> {
        let b = self
            .buckets
            .get(bucket)
            .with_context(|| format!("no such bucket: {bucket}"))?;
        b.objects
            .get(key)
            .with_context(|| format!("no such key: {bucket}/{key}"))
    }

    /// List every non-delete-marker version of a key, newest first.
    pub fn list_versions(&self, bucket: &str, key: &str) -> Result<Vec<ObjectMeta>> {
        let entry = self.entry(bucket, key)?;
        Ok(entry
            .versions
            .iter()
            .rev()
            .filter(|v| !v.is_delete_marker)
            .map(|v| v.meta.clone())
            .collect())
    }

    /// Delete a key (DeleteObject). On an unversioned bucket the key is removed (idempotent: removing
    /// a missing key succeeds, S3 semantics). On a versioned bucket a **delete marker** is appended,
    /// hiding the object from `head`/`get` while keeping prior versions retrievable by `version_id`.
    pub fn delete(&mut self, bucket: &str, key: &str, now: u64) -> Result<()> {
        let b = self
            .buckets
            .get_mut(bucket)
            .with_context(|| format!("no such bucket: {bucket}"))?;
        if b.versioning {
            if let Some(entry) = b.objects.get_mut(key) {
                // Only append a marker if the current version is not already a marker.
                if entry
                    .current()
                    .map(|v| !v.is_delete_marker)
                    .unwrap_or(false)
                {
                    let mut meta = ObjectMeta::new(String::new(), 0, "", now);
                    meta.version_id = format!("delete-marker-{now}");
                    entry.versions.push(ObjectVersion {
                        meta,
                        is_delete_marker: true,
                    });
                }
            }
        } else {
            b.objects.remove(key);
        }
        Ok(())
    }

    /// Permanently delete a specific version by id (S3 `DeleteObject?versionId=`). If removing the
    /// last version, the key is dropped entirely. Idempotent on a missing version id.
    pub fn delete_version(&mut self, bucket: &str, key: &str, version_id: &str) -> Result<()> {
        let b = self
            .buckets
            .get_mut(bucket)
            .with_context(|| format!("no such bucket: {bucket}"))?;
        if let Some(entry) = b.objects.get_mut(key) {
            entry.versions.retain(|v| v.meta.version_id != version_id);
            if entry.versions.is_empty() {
                b.objects.remove(key);
            }
        }
        Ok(())
    }

    /// Copy `src` -> `dst` by sharing the CID — free, no bytes move (content-addressed CopyObject).
    /// Carries the source object's metadata/headers; `now` becomes the new last-modified time.
    pub fn copy(
        &mut self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
        now: u64,
    ) -> Result<()> {
        let mut meta = self.head(src_bucket, src_key)?.clone();
        meta.last_modified = now;
        self.put(dst_bucket, dst_key, meta)
    }

    /// `ListObjectsV2` over a bucket: keys with `prefix`, rolled up by `delimiter`, starting after
    /// `start_after` (the continuation token), capped at `max_keys`.
    ///
    /// Pure function over the sorted map — no network. Delete-marked keys are hidden. Seeks into the
    /// `BTreeMap` from the larger of `prefix`/`start_after` instead of scanning from the start, so a
    /// continuation does not re-walk earlier keys. Returns the page plus a continuation token if
    /// truncated. A `delimiter` of `"/"` yields directory-style `common_prefixes`.
    pub fn list(
        &self,
        bucket: &str,
        prefix: &str,
        delimiter: Option<&str>,
        start_after: Option<&str>,
        max_keys: usize,
    ) -> Result<ListPage> {
        let b = self
            .buckets
            .get(bucket)
            .with_context(|| format!("no such bucket: {bucket}"))?;

        let max_keys = max_keys.max(1);
        let mut keys = Vec::new();
        let mut common_prefixes: Vec<String> = Vec::new();
        let mut last_seen: Option<String> = None;
        let mut truncated = false;

        // Seek to the first candidate key: max(prefix, start_after-exclusive). BTreeMap::range gives
        // us an O(log n + page) walk instead of scanning from the beginning every page.
        let lower = match start_after {
            // `start_after` is exclusive; the smallest key strictly greater than it sorts right after
            // its bytes with a NUL appended (no valid key contains NUL, so this is a clean bound).
            Some(after) if after >= prefix => {
                let mut b = after.as_bytes().to_vec();
                b.push(0);
                String::from_utf8_lossy(&b).into_owned()
            }
            _ => prefix.to_string(),
        };

        for (k, entry) in b.objects.range(lower..) {
            if !k.starts_with(prefix) {
                // Sorted order: once we pass the prefix range we are done.
                break;
            }
            // Hide delete-marked / empty keys.
            match entry.current() {
                Some(v) if !v.is_delete_marker => {}
                _ => continue,
            }
            let meta = match entry.current() {
                Some(v) => &v.meta,
                None => continue,
            };

            let emitted = keys.len() + common_prefixes.len();

            // Delimiter rollup: if the remainder after the prefix contains the delimiter, emit a
            // common prefix (the "folder") instead of the key.
            if let Some(delim) = delimiter {
                let rest = &k[prefix.len()..];
                if let Some(idx) = rest.find(delim) {
                    let cp = format!("{}{}{}", prefix, &rest[..idx], delim);
                    if common_prefixes.last().map(|p| p == &cp).unwrap_or(false) {
                        // Same folder as the previous roll-up; advance the cursor, no duplicate.
                        last_seen = Some(k.clone());
                    } else if common_prefixes.contains(&cp) {
                        last_seen = Some(k.clone());
                    } else {
                        if emitted >= max_keys {
                            truncated = true;
                            break;
                        }
                        common_prefixes.push(cp);
                        last_seen = Some(k.clone());
                    }
                    continue;
                }
            }

            if emitted >= max_keys {
                truncated = true;
                break;
            }
            keys.push((k.clone(), meta.clone()));
            last_seen = Some(k.clone());
        }

        let key_count = keys.len() + common_prefixes.len();
        Ok(ListPage {
            keys,
            common_prefixes,
            next_continuation: if truncated { last_seen } else { None },
            is_truncated: truncated,
            key_count,
            max_keys,
        })
    }
}

/// Default on-disk path for the bucket index inside the CE data dir.
pub fn default_index_path() -> PathBuf {
    let dir = directories::ProjectDirs::from("", "", "ce")
        .map(|p| p.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    dir.join("storage").join("buckets.json")
}

fn with_tmp_suffix(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(format!(".tmp.{}", std::process::id()));
    PathBuf::from(s)
}

/// Validate a bucket name: 3–63 chars, lowercase `a-z`/`0-9`/hyphen/dot, not leading/trailing
/// hyphen or dot, and never containing a slash — a conservative subset of the S3 DNS-compatible
/// naming rules. The no-slash rule keeps the `bucket/prefix` caveat encoding unambiguous.
pub fn valid_bucket_name(name: &str) -> Result<()> {
    let n = name.len();
    if !(3..=63).contains(&n) {
        anyhow::bail!("bucket name must be 3-63 characters: {name}");
    }
    let bytes = name.as_bytes();
    let bad_edge = |c: u8| c == b'-' || c == b'.';
    if bad_edge(bytes[0]) || bad_edge(bytes[n - 1]) {
        anyhow::bail!("bucket name must not start or end with '-' or '.': {name}");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
    {
        anyhow::bail!(
            "bucket name may only contain lowercase letters, digits, '-' and '.': {name}"
        );
    }
    Ok(())
}

/// Validate an object key: non-empty, no embedded NUL, ≤ 1024 bytes (S3 limit). Enforced on every
/// read/write path, not just put, so a forged gateway path or capability cannot smuggle a malformed
/// key into the index.
pub fn valid_key(key: &str) -> Result<()> {
    if key.is_empty() {
        anyhow::bail!("object key must not be empty");
    }
    if key.len() > 1024 {
        anyhow::bail!("object key must be <= 1024 bytes");
    }
    if key.contains('\0') {
        anyhow::bail!("object key must not contain NUL");
    }
    Ok(())
}

/// Validate user metadata: bounded entry count and per-entry length, no NUL, keys non-empty.
pub fn validate_user_metadata(meta: &BTreeMap<String, String>) -> Result<()> {
    if meta.len() > MAX_USER_METADATA_ENTRIES {
        anyhow::bail!(
            "too many user-metadata entries: {} (max {})",
            meta.len(),
            MAX_USER_METADATA_ENTRIES
        );
    }
    for (k, v) in meta {
        if k.is_empty() {
            anyhow::bail!("user-metadata key must not be empty");
        }
        if k.len() > MAX_USER_METADATA_LEN || v.len() > MAX_USER_METADATA_LEN {
            anyhow::bail!("user-metadata key/value exceeds {MAX_USER_METADATA_LEN} bytes");
        }
        if k.contains('\0') || v.contains('\0') {
            anyhow::bail!("user-metadata must not contain NUL");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(cid: &str, size: u64) -> ObjectMeta {
        ObjectMeta::new(cid, size, "application/octet-stream", 100)
    }

    #[test]
    fn make_and_list_buckets() {
        let mut idx = Index::default();
        idx.make_bucket("photos", 1).unwrap();
        idx.make_bucket("docs", 1).unwrap();
        assert_eq!(
            idx.list_buckets(),
            vec!["docs".to_string(), "photos".to_string()]
        );
        assert!(
            idx.make_bucket("photos", 1).is_err(),
            "duplicate bucket rejected"
        );
    }

    #[test]
    fn bucket_name_rules() {
        assert!(valid_bucket_name("ab").is_err());
        assert!(valid_bucket_name("-bad").is_err());
        assert!(valid_bucket_name("bad-").is_err());
        assert!(valid_bucket_name("Good").is_err());
        assert!(valid_bucket_name("my-bucket.01").is_ok());
        assert!(valid_bucket_name("has/slash").is_err());
    }

    #[test]
    fn put_head_delete() {
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        idx.put("buk", "a/x.txt", meta("cid1", 10)).unwrap();
        assert_eq!(idx.head("buk", "a/x.txt").unwrap().cid, "cid1");
        assert_eq!(idx.head("buk", "a/x.txt").unwrap().etag, "cid1");
        idx.delete("buk", "a/x.txt", 1).unwrap();
        assert!(idx.head("buk", "a/x.txt").is_err());
        // delete is idempotent
        idx.delete("buk", "a/x.txt", 1).unwrap();
    }

    #[test]
    fn unversioned_put_overwrites_in_place() {
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        idx.put("buk", "k", meta("cidA", 1)).unwrap();
        idx.put("buk", "k", meta("cidB", 2)).unwrap();
        assert_eq!(idx.head("buk", "k").unwrap().cid, "cidB");
        // exactly one version
        assert_eq!(idx.entry("buk", "k").unwrap().versions.len(), 1);
    }

    #[test]
    fn versioned_put_keeps_history_and_delete_marker() {
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        idx.set_versioning("buk", true).unwrap();
        idx.put("buk", "k", meta("cidA", 1)).unwrap();
        idx.put("buk", "k", meta("cidB", 2)).unwrap();
        // current is newest
        assert_eq!(idx.head("buk", "k").unwrap().cid, "cidB");
        // both versions retrievable
        assert_eq!(idx.head_version("buk", "k", "cidA").unwrap().cid, "cidA");
        assert_eq!(idx.list_versions("buk", "k").unwrap().len(), 2);
        // delete adds a marker, hides current, keeps versions
        idx.delete("buk", "k", 50).unwrap();
        assert!(idx.head("buk", "k").is_err(), "delete marker hides current");
        assert_eq!(idx.head_version("buk", "k", "cidA").unwrap().cid, "cidA");
        // permanently drop one version
        idx.delete_version("buk", "k", "cidA").unwrap();
        assert!(idx.head_version("buk", "k", "cidA").is_err());
    }

    #[test]
    fn delete_version_removes_key_when_last() {
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        idx.set_versioning("buk", true).unwrap();
        idx.put("buk", "k", meta("only", 1)).unwrap();
        idx.delete_version("buk", "k", "only").unwrap();
        assert!(
            idx.entry("buk", "k").is_err(),
            "key removed when last version gone"
        );
    }

    #[test]
    fn remove_bucket_requires_empty_or_force() {
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        idx.put("buk", "k", meta("c", 1)).unwrap();
        assert!(idx.remove_bucket("buk", false).is_err());
        idx.remove_bucket("buk", true).unwrap();
        assert!(idx.buckets.is_empty());
    }

    #[test]
    fn copy_shares_cid() {
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        idx.put("buk", "src", meta("cidA", 5)).unwrap();
        idx.copy("buk", "src", "buk", "dst", 200).unwrap();
        assert_eq!(idx.head("buk", "dst").unwrap().cid, "cidA");
        assert_eq!(idx.head("buk", "dst").unwrap().last_modified, 200);
    }

    #[test]
    fn user_metadata_bounds_enforced() {
        let mut big = BTreeMap::new();
        for i in 0..(MAX_USER_METADATA_ENTRIES + 1) {
            big.insert(format!("k{i}"), "v".to_string());
        }
        assert!(validate_user_metadata(&big).is_err());
        let mut long = BTreeMap::new();
        long.insert("k".to_string(), "v".repeat(MAX_USER_METADATA_LEN + 1));
        assert!(validate_user_metadata(&long).is_err());
        let mut nul = BTreeMap::new();
        nul.insert("k".to_string(), "has\0nul".to_string());
        assert!(validate_user_metadata(&nul).is_err());
    }

    #[test]
    fn put_rejects_oversized_metadata() {
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        let mut m = meta("c", 1);
        m.metadata
            .insert("k".into(), "v".repeat(MAX_USER_METADATA_LEN + 1));
        assert!(idx.put("buk", "k", m).is_err());
    }

    #[test]
    fn list_prefix_and_pagination() {
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        for k in ["a/1", "a/2", "a/3", "b/1"] {
            idx.put("buk", k, meta("c", 1)).unwrap();
        }
        // prefix filter
        let page = idx.list("buk", "a/", None, None, 100).unwrap();
        assert_eq!(page.keys.len(), 3);
        assert!(!page.is_truncated);
        assert_eq!(page.key_count, 3);

        // pagination: 2 per page
        let p1 = idx.list("buk", "", None, None, 2).unwrap();
        assert_eq!(p1.keys.len(), 2);
        assert!(p1.is_truncated);
        let cont = p1.next_continuation.clone().unwrap();
        let p2 = idx.list("buk", "", None, Some(&cont), 2).unwrap();
        assert_eq!(p2.keys.len(), 2);
    }

    #[test]
    fn list_delimiter_rolls_up_prefixes() {
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        for k in ["photos/2025/a", "photos/2025/b", "photos/2026/c", "readme"] {
            idx.put("buk", k, meta("c", 1)).unwrap();
        }
        let page = idx.list("buk", "photos/", Some("/"), None, 100).unwrap();
        // two folders rolled up, no individual keys
        assert_eq!(page.keys.len(), 0);
        assert_eq!(
            page.common_prefixes,
            vec!["photos/2025/".to_string(), "photos/2026/".to_string()]
        );
    }

    #[test]
    fn list_hides_delete_markers() {
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        idx.set_versioning("buk", true).unwrap();
        idx.put("buk", "a", meta("c", 1)).unwrap();
        idx.put("buk", "b", meta("c", 1)).unwrap();
        idx.delete("buk", "a", 5).unwrap();
        let page = idx.list("buk", "", None, None, 100).unwrap();
        assert_eq!(page.keys.len(), 1);
        assert_eq!(page.keys[0].0, "b");
    }

    #[test]
    fn list_seek_continuation_does_not_revisit() {
        // After many keys, a continuation should resume past the token. Verify the union covers all.
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        for i in 0..50 {
            idx.put("buk", &format!("k{i:02}"), meta("c", 1)).unwrap();
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut after: Option<String> = None;
        loop {
            let page = idx.list("buk", "", None, after.as_deref(), 7).unwrap();
            for (k, _) in &page.keys {
                assert!(seen.insert(k.clone()), "key {k} emitted twice");
            }
            match page.next_continuation {
                Some(tok) if page.is_truncated => after = Some(tok),
                _ => break,
            }
        }
        assert_eq!(seen.len(), 50);
    }

    #[test]
    fn roundtrip_save_load() {
        let dir = std::env::temp_dir().join(format!("ce-storage-test-{}", std::process::id()));
        let path = dir.join("buckets.json");
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        idx.put("buk", "k", meta("cidZ", 7)).unwrap();
        idx.save(&path).unwrap();
        let loaded = Index::load(&path).unwrap();
        assert_eq!(loaded.head("buk", "k").unwrap().cid, "cidZ");
        assert_eq!(loaded.schema, SCHEMA_VERSION);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lifecycle_rule_expiry_math() {
        let r = LifecycleRule {
            prefix: "logs/".into(),
            expiration_secs: 100,
        };
        assert!(r.matches("logs/a"));
        assert!(!r.matches("data/a"));
        // written at 1000, ttl 100 → expires at 1100
        assert!(!r.is_expired(1000, 1099));
        assert!(r.is_expired(1000, 1100));
        assert!(r.is_expired(1000, 5000));
        // zero ttl never expires
        let never = LifecycleRule {
            prefix: String::new(),
            expiration_secs: 0,
        };
        assert!(!never.is_expired(0, u64::MAX));
        // empty prefix matches everything
        assert!(never.matches("anything"));
    }

    #[test]
    fn expired_keys_first_matching_rule_wins() {
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        // write three keys at t=1000
        for k in ["logs/a", "logs/b", "keep/c"] {
            idx.put("buk", k, ObjectMeta::new("c", 1, "x", 1000))
                .unwrap();
        }
        // rules: logs/ expires fast; everything else never (the empty-prefix rule comes AFTER, so
        // logs/ matches the specific rule first).
        idx.set_lifecycle(
            "buk",
            vec![
                LifecycleRule {
                    prefix: "logs/".into(),
                    expiration_secs: 10,
                },
                LifecycleRule {
                    prefix: String::new(),
                    expiration_secs: 0,
                },
            ],
        )
        .unwrap();
        // at t=1005 nothing expired yet; at t=1010 the two logs/ keys expire, keep/c stays.
        assert!(idx.expired_keys("buk", 1005).unwrap().is_empty());
        let exp = idx.expired_keys("buk", 1010).unwrap();
        assert_eq!(exp, vec!["logs/a".to_string(), "logs/b".to_string()]);
    }

    #[test]
    fn expired_keys_empty_without_rules() {
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        idx.put("buk", "k", ObjectMeta::new("c", 1, "x", 0))
            .unwrap();
        assert!(idx.expired_keys("buk", u64::MAX).unwrap().is_empty());
    }

    #[test]
    fn expired_keys_skips_delete_markers() {
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        idx.set_versioning("buk", true).unwrap();
        idx.put("buk", "k", ObjectMeta::new("c", 1, "x", 1000))
            .unwrap();
        idx.delete("buk", "k", 1001).unwrap(); // current is now a delete marker
        idx.set_lifecycle(
            "buk",
            vec![LifecycleRule {
                prefix: String::new(),
                expiration_secs: 1,
            }],
        )
        .unwrap();
        // delete-marked current version is not eligible for expiry
        assert!(idx.expired_keys("buk", u64::MAX).unwrap().is_empty());
    }

    #[test]
    fn lifecycle_validation_bounds() {
        let too_many: Vec<LifecycleRule> = (0..(MAX_LIFECYCLE_RULES + 1))
            .map(|i| LifecycleRule {
                prefix: format!("p{i}"),
                expiration_secs: 1,
            })
            .collect();
        assert!(validate_lifecycle(&too_many).is_err());
        let nul = vec![LifecycleRule {
            prefix: "a\0b".into(),
            expiration_secs: 1,
        }];
        assert!(validate_lifecycle(&nul).is_err());
        assert!(validate_lifecycle(&[]).is_ok());
    }

    #[test]
    fn lifecycle_survives_save_load() {
        let dir = std::env::temp_dir().join(format!("ce-storage-lc-{}", std::process::id()));
        let path = dir.join("buckets.json");
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        idx.set_lifecycle(
            "buk",
            vec![LifecycleRule {
                prefix: "tmp/".into(),
                expiration_secs: 42,
            }],
        )
        .unwrap();
        idx.save(&path).unwrap();
        let loaded = Index::load(&path).unwrap();
        assert_eq!(loaded.lifecycle("buk").unwrap().len(), 1);
        assert_eq!(loaded.lifecycle("buk").unwrap()[0].expiration_secs, 42);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn future_schema_is_rejected() {
        let dir = std::env::temp_dir().join(format!("ce-storage-future-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("buckets.json");
        std::fs::write(&path, br#"{"schema": 9999, "buckets": {}}"#).unwrap();
        assert!(Index::load(&path).is_err(), "newer schema must be rejected");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
