//! The bucket index — `bucket -> { key -> ObjectMeta }`, the durable map that turns CE's flat,
//! content-addressed blob store into named buckets and keys.
//!
//! In the design stub a bucket is "a ce-coord map of key -> CID". ce-coord's `RMap` is a
//! single-writer replicated collection; for a self-contained store whose owner is the writer we
//! keep the same shape (`key -> CID` plus size/etag/time) but persist it locally as JSON and (when
//! a node is reachable) mirror it into the CE blob store so the index itself is content-addressed
//! and shareable. The on-disk file is the source of truth for the owning node; `snapshot_cid`
//! lets a reader bootstrap the whole index from a single blob. This keeps the crate free of the
//! ce-coord/ce-rs git-vs-path duplication while preserving the exact key->CID semantics the S3
//! verbs need (prefix listing, delimiter rollups, continuation).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Metadata recorded for one object version under a key. The object's bytes live in the CE blob
/// store under `cid` (the manifest CID for multi-chunk objects, or the single blob hash); this
/// struct is the index entry that maps a human key to that content address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectMeta {
    /// Content id of the object: the `put_object` manifest CID (or `put_blob` hash for tiny inline
    /// objects). This is the durable, verifiable handle to the bytes.
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
}

impl ObjectMeta {
    /// Build metadata for an object stored at `cid` with `size` bytes. The ETag is the CID.
    pub fn new(cid: impl Into<String>, size: u64, content_type: impl Into<String>, now: u64) -> Self {
        let cid = cid.into();
        Self {
            etag: cid.clone(),
            cid,
            size,
            content_type: content_type.into(),
            last_modified: now,
        }
    }
}

/// One bucket: an ordered `key -> ObjectMeta` map. `BTreeMap` keeps keys sorted, which is exactly
/// what `ListObjectsV2` needs (lexicographic order, prefix ranges, delimiter rollups, continuation
/// tokens that are just "start after this key").
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Bucket {
    /// Unix seconds the bucket was created.
    pub created: u64,
    /// key -> object metadata, kept sorted for prefix/range listing.
    pub objects: BTreeMap<String, ObjectMeta>,
}

/// The whole index: all buckets owned by this node, persisted as one JSON file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Index {
    /// bucket name -> bucket.
    pub buckets: BTreeMap<String, Bucket>,
}

/// A page of `ListObjectsV2` results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPage {
    /// Object keys in this page (full keys, sorted).
    pub keys: Vec<(String, ObjectMeta)>,
    /// Common prefixes rolled up by the delimiter (the "directory" entries).
    pub common_prefixes: Vec<String>,
    /// If the listing was truncated, the key to pass as `start_after` for the next page.
    pub next_continuation: Option<String>,
    /// Whether more results exist beyond this page.
    pub is_truncated: bool,
}

impl Index {
    /// Load the index from `path`, returning an empty index if the file does not yet exist.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).context("parsing bucket index JSON")
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Index::default()),
            Err(e) => Err(e).context("reading bucket index"),
        }
    }

    /// Persist the index to `path` (creating parent directories) atomically via a temp file.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("creating index directory")?;
        }
        let bytes = serde_json::to_vec_pretty(self).context("serializing index")?;
        let tmp = with_tmp_suffix(path);
        std::fs::write(&tmp, &bytes).context("writing index temp file")?;
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

    /// List bucket names, sorted.
    pub fn list_buckets(&self) -> Vec<String> {
        self.buckets.keys().cloned().collect()
    }

    /// Bind `key -> meta` in `bucket` (PutObject index step). Errors if the bucket is missing.
    pub fn put(&mut self, bucket: &str, key: &str, meta: ObjectMeta) -> Result<()> {
        valid_key(key)?;
        let b = self
            .buckets
            .get_mut(bucket)
            .with_context(|| format!("no such bucket: {bucket}"))?;
        b.objects.insert(key.to_string(), meta);
        Ok(())
    }

    /// Look up an object's metadata (HeadObject / GetObject index step).
    pub fn head(&self, bucket: &str, key: &str) -> Result<&ObjectMeta> {
        let b = self
            .buckets
            .get(bucket)
            .with_context(|| format!("no such bucket: {bucket}"))?;
        b.objects
            .get(key)
            .with_context(|| format!("no such key: {bucket}/{key}"))
    }

    /// Delete a key (DeleteObject). Idempotent: removing a missing key succeeds (S3 semantics).
    pub fn delete(&mut self, bucket: &str, key: &str) -> Result<()> {
        let b = self
            .buckets
            .get_mut(bucket)
            .with_context(|| format!("no such bucket: {bucket}"))?;
        b.objects.remove(key);
        Ok(())
    }

    /// Copy `src` -> `dst` by sharing the CID — free, no bytes move (content-addressed CopyObject).
    pub fn copy(&mut self, src_bucket: &str, src_key: &str, dst_bucket: &str, dst_key: &str, now: u64) -> Result<()> {
        let mut meta = self.head(src_bucket, src_key)?.clone();
        meta.last_modified = now;
        self.put(dst_bucket, dst_key, meta)
    }

    /// `ListObjectsV2` over a bucket: keys with `prefix`, rolled up by `delimiter`, starting after
    /// `start_after` (the continuation token), capped at `max_keys`.
    ///
    /// Pure function over the sorted map — no network. Returns the page plus a continuation token if
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

        // Walk keys in sorted order, skipping anything <= start_after.
        for (k, meta) in b.objects.iter() {
            if !k.starts_with(prefix) {
                continue;
            }
            if let Some(after) = start_after {
                if k.as_str() <= after {
                    continue;
                }
            }

            // Total emitted entries (keys + distinct common prefixes) is what max_keys caps.
            let emitted = keys.len() + common_prefixes.len();

            // Delimiter rollup: if the remainder after the prefix contains the delimiter, emit a
            // common prefix (the "folder") instead of the key.
            if let Some(delim) = delimiter {
                let rest = &k[prefix.len()..];
                if let Some(idx) = rest.find(delim) {
                    let cp = format!("{}{}{}", prefix, &rest[..idx], delim);
                    if !common_prefixes.last().map(|p| p == &cp).unwrap_or(false)
                        && !common_prefixes.contains(&cp)
                    {
                        if emitted >= max_keys {
                            truncated = true;
                            break;
                        }
                        common_prefixes.push(cp);
                        last_seen = Some(k.clone());
                    } else {
                        // Same folder as the previous roll-up; advance the cursor so continuation
                        // resumes correctly, but do not emit a duplicate.
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

        Ok(ListPage {
            keys,
            common_prefixes,
            next_continuation: if truncated { last_seen } else { None },
            is_truncated: truncated,
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
    s.push(".tmp");
    PathBuf::from(s)
}

/// Validate a bucket name: 3–63 chars, lowercase `a-z`/`0-9`/hyphen/dot, not leading/trailing
/// hyphen or dot — a conservative subset of the S3 DNS-compatible naming rules.
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
        anyhow::bail!("bucket name may only contain lowercase letters, digits, '-' and '.': {name}");
    }
    Ok(())
}

/// Validate an object key: non-empty, no embedded NUL, ≤ 1024 bytes (S3 limit).
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
        assert_eq!(idx.list_buckets(), vec!["docs".to_string(), "photos".to_string()]);
        assert!(idx.make_bucket("photos", 1).is_err(), "duplicate bucket rejected");
    }

    #[test]
    fn bucket_name_rules() {
        assert!(valid_bucket_name("ab").is_err());
        assert!(valid_bucket_name("-bad").is_err());
        assert!(valid_bucket_name("bad-").is_err());
        assert!(valid_bucket_name("Good").is_err());
        assert!(valid_bucket_name("my-bucket.01").is_ok());
    }

    #[test]
    fn put_head_delete() {
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        idx.put("buk", "a/x.txt", meta("cid1", 10)).unwrap();
        assert_eq!(idx.head("buk", "a/x.txt").unwrap().cid, "cid1");
        assert_eq!(idx.head("buk", "a/x.txt").unwrap().etag, "cid1");
        idx.delete("buk", "a/x.txt").unwrap();
        assert!(idx.head("buk", "a/x.txt").is_err());
        // delete is idempotent
        idx.delete("buk", "a/x.txt").unwrap();
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
    fn roundtrip_save_load() {
        let dir = std::env::temp_dir().join(format!("ce-storage-test-{}", std::process::id()));
        let path = dir.join("buckets.json");
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        idx.put("buk", "k", meta("cidZ", 7)).unwrap();
        idx.save(&path).unwrap();
        let loaded = Index::load(&path).unwrap();
        assert_eq!(loaded.head("buk", "k").unwrap().cid, "cidZ");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
