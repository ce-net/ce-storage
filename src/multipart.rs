//! Multipart / resumable upload — `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`,
//! `AbortMultipartUpload`, `ListParts` over the existing content-addressed chunk/manifest model.
//!
//! ## Why multipart maps cleanly onto CE
//!
//! An object in CE is a [`Manifest`](ce_rs::Manifest): an ordered list of 1 MiB chunk CIDs plus a
//! `total_size`. A multipart **part** is itself just an object — a run of those same chunks. So
//! completing a multipart upload is nothing more than **concatenating the parts' chunk lists** into
//! one combined manifest, storing it, and binding the resulting object CID into the bucket index.
//! No bytes are copied on completion: each part's chunks already live in the blob store, and the
//! final object references them in order. Ranged reads over the assembled object keep working
//! unchanged because the combined manifest is a normal v1 manifest.
//!
//! The one wrinkle is the S3 rule that every part except the last must be the **same size**, so that
//! `chunk_size` stays uniform across the concatenation. We enforce a single per-upload `part_chunk`
//! size (defaulting to the blob layer's 1 MiB) and require each non-final part to be a whole multiple
//! of it. This keeps the assembled manifest a clean fixed-`chunk_size` manifest that [`crate::range`]
//! can index. A short final part is allowed (its trailing chunk is simply smaller, exactly like a
//! normal object's last chunk).
//!
//! ## State
//!
//! In-flight uploads live in [`MultipartState`], persisted next to the bucket index (atomic
//! temp-file + rename, same as the index) and guarded by the same cross-process advisory lock, so a
//! resumed or concurrent CLI/gateway process sees a consistent view. An upload id is a random hex
//! token; parts are recorded as `(part_number, etag, size, chunk_cids)`. Abort drops the record (the
//! orphaned chunks are reclaimed by the same GC/unpin path as deleted objects).

use anyhow::{Context, Result};
use ce_rs::Manifest;
use ce_rs::data::{self, MANIFEST_KIND_V1};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Maximum number of parts in one multipart upload (S3's limit is 10,000). Bounds the state file and
/// the assembled chunk list.
pub const MAX_PARTS: u32 = 10_000;

/// Maximum number of concurrently-tracked in-flight uploads across all buckets. Bounds the state file
/// so a client cannot exhaust memory/disk by opening uploads without ever completing them.
pub const MAX_INFLIGHT_UPLOADS: usize = 4096;

/// Default per-part chunk size — the blob layer's chunk size (1 MiB). Every non-final part must be a
/// whole multiple of this so the assembled manifest keeps a uniform `chunk_size`.
pub const DEFAULT_PART_CHUNK: u64 = data::DEFAULT_CHUNK_SIZE as u64;

/// On-disk schema version for the multipart state file.
pub const MULTIPART_SCHEMA: u32 = 1;

/// One uploaded part: its number, content etag (CID of the part's own manifest), byte size, and the
/// ordered chunk CIDs that make it up (spliced into the final manifest on completion).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Part {
    /// 1-based part number (S3 parts are numbered 1..=10000).
    pub part_number: u32,
    /// ETag of the part — the CID of the part's bytes (content-addressed, so a re-uploaded identical
    /// part is free and idempotent).
    pub etag: String,
    /// Size of this part in bytes.
    pub size: u64,
    /// Ordered chunk CIDs comprising this part, spliced into the assembled object manifest.
    pub chunk_cids: Vec<String>,
}

/// An in-flight multipart upload: its target, the agreed per-part chunk size, recorded parts, and
/// the put-time options (content type / metadata / headers) to carry onto the completed object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upload {
    /// Target bucket.
    pub bucket: String,
    /// Target key.
    pub key: String,
    /// Uniform chunk size for every part (last part may end short).
    pub part_chunk: u64,
    /// Content type to record on the completed object.
    pub content_type: String,
    /// User metadata to record on the completed object.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    /// Unix seconds the upload was created.
    pub created: u64,
    /// Parts uploaded so far, keyed by part number (so a re-uploaded part replaces the old one).
    pub parts: BTreeMap<u32, Part>,
}

impl Upload {
    /// Total assembled size if completed now (sum of part sizes, in part-number order).
    pub fn assembled_size(&self) -> u64 {
        self.parts.values().map(|p| p.size).sum()
    }
}

/// The persisted set of in-flight multipart uploads: `upload_id -> Upload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultipartState {
    /// On-disk schema version.
    #[serde(default = "default_mp_schema")]
    pub schema: u32,
    /// upload id -> upload record.
    pub uploads: BTreeMap<String, Upload>,
}

fn default_mp_schema() -> u32 {
    MULTIPART_SCHEMA
}

impl Default for MultipartState {
    fn default() -> Self {
        Self {
            schema: MULTIPART_SCHEMA,
            uploads: BTreeMap::new(),
        }
    }
}

impl MultipartState {
    /// Load the multipart state from `path`, returning an empty state if absent. Rejects a newer
    /// schema rather than silently misinterpreting it.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let st: MultipartState =
                    serde_json::from_slice(&bytes).context("parsing multipart state JSON")?;
                if st.schema > MULTIPART_SCHEMA {
                    anyhow::bail!(
                        "multipart state schema v{} is newer than supported (v{})",
                        st.schema,
                        MULTIPART_SCHEMA
                    );
                }
                Ok(st)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(MultipartState::default()),
            Err(e) => Err(e).context("reading multipart state"),
        }
    }

    /// Persist atomically via temp-file + fsync + rename (same discipline as the index).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("creating multipart state directory")?;
        }
        let bytes = serde_json::to_vec_pretty(self).context("serializing multipart state")?;
        let mut tmp = path.as_os_str().to_os_string();
        tmp.push(format!(".tmp.{}", std::process::id()));
        let tmp = PathBuf::from(tmp);
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp).context("creating multipart temp file")?;
            f.write_all(&bytes).context("writing multipart temp file")?;
            f.sync_all().context("fsyncing multipart temp file")?;
        }
        std::fs::rename(&tmp, path).context("renaming multipart state into place")?;
        Ok(())
    }

    /// Begin a new upload, returning its id. `id` is supplied by the caller (a random hex token) so
    /// the store controls entropy. Enforces the in-flight cap.
    pub fn create(&mut self, id: String, upload: Upload) -> Result<()> {
        if self.uploads.len() >= MAX_INFLIGHT_UPLOADS && !self.uploads.contains_key(&id) {
            anyhow::bail!(
                "too many in-flight multipart uploads ({}); complete or abort some first",
                self.uploads.len()
            );
        }
        self.uploads.insert(id, upload);
        Ok(())
    }

    /// Borrow an upload by id.
    pub fn get(&self, id: &str) -> Result<&Upload> {
        self.uploads
            .get(id)
            .with_context(|| format!("no such multipart upload: {id}"))
    }

    /// Record (or replace) a part on an existing upload. Validates the part number range and, for a
    /// non-final part, that its size is a positive whole multiple of the upload's `part_chunk` (the
    /// S3 uniform-part-size rule that keeps the assembled manifest's `chunk_size` uniform). The
    /// "is this the final part" judgement is deferred to completion; here we only reject a part that
    /// can *never* be valid as a non-final part AND is not plausibly final — i.e. a zero-length part.
    pub fn put_part(&mut self, id: &str, part: Part) -> Result<()> {
        if part.part_number == 0 || part.part_number > MAX_PARTS {
            anyhow::bail!(
                "part number must be 1..={MAX_PARTS}, got {}",
                part.part_number
            );
        }
        if part.size == 0 {
            anyhow::bail!("a part must be non-empty");
        }
        let up = self
            .uploads
            .get_mut(id)
            .with_context(|| format!("no such multipart upload: {id}"))?;
        up.parts.insert(part.part_number, part);
        Ok(())
    }

    /// List the recorded parts of an upload in part-number order.
    pub fn list_parts(&self, id: &str) -> Result<Vec<Part>> {
        Ok(self.get(id)?.parts.values().cloned().collect())
    }

    /// Remove (abort) an upload, returning the dropped record if present (idempotent).
    pub fn remove(&mut self, id: &str) -> Option<Upload> {
        self.uploads.remove(id)
    }

    /// Number of in-flight uploads.
    pub fn len(&self) -> usize {
        self.uploads.len()
    }

    /// Whether there are no in-flight uploads.
    pub fn is_empty(&self) -> bool {
        self.uploads.is_empty()
    }
}

/// Validate a requested part list against an upload and assemble the combined object [`Manifest`].
///
/// `requested` is the ordered `(part_number, etag)` list the client wants to complete with (S3's
/// `CompleteMultipartUpload` body). Each must reference a previously-uploaded part whose etag
/// matches. Parts must be strictly ascending and, per S3, every part except the **last** must be a
/// whole multiple of `part_chunk` so the concatenation has a uniform chunk size. The assembled
/// manifest's `total_size` is the sum of part sizes; its `chunks` are the parts' chunk lists spliced
/// in order.
pub fn assemble_manifest(upload: &Upload, requested: &[(u32, String)]) -> Result<Manifest> {
    if requested.is_empty() {
        anyhow::bail!("CompleteMultipartUpload requires at least one part");
    }
    if requested.len() > MAX_PARTS as usize {
        anyhow::bail!("too many parts: {}", requested.len());
    }
    let mut last_num = 0u32;
    let mut chunks: Vec<String> = Vec::new();
    let mut total: u64 = 0;
    for (idx, (num, etag)) in requested.iter().enumerate() {
        if *num <= last_num {
            anyhow::bail!("parts must be in strictly ascending order (saw {num} after {last_num})");
        }
        last_num = *num;
        let part = upload
            .parts
            .get(num)
            .with_context(|| format!("part {num} was never uploaded"))?;
        if &part.etag != etag {
            anyhow::bail!(
                "part {num} etag mismatch: client {etag} != stored {}",
                part.etag
            );
        }
        let is_last = idx + 1 == requested.len();
        // Every non-final part must be a positive whole multiple of part_chunk so the assembled
        // manifest stays uniform-chunk (S3's minimum-part-size invariant, expressed against our
        // chunk granularity). The final part may end short.
        if !is_last && part.size % upload.part_chunk != 0 {
            anyhow::bail!(
                "part {num} size {} is not a multiple of the part chunk size {} (only the final part may be short)",
                part.size,
                upload.part_chunk
            );
        }
        total = total
            .checked_add(part.size)
            .context("assembled object size overflow")?;
        chunks.extend_from_slice(&part.chunk_cids);
    }
    Ok(Manifest {
        kind: MANIFEST_KIND_V1.to_string(),
        chunk_size: upload.part_chunk,
        total_size: total,
        chunks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upload(part_chunk: u64) -> Upload {
        Upload {
            bucket: "buk".into(),
            key: "big".into(),
            part_chunk,
            content_type: "application/octet-stream".into(),
            metadata: BTreeMap::new(),
            created: 1,
            parts: BTreeMap::new(),
        }
    }

    fn part(n: u32, size: u64, chunks: &[&str]) -> Part {
        Part {
            part_number: n,
            etag: format!("etag{n}"),
            size,
            chunk_cids: chunks.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn create_put_list_abort_roundtrip() {
        let mut st = MultipartState::default();
        st.create("u1".into(), upload(8)).unwrap();
        st.put_part("u1", part(1, 8, &["c0"])).unwrap();
        st.put_part("u1", part(2, 4, &["c1"])).unwrap();
        let parts = st.list_parts("u1").unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].part_number, 1);
        assert_eq!(parts[1].part_number, 2);
        assert!(st.remove("u1").is_some());
        assert!(st.list_parts("u1").is_err());
        // abort is idempotent
        assert!(st.remove("u1").is_none());
    }

    #[test]
    fn put_part_replaces_same_number() {
        let mut st = MultipartState::default();
        st.create("u".into(), upload(8)).unwrap();
        st.put_part("u", part(1, 8, &["a"])).unwrap();
        st.put_part("u", part(1, 8, &["b"])).unwrap(); // same number, new content
        let parts = st.list_parts("u").unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].chunk_cids, vec!["b".to_string()]);
    }

    #[test]
    fn put_part_rejects_bad_number_and_empty() {
        let mut st = MultipartState::default();
        st.create("u".into(), upload(8)).unwrap();
        assert!(st.put_part("u", part(0, 8, &["a"])).is_err());
        assert!(st.put_part("u", part(MAX_PARTS + 1, 8, &["a"])).is_err());
        assert!(st.put_part("u", part(1, 0, &[])).is_err(), "empty part");
    }

    #[test]
    fn create_enforces_inflight_cap() {
        let mut st = MultipartState::default();
        for i in 0..MAX_INFLIGHT_UPLOADS {
            st.create(format!("u{i}"), upload(8)).unwrap();
        }
        assert!(
            st.create("overflow".into(), upload(8)).is_err(),
            "in-flight cap enforced"
        );
        // re-creating an existing id is allowed (resume/overwrite)
        assert!(st.create("u0".into(), upload(8)).is_ok());
    }

    #[test]
    fn assemble_concatenates_chunks_in_order() {
        let mut up = upload(4);
        // part 1: 8 bytes = 2 chunks of 4 (multiple of part_chunk → valid non-final)
        up.parts.insert(1, part(1, 8, &["a0", "a1"]));
        // part 2 (final): 3 bytes = short final chunk
        up.parts.insert(2, part(2, 3, &["b0"]));
        let manifest = assemble_manifest(&up, &[(1, "etag1".into()), (2, "etag2".into())]).unwrap();
        assert_eq!(manifest.chunk_size, 4);
        assert_eq!(manifest.total_size, 11);
        assert_eq!(manifest.chunks, vec!["a0", "a1", "b0"]);
        assert!(manifest.is_v1());
    }

    #[test]
    fn assemble_rejects_non_multiple_nonfinal_part() {
        let mut up = upload(4);
        up.parts.insert(1, part(1, 3, &["a0"])); // 3 is not a multiple of 4, and it is NOT last
        up.parts.insert(2, part(2, 4, &["b0"]));
        let r = assemble_manifest(&up, &[(1, "etag1".into()), (2, "etag2".into())]);
        assert!(r.is_err(), "non-final short part must be rejected");
    }

    #[test]
    fn assemble_allows_short_final_part() {
        let mut up = upload(4);
        up.parts.insert(1, part(1, 4, &["a0"]));
        up.parts.insert(2, part(2, 1, &["b0"])); // short, but final → ok
        assert!(assemble_manifest(&up, &[(1, "etag1".into()), (2, "etag2".into())]).is_ok());
    }

    #[test]
    fn assemble_rejects_etag_mismatch_and_missing_and_unordered() {
        let mut up = upload(4);
        up.parts.insert(1, part(1, 4, &["a0"]));
        up.parts.insert(2, part(2, 4, &["b0"]));
        // etag mismatch
        assert!(assemble_manifest(&up, &[(1, "wrong".into())]).is_err());
        // missing part
        assert!(assemble_manifest(&up, &[(3, "etag3".into())]).is_err());
        // not ascending
        assert!(
            assemble_manifest(&up, &[(2, "etag2".into()), (1, "etag1".into())]).is_err(),
            "descending parts rejected"
        );
        // empty request
        assert!(assemble_manifest(&up, &[]).is_err());
    }

    #[test]
    fn state_save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("ce-mp-{}", std::process::id()));
        let path = dir.join("multipart.json");
        let mut st = MultipartState::default();
        st.create("u".into(), upload(8)).unwrap();
        st.put_part("u", part(1, 8, &["c0"])).unwrap();
        st.save(&path).unwrap();
        let loaded = MultipartState::load(&path).unwrap();
        assert_eq!(loaded.list_parts("u").unwrap().len(), 1);
        assert_eq!(loaded.schema, MULTIPART_SCHEMA);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_future_schema_rejected() {
        let dir = std::env::temp_dir().join(format!("ce-mp-fut-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("multipart.json");
        std::fs::write(&path, br#"{"schema": 999, "uploads": {}}"#).unwrap();
        assert!(MultipartState::load(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn assembled_size_sums_parts() {
        let mut up = upload(4);
        up.parts.insert(1, part(1, 4, &["a"]));
        up.parts.insert(2, part(2, 7, &["b"]));
        assert_eq!(up.assembled_size(), 11);
    }
}
