//! The replica index — the one piece of state the replicated layer owns.
//!
//! The replicated layer binds a `(bucket, key)` namespace coordinate (owned by [`crate::store::Store`])
//! to the replication facts ce-pin produces for that object's CID: the CID, the holder set, the desired
//! factor, and the rent expiry height. ce-storage already tracks `key -> CID`; ce-pin already tracks
//! `cid -> replicas`. Neither knows the *bucket/key -> replication intent* binding, so that — and only
//! that — lives here.
//!
//! ## Why a separate index (and not just ce-pin's pin-set)
//! ce-pin's pin-set is keyed by CID. Two different keys can resolve to the same CID (free dedup), and
//! a bucket's *policy* (its replication factor) is a namespace concept, not a content one. So we keep
//! a thin `bucket/key -> RecordEntry` map here and let ce-pin remain the source of truth for the live
//! replica health. This index is the durable record of intent + last-known placement.
//!
//! ## Durability
//! Persisted as pretty-printed JSON, written **atomically** (temp file in the same directory + rename)
//! so a crash or a concurrent reader never observes a truncated file — mirroring the ce-pin pin-set
//! and ce-storage index persistence style.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Per-bucket replication policy. Today just the desired replication factor; kept as a struct so rent
/// terms / region pinning can be added without a format break (all fields `#[serde(default)]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketPolicy {
    /// Desired number of distinct-fault-domain replicas for objects in this bucket.
    pub replication_factor: u8,
}

impl BucketPolicy {
    /// A policy with the given factor (clamped to at least 1 — a bucket with zero replicas is not a
    /// bucket, it is a hole).
    pub fn with_factor(factor: u8) -> Self {
        BucketPolicy { replication_factor: factor.max(1) }
    }
}

/// One tracked object: the binding from a namespace coordinate to its replication facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordEntry {
    /// The object CID (manifest hash) ce-storage bound this key to. Re-put of identical bytes keeps
    /// the same CID (dedup), so this changes only when the key's content changes.
    pub cid: String,
    /// Object size in bytes (carried so re-replication can size rent channels without a refetch).
    pub bytes_len: u64,
    /// Desired replication factor for this object (snapshot of the bucket policy at put time, so a
    /// later policy change does not silently rewrite an object's intent until it is re-put).
    pub replication_factor: u8,
    /// Holders that last accepted/held a replica of `cid` (64-hex NodeIds). Updated by `maintain`.
    #[serde(default)]
    pub replica_hosts: Vec<String>,
    /// Block height after which rent is no longer guaranteed (the pin lease expiry).
    #[serde(default)]
    pub expiry_height: u64,
}

impl RecordEntry {
    /// Whether this object currently has fewer recorded healthy holders than its desired factor.
    /// Pure; `maintain` uses the live ce-pin audit result, but this is the cheap index-only view used
    /// by `ls`/reporting and unit tests.
    pub fn is_under_replicated(&self) -> bool {
        self.replica_hosts.len() < self.replication_factor as usize
    }
}

/// The whole replica index: per-bucket policy + the `bucket -> { key -> RecordEntry }` map. `BTreeMap`
/// throughout so the on-disk JSON is stable and diffs cleanly.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplicaIndex {
    /// Per-bucket replication policy.
    #[serde(default)]
    pub policies: BTreeMap<String, BucketPolicy>,
    /// `bucket -> { key -> RecordEntry }`.
    #[serde(default)]
    pub records: BTreeMap<String, BTreeMap<String, RecordEntry>>,
}

impl ReplicaIndex {
    /// Default on-disk location: `<config dir>/ce-bucket/replicas.json`, overridable via
    /// `$CE_BUCKET_DIR`. The `ce-bucket` path segment / env var are kept (rather than renamed to
    /// ce-storage) so replica indexes written by the former standalone `ce-bucket` crate load
    /// unchanged after the merge.
    pub fn default_path() -> PathBuf {
        if let Some(d) = std::env::var_os("CE_BUCKET_DIR") {
            return PathBuf::from(d).join("replicas.json");
        }
        directories::ProjectDirs::from("", "", "ce-bucket")
            .map(|p| p.config_dir().join("replicas.json"))
            .unwrap_or_else(|| PathBuf::from(".ce-bucket").join("replicas.json"))
    }

    /// Load the index from `path`, returning an empty index if the file does not exist.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing replica index {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ReplicaIndex::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Persist atomically (temp file in the same dir + rename), creating parents as needed. A crash
    /// or concurrent reader never sees a half-written index.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let json = serde_json::to_vec_pretty(self)?;
        atomic_write(path, &json).with_context(|| format!("writing {}", path.display()))
    }

    /// Set (or replace) a bucket's replication policy.
    pub fn set_policy(&mut self, bucket: &str, policy: BucketPolicy) {
        self.policies.insert(bucket.to_string(), policy);
    }

    /// The effective replication factor for a bucket: its policy if set, else `default_factor`.
    pub fn factor_for(&self, bucket: &str, default_factor: u8) -> u8 {
        self.policies
            .get(bucket)
            .map(|p| p.replication_factor)
            .unwrap_or(default_factor)
            .max(1)
    }

    /// Bind/refresh a record for `bucket/key`.
    pub fn put_record(&mut self, bucket: &str, key: &str, entry: RecordEntry) {
        self.records
            .entry(bucket.to_string())
            .or_default()
            .insert(key.to_string(), entry);
    }

    /// Look up a record.
    pub fn get_record(&self, bucket: &str, key: &str) -> Option<&RecordEntry> {
        self.records.get(bucket).and_then(|b| b.get(key))
    }

    /// Mutable lookup (for `maintain` to refresh holders/health in place).
    pub fn get_record_mut(&mut self, bucket: &str, key: &str) -> Option<&mut RecordEntry> {
        self.records.get_mut(bucket).and_then(|b| b.get_mut(key))
    }

    /// Remove a record, returning it if present.
    pub fn remove_record(&mut self, bucket: &str, key: &str) -> Option<RecordEntry> {
        self.records.get_mut(bucket).and_then(|b| b.remove(key))
    }

    /// Every tracked `(bucket, key)` pair, sorted — the set `maintain` iterates.
    pub fn all_records(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for (bucket, keys) in &self.records {
            for key in keys.keys() {
                out.push((bucket.clone(), key.clone()));
            }
        }
        out
    }
}

/// Atomically write `bytes` to `path`: write a sibling temp file, fsync it, then rename over the
/// target (rename is atomic within a filesystem). Independent re-implementation so the replicated
/// layer does not reach into ce-pin's private `held::atomic_write`.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("replicas.json"),
        std::process::id()
    ));
    {
        let mut f = std::fs::File::create(&tmp)
            .with_context(|| format!("creating temp file {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(cid: &str, factor: u8, holders: &[&str]) -> RecordEntry {
        RecordEntry {
            cid: cid.into(),
            bytes_len: 1024,
            replication_factor: factor,
            replica_hosts: holders.iter().map(|s| s.to_string()).collect(),
            expiry_height: 8640,
        }
    }

    #[test]
    fn policy_factor_clamps_to_at_least_one() {
        assert_eq!(BucketPolicy::with_factor(0).replication_factor, 1);
        assert_eq!(BucketPolicy::with_factor(3).replication_factor, 3);
    }

    #[test]
    fn factor_for_uses_policy_then_default() {
        let mut idx = ReplicaIndex::default();
        assert_eq!(idx.factor_for("photos", 3), 3, "no policy -> default");
        idx.set_policy("photos", BucketPolicy::with_factor(5));
        assert_eq!(idx.factor_for("photos", 3), 5, "policy overrides default");
        // A pathological zero policy is clamped on read too.
        idx.set_policy("zero", BucketPolicy { replication_factor: 0 });
        assert_eq!(idx.factor_for("zero", 3), 1);
    }

    #[test]
    fn under_replicated_detection_is_pure() {
        assert!(entry("c", 3, &["a", "b"]).is_under_replicated(), "2 of 3 -> under");
        assert!(!entry("c", 3, &["a", "b", "c"]).is_under_replicated(), "3 of 3 -> ok");
        assert!(!entry("c", 3, &["a", "b", "c", "d"]).is_under_replicated(), "over -> not under");
    }

    #[test]
    fn put_get_remove_record_roundtrip() {
        let mut idx = ReplicaIndex::default();
        idx.put_record("buk", "a/x", entry("cid1", 3, &["h1"]));
        assert_eq!(idx.get_record("buk", "a/x").unwrap().cid, "cid1");
        assert!(idx.get_record("buk", "missing").is_none());
        assert!(idx.get_record("nope", "a/x").is_none());
        let removed = idx.remove_record("buk", "a/x");
        assert_eq!(removed.unwrap().cid, "cid1");
        assert!(idx.get_record("buk", "a/x").is_none());
    }

    #[test]
    fn all_records_is_sorted_and_complete() {
        let mut idx = ReplicaIndex::default();
        idx.put_record("b2", "k1", entry("c", 1, &[]));
        idx.put_record("b1", "k2", entry("c", 1, &[]));
        idx.put_record("b1", "k1", entry("c", 1, &[]));
        let all = idx.all_records();
        assert_eq!(
            all,
            vec![
                ("b1".to_string(), "k1".to_string()),
                ("b1".to_string(), "k2".to_string()),
                ("b2".to_string(), "k1".to_string()),
            ]
        );
    }

    #[test]
    fn roundtrips_through_disk_atomically() {
        let dir = std::env::temp_dir().join(format!("ce-storage-replicated-test-{}", std::process::id()));
        let path = dir.join("replicas.json");
        let _ = std::fs::remove_dir_all(&dir);
        let mut idx = ReplicaIndex::default();
        idx.set_policy("buk", BucketPolicy::with_factor(4));
        idx.put_record("buk", "a/x", entry("cid1", 4, &["h1", "h2"]));
        idx.save(&path).unwrap();

        let loaded = ReplicaIndex::load(&path).unwrap();
        assert_eq!(loaded.factor_for("buk", 3), 4);
        assert_eq!(loaded.get_record("buk", "a/x").unwrap().replica_hosts.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_loads_empty() {
        let path = std::env::temp_dir().join("ce-storage-replicated-does-not-exist-zzz/replicas.json");
        let idx = ReplicaIndex::load(&path).unwrap();
        assert!(idx.records.is_empty());
        assert!(idx.policies.is_empty());
    }
}
