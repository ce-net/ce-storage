//! Durable **replicated buckets** — the former standalone `ce-bucket` crate, merged into ce-storage
//! behind the optional `replicated` feature.
//!
//! ce-storage on its own binds `key -> CID` and serves the bytes (content-addressed, single-writer).
//! This module makes a bucket **durable across hosts** by composing two existing layers rather than
//! reimplementing anything:
//!
//! | Concern                                  | Provided by (composed, not reinvented)                  |
//! |------------------------------------------|----------------------------------------------------------|
//! | Bucket / object namespace, `key -> CID`, S3 verbs, ranged reads, versioning | [`crate::store::Store`] |
//! | Replication to N hosts across distinct fault domains (region/zone/ASN/owner) | `ce_pin::client::replicate` (calls `ce_pin::placement::select`) |
//! | Proof-of-retrievability audits + cheap status probes | `ce_pin::client::audit_replica` / `probe_status` |
//! | Payment for pins (rent channels)         | wired by `ce_pin::client::replicate` over CE payment channels |
//! | Auto-repair shortfall decision           | `ce_pin::repair::repair_plan` |
//!
//! The **only** new state this module owns is the [`ReplicaIndex`]: the durable binding from a
//! namespace coordinate `(bucket, key)` to its replication facts `{cid, replica_hosts, expiry}`, plus
//! a per-bucket [`BucketPolicy`] (the replication factor).
//!
//! ```no_run
//! use ce_storage::replicated::ReplicatedStore;
//! use ce_storage::index::default_index_path;
//! use ce_storage::replicated::ReplicaIndex;
//! # async fn demo() -> anyhow::Result<()> {
//! let mut store = ReplicatedStore::open(
//!     default_index_path(),
//!     ReplicaIndex::default_path(),
//!     String::new(), // capability chain hex (empty = self-rooted hosts only)
//! )?;
//! store.make_bucket("backups", Some(3))?;        // 3-way, fault-domain-diverse
//! store.put_object("backups", "db.sql", b"...", "application/sql", None).await?;
//! let bytes = store.get_object("backups", "db.sql").await?; // CID-verified, mesh-aware
//! let report = store.maintain().await?;          // audit + auto-repair to the factor
//! # let _ = (bytes, report); Ok(())
//! # }
//! ```

pub mod index;
pub mod store;

pub use index::{BucketPolicy, RecordEntry, ReplicaIndex};
pub use store::{
    expiry_height_from, MaintainReport, PutReport, ReplicatedStore, DEFAULT_LEASE_BLOCKS,
    DEFAULT_RENT_PER_GB_HOUR, DEFAULT_REPLICATION_FACTOR,
};
