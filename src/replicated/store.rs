//! [`ReplicatedStore`] — the wiring that makes a ce-storage bucket durable across hosts.
//!
//! This is the whole point of the `replicated` module (the former `ce-bucket` crate): it composes two
//! existing layers and adds nothing they already do.
//!
//! * **Namespace + bytes** come from [`crate::store::Store`]: `make_bucket`, `put_object` (which stores
//!   the bytes content-addressed and returns an [`crate::ObjectMeta`] carrying the CID), `get_object`,
//!   `list_objects`, `head_object`.
//! * **Replication** comes from `ce-pin`: [`ce_pin::client::candidate_hosts`] (DHT + atlas + on-chain
//!   reputation), [`ce_pin::placement::select`] (fault-domain / owner-diverse placement),
//!   [`ce_pin::client::replicate`] (offer + paid channel), [`ce_pin::client::audit_replica`] /
//!   [`ce_pin::client::probe_status`] (proof-of-retrievability), and [`ce_pin::repair::repair_plan`]
//!   (the pure under-replication decision). We do **not** re-implement any of that.
//! * **The binding** — `(bucket, key) -> {cid, replica_hosts, expiry}` — is the one new thing, in
//!   [`super::index`].
//!
//! Mesh-first: every cross-host action goes through `ce-rs` (request/reply, DHT, channels) inside the
//! ce-pin calls. The replicated layer opens no side HTTP channel and stores no ip:port.

use std::path::PathBuf;

use anyhow::{Context, Result};
use ce_pin::client as pin_client;
use ce_pin::pinset::Replica;
use ce_pin::repair;
use ce_rs::CeClient;

use super::index::{BucketPolicy, RecordEntry, ReplicaIndex};
use crate::store::Store;

/// Default replication factor when a bucket has no explicit policy. Three distinct fault domains is
/// the usual durability sweet spot.
pub const DEFAULT_REPLICATION_FACTOR: u8 = 3;

/// Default rent offered to pinning hosts, base units per GB-hour (decimal string; never a float).
/// Zero means "best-effort, unpaid pins" — usable on a friendly/own mesh; raise it to attract hosts.
pub const DEFAULT_RENT_PER_GB_HOUR: &str = "0";

/// How many blocks ahead to set the pin-lease expiry by default (~10s/block => 8640 blocks ≈ 24h).
pub const DEFAULT_LEASE_BLOCKS: u64 = 8640;

/// Outcome of a single `put_object`: what was stored and where it landed.
#[derive(Debug, Clone)]
pub struct PutReport {
    /// The object CID (ETag) ce-storage bound the key to.
    pub cid: String,
    /// Object size in bytes.
    pub bytes_len: u64,
    /// Desired replication factor for this object.
    pub replication_factor: u8,
    /// Holders that accepted a replica (may be fewer than the factor if the mesh is short on hosts;
    /// `maintain` will top up later).
    pub replica_hosts: Vec<String>,
}

/// Outcome of a `maintain` pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaintainReport {
    /// Objects examined.
    pub objects_checked: usize,
    /// Objects that were under-replicated and triggered re-placement.
    pub objects_repaired: usize,
    /// New replicas successfully placed across all objects.
    pub replicas_added: usize,
    /// Replica probes/audits that came back unhealthy this pass.
    pub replicas_unhealthy: usize,
}

/// A bucket store with N-way, fault-domain-diverse replication.
pub struct ReplicatedStore {
    /// The CE SDK client (local node). All mesh I/O flows through here.
    ce: CeClient,
    /// The S3-verb namespace + bytes layer.
    store: Store,
    /// Our durable `(bucket,key) -> replication facts` binding.
    index: ReplicaIndex,
    /// Where the replica index is persisted.
    index_path: PathBuf,
    /// Capability chain hex presented to pinning hosts (resolved via `ce-pin`'s caps resolution).
    caps: String,
    /// Default replication factor for buckets without a policy.
    default_factor: u8,
    /// Rent offered to hosts (base units per GB-hour, decimal string).
    rent_per_gb_hour: String,
    /// Lease length in blocks used to compute `expiry_height` at put time.
    lease_blocks: u64,
}

impl ReplicatedStore {
    /// Open a replicated store against the local CE node.
    ///
    /// `storage_index_path` is ce-storage's bucket index; `replica_index_path` is the replica
    /// index ([`ReplicaIndex::default_path`]); `caps` is the capability chain hex presented to
    /// pinning hosts (use [`ce_pin::caps::resolve`] to load it from `--caps`/env/file).
    pub fn open(
        storage_index_path: PathBuf,
        replica_index_path: PathBuf,
        caps: String,
    ) -> Result<Self> {
        let ce = CeClient::local();
        let store = Store::with_client(ce.clone(), storage_index_path)
            .context("opening ce-storage bucket index")?;
        let index = ReplicaIndex::load(&replica_index_path)?;
        Ok(Self {
            ce,
            store,
            index,
            index_path: replica_index_path,
            caps,
            default_factor: DEFAULT_REPLICATION_FACTOR,
            rent_per_gb_hour: DEFAULT_RENT_PER_GB_HOUR.to_string(),
            lease_blocks: DEFAULT_LEASE_BLOCKS,
        })
    }

    /// Builder: set the default replication factor (for buckets without a policy).
    pub fn with_default_factor(mut self, factor: u8) -> Self {
        self.default_factor = factor.max(1);
        self
    }

    /// Builder: set the rent offered to hosts (base units per GB-hour, decimal string).
    pub fn with_rent_per_gb_hour(mut self, rent: impl Into<String>) -> Self {
        self.rent_per_gb_hour = rent.into();
        self
    }

    /// Builder: set the lease length in blocks.
    pub fn with_lease_blocks(mut self, blocks: u64) -> Self {
        self.lease_blocks = blocks;
        self
    }

    /// Immutable view of the replica index.
    pub fn index(&self) -> &ReplicaIndex {
        &self.index
    }

    // ---- bucket verbs ----

    /// Create a bucket (delegated to ce-storage) and, optionally, set its replication policy. With
    /// `factor = None` the bucket inherits the store default until a policy is set.
    pub fn make_bucket(&mut self, bucket: &str, factor: Option<u8>) -> Result<()> {
        self.store
            .make_bucket(bucket)
            .with_context(|| format!("creating bucket {bucket}"))?;
        if let Some(f) = factor {
            self.index.set_policy(bucket, BucketPolicy::with_factor(f));
            self.index.save(&self.index_path)?;
        }
        Ok(())
    }

    /// Set (or change) a bucket's replication policy. Does not retroactively re-replicate existing
    /// objects — `maintain` brings them up to the new factor on its next pass for keys re-put after
    /// the change; existing records keep their put-time factor until re-put. (This is deliberate: a
    /// policy change is intent, `maintain` is the actuator.)
    pub fn set_policy(&mut self, bucket: &str, factor: u8) -> Result<()> {
        self.index.set_policy(bucket, BucketPolicy::with_factor(factor));
        self.index.save(&self.index_path)
    }

    /// List bucket names.
    pub fn list_buckets(&self) -> Vec<String> {
        self.store.list_buckets()
    }

    /// `ListObjectsV2` (delegated to ce-storage). Returns keys/prefixes for `prefix`.
    pub fn list_objects(
        &self,
        bucket: &str,
        prefix: &str,
        max_keys: usize,
    ) -> Result<crate::ListPage> {
        self.store
            .list_objects(bucket, prefix, None, None, max_keys)
            .with_context(|| format!("listing {bucket}/{prefix}"))
    }

    // ---- object verbs ----

    /// `PutObject` with N-way replication.
    ///
    /// 1. Store the bytes content-addressed and bind `bucket/key -> CID` via ce-storage.
    /// 2. Resolve the effective replication factor (per-object override > bucket policy > default).
    /// 3. Drive ce-pin to place `factor` replicas across distinct fault domains
    ///    ([`ce_pin::client::candidate_hosts`] + [`ce_pin::client::replicate`], which itself calls
    ///    [`ce_pin::placement::select`] for owner/region diversity).
    /// 4. Record `bucket/key -> {cid, replica_hosts, expiry}` durably.
    ///
    /// Replication is best-effort at put time: if the mesh has fewer eligible hosts than the factor,
    /// the object is still stored and bound, the partial placement is recorded, and `maintain` tops
    /// it up later. The CID binding is durable regardless (the bytes are content-addressed locally and
    /// DHT-announced), so a put never silently loses data.
    pub async fn put_object(
        &mut self,
        bucket: &str,
        key: &str,
        bytes: &[u8],
        content_type: &str,
        replication_factor: Option<u8>,
    ) -> Result<PutReport> {
        // 1. Namespace + bytes (ce-storage). meta.cid is the manifest hash.
        let meta = self
            .store
            .put_object(bucket, key, bytes, content_type)
            .await
            .with_context(|| format!("storing {bucket}/{key} via ce-storage"))?;
        let cid = meta.cid.clone();
        let bytes_len = meta.size;

        // 2. Effective replication factor.
        let factor = replication_factor
            .map(|f| f.max(1))
            .unwrap_or_else(|| self.index.factor_for(bucket, self.default_factor));

        // 3. Replication (ce-pin). Compute the lease expiry from the chain tip, then place.
        let expiry_height = self.lease_expiry_height().await;
        let replica_hosts = self
            .place_replicas(&cid, bytes_len, factor as usize, expiry_height, &[])
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(bucket, key, cid = %cid, error = %e, "initial replication incomplete; maintain will top up");
                Vec::new()
            });

        // 4. Durable binding.
        let entry = RecordEntry {
            cid: cid.clone(),
            bytes_len,
            replication_factor: factor,
            replica_hosts: replica_hosts.clone(),
            expiry_height,
        };
        self.index.put_record(bucket, key, entry);
        self.index.save(&self.index_path)?;

        tracing::info!(
            bucket,
            key,
            cid = %cid,
            placed = replica_hosts.len(),
            factor,
            "put_object: stored + replicated"
        );
        Ok(PutReport { cid, bytes_len, replication_factor: factor, replica_hosts })
    }

    /// `GetObject`. Serve from ce-storage (which resolves the CID and pulls+verifies every chunk,
    /// falling back to the mesh DHT for any chunk not held locally). This is already CID-verified and
    /// mesh-aware end to end, so a fetch from a remote replica is trustless. Returns the object bytes.
    ///
    /// If the key is not in ce-storage's local index (e.g. this node only holds the replica record,
    /// not the namespace binding), we fall back to our own replica index for the CID and fetch by CID
    /// directly over the mesh via ce-pin ([`ce_pin::client::get`], also CID-verified).
    pub async fn get_object(&self, bucket: &str, key: &str) -> Result<Vec<u8>> {
        match self.store.get_object(bucket, key).await {
            Ok(res) => Ok(res.bytes),
            Err(primary_err) => {
                // Fall back to our replica index: fetch by CID over the mesh (CID-verified).
                if let Some(rec) = self.index.get_record(bucket, key) {
                    tracing::debug!(bucket, key, cid = %rec.cid, "get_object: local namespace miss, fetching by CID over mesh");
                    return pin_client::get(&self.ce, &rec.cid)
                        .await
                        .with_context(|| format!("fetching {bucket}/{key} by CID over the mesh"));
                }
                Err(primary_err).with_context(|| format!("getting {bucket}/{key}"))
            }
        }
    }

    /// The CID an object resolves to (from our replica index, else ce-storage's `pin_hint`).
    pub fn object_cid(&self, bucket: &str, key: &str) -> Result<String> {
        if let Some(rec) = self.index.get_record(bucket, key) {
            return Ok(rec.cid.clone());
        }
        self.store.pin_hint(bucket, key)
    }

    // ---- maintenance / auto-repair ----

    /// One maintenance pass over every tracked object: probe each recorded replica
    /// ([`ce_pin::client::probe_status`] + [`ce_pin::client::audit_replica`] for proof-of-
    /// retrievability), then re-replicate any under-provisioned object back to its factor across
    /// distinct fault domains. The pure shortfall decision is [`ce_pin::repair::repair_plan`]; the
    /// placement is [`ce_pin::placement::select`] (inside [`ce_pin::client::replicate`]).
    ///
    /// Updates `replica_hosts` to the set that passed this pass, adds new holders for repaired
    /// objects, and persists the index atomically. Returns a [`MaintainReport`].
    pub async fn maintain(&mut self) -> Result<MaintainReport> {
        let mut report = MaintainReport::default();
        let targets = self.index.all_records();
        let mut dirty = false;
        let expiry_height = self.lease_expiry_height().await;

        for (bucket, key) in targets {
            let Some(rec) = self.index.get_record(&bucket, &key).cloned() else { continue };
            report.objects_checked += 1;

            // 1. Audit each current holder (proof-of-retrievability); collect the healthy ones.
            let mut healthy: Vec<String> = Vec::new();
            for holder in &rec.replica_hosts {
                match pin_client::audit_replica(&self.ce, holder, &self.caps, &rec.cid).await {
                    Ok(true) => healthy.push(holder.clone()),
                    Ok(false) => report.replicas_unhealthy += 1,
                    Err(e) => {
                        report.replicas_unhealthy += 1;
                        tracing::debug!(bucket, key, host = %short(holder), error = %e, "audit error");
                    }
                }
            }

            // 2. Decide the shortfall with ce-pin's pure planner (reuse, do not re-derive).
            let as_replicas: Vec<Replica> = rec
                .replica_hosts
                .iter()
                .map(|h| Replica { holder: h.clone(), channel_id: String::new(), last_proof_ok: healthy.contains(h) })
                .collect();
            let plan = repair::repair_plan(&as_replicas, &healthy, rec.replication_factor as usize);

            // 3. Re-replicate the shortfall to fresh hosts (excluding all current holders).
            let mut new_hosts: Vec<String> = Vec::new();
            if plan.to_place > 0 {
                report.objects_repaired += 1;
                match self
                    .place_replicas(&rec.cid, rec.bytes_len, plan.to_place, expiry_height, &plan.exclude)
                    .await
                {
                    Ok(placed) => {
                        report.replicas_added += placed.len();
                        new_hosts = placed;
                    }
                    Err(e) => tracing::warn!(bucket, key, cid = %rec.cid, error = %e, "re-replication failed"),
                }
            }

            // 4. Write back the new holder set: the holders that passed + the freshly placed ones.
            let mut updated = healthy;
            for h in new_hosts {
                if !updated.contains(&h) {
                    updated.push(h);
                }
            }
            if updated != rec.replica_hosts {
                if let Some(e) = self.index.get_record_mut(&bucket, &key) {
                    e.replica_hosts = updated;
                    e.expiry_height = expiry_height;
                    dirty = true;
                }
            }
        }

        if dirty {
            self.index.save(&self.index_path)?;
        }
        tracing::info!(
            checked = report.objects_checked,
            repaired = report.objects_repaired,
            added = report.replicas_added,
            unhealthy = report.replicas_unhealthy,
            "maintain pass complete"
        );
        Ok(report)
    }

    // ---- internals ----

    /// Place up to `n` replicas of `cid` across distinct fault domains, excluding `exclude`. Wraps
    /// ce-pin: build ranked candidates, then `replicate` (which selects diverse hosts + opens paid
    /// channels). Returns the holders that accepted.
    async fn place_replicas(
        &self,
        cid: &str,
        bytes_len: u64,
        n: usize,
        expiry_height: u64,
        exclude: &[String],
    ) -> Result<Vec<String>> {
        if n == 0 {
            return Ok(Vec::new());
        }
        let candidates = pin_client::candidate_hosts(&self.ce)
            .await
            .context("gathering pinning-host candidates")?;
        if candidates.is_empty() {
            anyhow::bail!("no eligible pinning hosts advertised (pin:host) on the mesh");
        }
        // ce_pin::client::replicate internally calls ce_pin::placement::select(candidates, n, exclude)
        // — the fault-domain / owner-diverse placement — so we get geo/owner spread for free.
        let accepted: Vec<Replica> = pin_client::replicate(
            &self.ce,
            cid,
            bytes_len,
            &self.rent_per_gb_hour,
            expiry_height,
            n,
            &self.caps,
            &candidates,
            exclude,
        )
        .await
        .context("driving ce-pin replication")?;
        Ok(accepted.into_iter().map(|r| r.holder).collect())
    }

    /// The pin-lease expiry height = current chain tip + `lease_blocks`. Best-effort: if the node's
    /// status is unreadable we fall back to `lease_blocks` alone (a conservative non-zero expiry so a
    /// paid channel can still be sized).
    async fn lease_expiry_height(&self) -> u64 {
        let tip = self.ce.status().await.map(|s| s.height).unwrap_or(0);
        expiry_height_from(tip, self.lease_blocks)
    }
}

/// Pure helper: lease expiry height from the chain tip and the lease length in blocks. Saturating so
/// it never wraps near the height ceiling. Extracted so the (network-free) arithmetic is unit-tested.
pub fn expiry_height_from(tip: u64, lease_blocks: u64) -> u64 {
    tip.saturating_add(lease_blocks.max(1))
}

/// Shorten a 64-hex node id for log lines.
fn short(id: &str) -> &str {
    &id[..16.min(id.len())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_height_adds_lease_to_tip() {
        assert_eq!(expiry_height_from(100, 8640), 8740);
        // Zero lease is clamped to at least 1 so the expiry is strictly ahead of the tip.
        assert_eq!(expiry_height_from(100, 0), 101);
        // Saturating: never wraps.
        assert_eq!(expiry_height_from(u64::MAX, 10), u64::MAX);
    }

    #[test]
    fn short_truncates_node_ids() {
        assert_eq!(short("0123456789abcdef0123456789abcdef"), "0123456789abcdef");
        assert_eq!(short("short"), "short");
    }
}
