//! # ce-storage — an S3/GCS-compatible object store over CE blobs
//!
//! ce-storage is an **application built on CE primitives** (the SDK tier, like `ce-pin` / `swarm` /
//! `rdev`), not a node feature. It turns CE's flat, content-addressed blob layer into named
//! **buckets** and **objects** with the familiar S3 verb set — `PutObject`, `GetObject` (incl.
//! ranged reads), `ListObjectsV2`, `HeadObject`, `DeleteObject`, `CopyObject` — plus
//! presigned-equivalent access **links** (a `ce-cap` capability scoped to a bucket/prefix).
//!
//! ## How it composes existing CE
//!
//! | Concern              | CE primitive (composed, not reinvented)                              |
//! |----------------------|----------------------------------------------------------------------|
//! | Object storage       | `ce-rs` `put_object` / `get_object` over the `/blobs` store (1 MiB chunks, content-addressed) |
//! | Durability / availability | `ce-pin` (pin a CID across N hosts); blobs announced to the DHT for replication |
//! | Bucket index (`key -> CID`) | a sorted map persisted as JSON (the ce-coord `RMap` shape, kept local for a single-writer owner) |
//! | Authorization / presigned links | `ce-cap` signed attenuating chains scoped to `bucket/prefix` (`storage:read` / `storage:write`) |
//! | Ranged reads         | manifest chunk-index math ([`range`]) → fetch only covering chunks    |
//!
//! ## Shape
//!
//! - [`index`]  — the bucket index: `bucket -> { key -> ObjectMeta }`, JSON-persisted, sorted for
//!   prefix/delimiter/continuation listing.
//! - [`range`]  — pure ranged-read math: parse a `Range` header, compute covering chunks, slice.
//! - [`caps`]   — presigned-equivalent links: mint/verify a `ce-cap` chain scoped to `bucket/prefix`.
//! - [`store`]  — [`Store`]: the S3-verb library API over `ce-rs` + the index.
//! - [`gateway`] (feature `gateway`) — a tiny HTTP server exposing an S3-subset so `aws s3`-style
//!   clients work unmodified.
//!
//! ## Why CE wins (vs S3/GCS)
//!
//! Content-addressing makes ETags perfect cache keys and gives **free dedup** (upload the same
//! bytes twice → zero extra storage, same CID). Objects are geo-replicated by **pinning**, not by a
//! region you pay egress to leave. Presigned access is an **offline-verifiable capability**, not a
//! signed URL checked by a central policy server. Sealed (encrypt-before-store) objects the host
//! cannot read are a natural extension (the bytes are opaque to every node but the holder).

pub mod caps;
pub mod index;
pub mod range;
pub mod store;

#[cfg(feature = "gateway")]
pub mod gateway;

pub use caps::{Scope, ABILITY_READ, ABILITY_WRITE};
pub use index::{Bucket, Index, ListPage, ObjectMeta};
pub use range::CoveringRange;
pub use store::{GetResult, Store};
