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
//! | Bucket index (`key -> CID`) | a sorted map persisted as JSON, mutated under a cross-process advisory lock ([`lock`]) for a single-writer owner |
//! | Authorization / presigned links | `ce-cap` signed attenuating chains scoped to `bucket/prefix` (`storage:read` / `storage:write`), enforced by the gateway ([`gateway::Auth`]) |
//! | Ranged reads         | manifest chunk-index math ([`range`]) → fetch only covering chunks    |
//!
//! ## Shape
//!
//! - [`index`]  — the bucket index: `bucket -> { key -> ObjectEntry }` with version history,
//!   user metadata, and headers; JSON-persisted, sorted for prefix/delimiter/continuation listing.
//! - [`range`]  — pure ranged-read math: parse a `Range` header, compute covering chunks, slice.
//! - [`caps`]   — presigned-equivalent links: mint/verify a `ce-cap` chain scoped to `bucket/prefix`.
//! - [`lock`]   — a dependency-free cross-process advisory file lock guarding index mutations.
//! - [`store`]  — [`Store`]: the S3-verb library API over `ce-rs` + the index, with size limits,
//!   versioning, conditional requests, and bulk delete.
//! - [`gateway`] (feature `gateway`) — a tiny HTTP server exposing an S3-subset (with optional
//!   `ce-cap` enforcement + a body-size limit) so `aws s3`-style clients work unmodified.
//!
//! ## Why CE wins (vs S3/GCS)
//!
//! Content-addressing makes ETags perfect cache keys and gives **free dedup** (upload the same
//! bytes twice → zero extra storage, same CID). Presigned access is an **offline-verifiable
//! capability**, not a signed URL checked by a central policy server.
//!
//! ## What is implemented vs deferred (be honest)
//!
//! **Implemented & tested:** buckets, put/get/head/list/delete/copy, ranged reads, ListObjectsV2
//! (prefix/delimiter/continuation, KeyCount/MaxKeys/LastModified), object **versioning** (version
//! ids = CIDs, delete markers, `versionId` reads/deletes), **user metadata + caching headers**,
//! **conditional requests** (If-Match/If-None-Match/If-*-Since → 304/412), **bulk DeleteObjects**,
//! **lifecycle / TTL expiration rules** ([`LifecycleRule`] + [`Store::sweep_expired`]/[`Store::sweep_all`]),
//! gateway **CopyObject** (`x-amz-copy-source`), a **body-size limit** (413), per-object **size
//! cap**, **cross-process index locking**, **gateway capability enforcement** ([`gateway::Auth`]),
//! **multipart / resumable upload** ([`multipart`] — Create/Upload/Complete/Abort/List, assembled
//! from content-addressed parts with no copy on completion), and **sealed objects** ([`seal`] —
//! client-side encrypt-before-store with an authenticated cipher, the SSE-C analogue).
//!
//! **Deferred (documented, not faked):** true multi-host durability/pinning (the companion `ce-pin`
//! app's job — [`Store::pin_hint`] exposes the CID for that handoff, but ce-storage does not pin
//! itself); managed server-side keys (SSE-S3/SSE-KMS — the sealed-object mode is client-key only,
//! the SSE-C analogue); AWS SigV4 (the `ce-cap` link is the auth mechanism instead); storage-class
//! transitions (only expiration is implemented, not tiering); streaming bodies (objects are bounded
//! and buffered, not streamed). See `ARCHITECTURE.md`.
//!
//! ```no_run
//! use ce_storage::store::Store;
//! use ce_storage::index::default_index_path;
//!
//! # async fn demo() -> anyhow::Result<()> {
//! let mut store = Store::open(default_index_path())?;
//! store.make_bucket("my-bucket")?;
//! let meta = store.put_object("my-bucket", "hello.txt", b"hello", "text/plain").await?;
//! assert_eq!(meta.size, 5);
//! let got = store.get_object("my-bucket", "hello.txt").await?;
//! assert_eq!(got.bytes, b"hello");
//! # Ok(())
//! # }
//! ```

pub mod caps;
pub mod index;
pub mod lock;
pub mod multipart;
pub mod range;
pub mod seal;
pub mod store;

#[cfg(feature = "gateway")]
pub mod gateway;

pub use caps::{ABILITY_READ, ABILITY_WRITE, Scope};
pub use index::{Bucket, Index, LifecycleRule, ListPage, ObjectEntry, ObjectMeta, ObjectVersion};
pub use multipart::{MultipartState, Part, Upload};
pub use range::CoveringRange;
pub use store::{GetResult, Preconditions, PutOptions, StorageError, Store};
