# Changelog

All notable changes to ce-storage are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this crate is pre-1.0 so minor versions may break.

## [Unreleased]

### Added
- Live end-to-end tests for **multipart upload** and **sealed objects** against an ephemeral node
  (`tests/live_multipart_seal.rs`): multipart round trip + cross-part ranged read + assembled-CID
  equality to a single put; abort/validation paths; sealed round trip proving the host stores only
  ciphertext and a wrong key is rejected; sealed + versioning composition.
- `ARCHITECTURE.md` documenting the content-addressed object model, the single-writer + file-lock
  concurrency model, the on-disk index/multipart formats and migration, the multipart and sealed
  constructions, the `ce-cap` authorization model, and an explicit deferred-features table.
- `CHANGELOG.md` (this file).

### Changed
- README rewritten to reflect the implemented feature set (versioning, multipart, sealed objects,
  lifecycle, conditional requests, user metadata, gateway capability enforcement) and to state the
  deferred features up front rather than understating maturity.

## [0.1.0]

### Added
- Buckets (create/remove/list) and the core object verbs: `PutObject`, `GetObject` (full + ranged),
  `HeadObject`, `DeleteObject`, `CopyObject`, `ListObjectsV2` (prefix/delimiter/continuation).
- Object **versioning** (version ids = CIDs, delete markers, `?versionId=`), **user metadata** +
  caching headers, **conditional requests** (304/412), **bulk DeleteObjects**, **lifecycle/TTL**
  expiration + sweeper.
- **Multipart / resumable upload** assembled from content-addressed parts (no copy on completion).
- **Sealed objects** — client-side encrypt-before-store (encrypt-then-MAC over SHA-256), the SSE-C
  analogue.
- **Presigned-equivalent links** — `ce-cap` chains scoped to `bucket/prefix`, offline-verifiable;
  boundary-aware scope matching.
- Feature-gated **S3-subset HTTP gateway** with optional `ce-cap` enforcement, a body-size limit
  (413), `x-amz-copy-source` CopyObject, and bulk delete.
- **Crash-safe** atomic (temp-file + fsync + rename) persistence and a **cross-process advisory file
  lock** serialising index/multipart mutations.
- The `ce-storage` CLI and a `presign → verify_link` example.
- Extensive unit, property, concurrency, and live (ephemeral-node) tests.
