# ce-storage

**An S3/GCS-compatible object store over CE's content-addressed blobs.**

ce-storage is an **application built on CE primitives** (the SDK tier, alongside `ce-pin`,
`ce-coord`, `swarm`, `rdev`) — not a node feature. It turns CE's flat, content-addressed blob layer
into named **buckets** and **objects** with the familiar S3 verb set, plus presigned-equivalent
access **links** backed by `ce-cap` capabilities.

> Pronounced like the rest of CE ("Sea"). Buckets in, content-addressed objects out, no egress fee.

## What is implemented vs deferred (read this first)

**Implemented and tested** (unit + property + live ephemeral-node integration):

- Buckets: create / remove (`--force`) / list; S3-subset DNS-compatible bucket-name validation.
- Objects: `PutObject`, `GetObject` (full + **ranged**, fetching only covering chunks), `HeadObject`,
  `DeleteObject`, `CopyObject` (free — shares the content address), `ListObjectsV2`
  (prefix / delimiter rollups / continuation, with `KeyCount` / `MaxKeys` / `LastModified`).
- **Object versioning** — version ids are CIDs, delete markers, `?versionId=` reads/deletes,
  per-key history.
- **User metadata + caching headers** (`x-amz-meta-*`, `Cache-Control`, `Content-Disposition`,
  `Content-Encoding`), bounded in count and size.
- **Conditional requests** — `If-Match` / `If-None-Match` / `If-(Un)Modified-Since` → 304 / 412,
  giving cache validation and optimistic-concurrency / write-once writes.
- **Multipart / resumable upload** — `Create` / `UploadPart` / `Complete` / `Abort` / `List`,
  assembled from content-addressed parts with **no byte copy** on completion (see `src/multipart.rs`).
- **Sealed objects** — client-side **encrypt-before-store** (the SSE-C analogue): the host only ever
  sees ciphertext, authenticated with HMAC-SHA256 (encrypt-then-MAC). See `src/seal.rs`.
- **Lifecycle / TTL expiration** rules + a sweeper (`sweep` / `sweep_expired` / `sweep_all`).
- **Bulk `DeleteObjects`**.
- A feature-gated **S3-subset HTTP gateway** with an optional **`ce-cap` capability-enforcement**
  layer (403 without a valid scoped link), a body-size limit (413), `x-amz-copy-source` CopyObject,
  and bulk delete.
- **Crash-safe, concurrency-safe persistence** — the index and multipart state are written
  atomically (temp-file + fsync + rename) and every mutation is serialised by a cross-process
  advisory file lock, so a concurrent CLI + gateway cannot lose updates.

**Deferred (documented, never faked)** — see [ARCHITECTURE.md](ARCHITECTURE.md) for why:

- Multi-host durability / pinning is the companion `ce-pin` app's job; ce-storage exposes the CID
  (`Store::pin_hint`) for that handoff and does not silently pin.
- Managed server-side keys (SSE-S3 / SSE-KMS) — sealed objects are client-key only (the SSE-C
  analogue).
- AWS SigV4 request signing — the `ce-cap` link is the auth mechanism instead.
- Storage-class transitions (only expiration is implemented, not tiering).
- Streaming request/response bodies — objects are bounded by a configurable size cap and buffered,
  not streamed.

## What it composes (it reinvents nothing)

| Concern | CE primitive used |
|---|---|
| Object storage | `ce-rs` `put_object` / `get_object` over the node `/blobs` store — 1 MiB chunks, content-addressed, hash-verified on read |
| Durability / availability | `ce-pin` (pin a CID across N hosts); every `put_blob` is announced to the DHT for replication |
| Bucket index (`bucket/key -> CID`) | a sorted, JSON-persisted map — the ce-coord `RMap` shape kept local for the single-writer owner |
| Authorization / presigned links | `ce-cap` signed, attenuating chains scoped to `bucket/prefix` (`storage:read` / `storage:write`), offline-verifiable |
| Ranged reads | manifest chunk-index math — fetch only the covering chunks, slice the window |

## S3 verb mapping

| S3 verb | CE mapping |
|---|---|
| `PutObject` | `put_object(bytes) -> CID`, then bind `key -> CID` in the bucket index |
| `GetObject` | look up the CID, `get_object(CID)` (every chunk re-verified against its hash) |
| `GetObject` + `Range` | look up the CID, fetch only the covering chunks, slice the exact byte window |
| `HeadObject` | index lookup — no bytes move |
| `ListObjectsV2` | prefix / delimiter / continuation walk over the sorted index |
| `DeleteObject` | drop the key from the index (bytes stay content-addressed; GC/unpin is separate) |
| `CopyObject` | share the CID — **free**, no bytes move (dedup by content address) |

Because objects are content-addressed, the **ETag is the CID**: equal ETag ⇒ identical bytes, so
re-uploading the same file is free dedup, and ETags are perfect cache keys.

## Install / build

```bash
cd ~/ce-net/ce-storage
cargo build --release                    # CLI: target/release/ce-storage
cargo build --release --features gateway # also builds the S3-subset HTTP gateway subcommand
```

ce-storage talks to your **local CE node** (`http://127.0.0.1:8844`) via `ce-rs`, discovering the
API token from `$CE_API_TOKEN` or `<CE data dir>/api.token`. Start a node first: `ce start`.

## CLI

```bash
# buckets
ce-storage mb my-bucket
ce-storage ls                            # list buckets
ce-storage rb my-bucket [--force]

# objects
ce-storage put my-bucket/path/to/key ./localfile           # PutObject
ce-storage get my-bucket/path/to/key ./out.bin             # GetObject
ce-storage get my-bucket/path/to/key ./part --range bytes=0-1023   # ranged GET
ce-storage head my-bucket/path/to/key                      # HeadObject (CID, size, type)
ce-storage ls my-bucket/path/ --delimiter /                # ListObjectsV2 (folder rollups)
ce-storage cp my-bucket/a my-bucket/b                      # CopyObject (free, shares CID)
ce-storage rm my-bucket/path/to/key                        # DeleteObject

# presigned-equivalent access links (a ce-cap chain scoped to bucket/prefix)
ce-storage presign my-bucket/photos/ --expires-in 3600     # read link, prints a token
ce-storage presign my-bucket/uploads/ --write              # write link
ce-storage inspect <token>                                 # show abilities + scope

# versioning, lifecycle, multipart, sealed objects
ce-storage versioning my-bucket                            # enable version history
ce-storage versions my-bucket/path/to/key                  # list an object's versions
ce-storage lifecycle set my-bucket --prefix tmp/ --expire-secs 86400   # TTL rule
ce-storage sweep my-bucket [--dry-run]                     # delete expired objects
ce-storage multipart upload my-bucket/big.bin ./big.bin --part-size 8388608
ce-storage put my-bucket/secret.bin ./plain --seal-key "my passphrase"  # encrypt-before-store
ce-storage get my-bucket/secret.bin ./out --seal-key "my passphrase"    # decrypt on read
```

### Presigned-equivalent links

An S3 presigned URL is a bearer token granting temporary access. The CE equivalent is a signed,
attenuating **`ce-cap` capability**: the bucket owner mints a chain whose abilities are
`["storage:read"]` (opaque app strings), whose resource is the owning node, and whose caveats carry
the expiry (`not_after`) and the `bucket/prefix` scope (`path_prefix`). Any honoring node verifies
it **offline in microseconds** — no policy server, no shared secret. The holder can **attenuate**
(narrow the prefix) and re-delegate it freely; revocation is on-chain (`RevokeCapability`) plus
expiry. See `src/caps.rs`.

## Optional: S3-subset HTTP gateway

Build with `--features gateway`, then:

```bash
ce-storage gateway --bind 127.0.0.1:9000                  # open (local/trusted)
ce-storage gateway --bind 0.0.0.0:9000 --require-cap       # enforce ce-cap links
```

Existing S3 clients work against the core verbs by pointing at the endpoint:

```bash
aws s3 cp ./bigfile s3://my-bucket/bigfile --endpoint-url http://127.0.0.1:9000
aws s3 ls s3://my-bucket/ --endpoint-url http://127.0.0.1:9000
aws s3 cp s3://my-bucket/bigfile ./out --endpoint-url http://127.0.0.1:9000
```

Implemented: `PutObject` (incl. `x-amz-meta-*`, caching headers, conditional `If-*`, and
`x-amz-copy-source` CopyObject), `GetObject` (incl. `Range` → 206, conditional → 304, `?versionId=`),
`HeadObject`, `DeleteObject` (incl. `?versionId=`), bulk `DeleteObjects` (`POST /{bucket}?delete`),
multipart upload — `CreateMultipartUpload` (`POST ?uploads`), `UploadPart` (`PUT ?partNumber&uploadId`),
`CompleteMultipartUpload` (`POST ?uploadId=` with an XML part list) — `ListObjectsV2` (XML),
`CreateBucket`, `ListBuckets`.

**Authorization.** By default the gateway is **open** (single-owner, local/trusted use), so `aws s3`
works with no signing. Pass `--require-cap` (or `Gateway::with_auth`) to **enforce `ce-cap`
capability links** on every object request: the caller supplies a token via the `X-Ce-Cap` header
(or `?ce-cap=`) and its node id via `X-Ce-Requester`; each handler runs `caps::verify_link` for the
request's ability/bucket/key before doing any work, returning `403 AccessDenied` on failure. This is
the presigned-equivalent enforcement point. AWS SigV4 request signing is **not** implemented — the
`ce-cap` link is the auth mechanism. A `DefaultBodyLimit` (default 256 MiB, tunable with
`--max-body`) rejects an oversize PUT with `413` before buffering the whole body.

## Library API

```rust
use ce_storage::store::Store;
use ce_storage::index::default_index_path;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut store = Store::open(default_index_path())?;
    store.make_bucket("my-bucket")?;

    let meta = store
        .put_object("my-bucket", "hello.txt", b"hello world", "text/plain")
        .await?;
    println!("stored at CID {}", meta.cid);

    let got = store.get_object("my-bucket", "hello.txt").await?;
    assert_eq!(got.bytes, b"hello world");

    // ranged read — only the covering chunks are fetched
    let part = store.get_object_range("my-bucket", "hello.txt", "bytes=0-4").await?;
    assert_eq!(part.bytes, b"hello");
    Ok(())
}
```

A runnable end-to-end **presign → verify** demo (pure crypto, no node) lives in
[`examples/presign_verify.rs`](examples/presign_verify.rs):

```bash
cargo run --example presign_verify
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the object model, concurrency model, and the
deferred-features rationale, and [CHANGELOG.md](CHANGELOG.md) for the release history.

## Durability handoff to ce-pin

Binding `key -> CID` does not by itself replicate the bytes off the owning node. For
content-availability across the mesh, hand the CID (`Store::pin_hint(bucket, key)`) to `ce-pin`,
which pins it across N hosts with payments and proof-of-retrievability. ce-storage owns the
**namespace + S3 verbs**; ce-pin owns **replication + availability**. This is the CE composition
principle: each app does one thing over shared primitives.

## Layout

```
src/
├── lib.rs        crate root + module docs
├── index.rs      bucket index: bucket -> { key -> versioned entries }, sorted, JSON-persisted;
│                 ListObjectsV2 + versioning + lifecycle logic
├── range.rs      pure ranged-read math: parse Range, compute covering chunks, slice
├── caps.rs       presigned-equivalent links: mint/verify a ce-cap chain scoped to bucket/prefix
├── lock.rs       cross-process advisory file lock guarding index mutations
├── seal.rs       sealed (client-side encrypted) objects — encrypt-then-MAC over SHA-256 primitives
├── multipart.rs  multipart/resumable upload: in-flight state + content-addressed part assembly
├── store.rs      Store — the S3-verb library API over ce-rs + the index
├── gateway.rs    (feature "gateway") S3-subset HTTP server with optional ce-cap enforcement
└── main.rs       ce-storage CLI
tests/
├── edge_cases.rs          failure-mode + boundary coverage for the pure library API
├── prop_storage.rs        proptest invariants (ranged reads, listing, scope, serde, lifecycle)
├── concurrency.rs         lost-update tests for the cross-process index lock
├── live.rs                live round trips vs an ephemeral node (objects, versioning, lifecycle, caps)
├── live_multipart_seal.rs live multipart upload + sealed-object round trips
├── gateway_features.rs    (feature "gateway") metadata/conditional/versioning/copy/bulk/413/auth
├── gateway_live.rs        (feature "gateway") gateway over an ephemeral node
└── integration.rs         #[ignore] opt-in round trip against the operator's :8844 node
```

## Tests

```bash
cargo test                                   # unit + property + concurrency + live (auto-skips
                                             #   the live tests if the release `ce` binary is absent)
cargo test --features gateway                # also runs the gateway feature/live tests
cargo test -- --ignored --nocapture          # opt-in round trip against your :8844 node
```

The live tests stand up a fresh **ephemeral** node per test (never your :8844 node) and skip
gracefully — logging why — when the release `ce` binary at `../.cargo-shared/release/ce` is not
built, so the suite is green on a machine that cannot run a node and meaningful where one exists.
Set `CE_NO_LIVE=1` to skip them explicitly.

## License

MIT. Author: Leif Rydenfalk <ledamecrydenfalk@gmail.com>.
