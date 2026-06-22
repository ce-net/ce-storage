# ce-storage

**An S3/GCS-compatible object store over CE's content-addressed blobs.**

ce-storage is an **application built on CE primitives** (the SDK tier, alongside `ce-pin`,
`ce-coord`, `swarm`, `rdev`) — not a node feature. It turns CE's flat, content-addressed blob layer
into named **buckets** and **objects** with the familiar S3 verb set, plus presigned-equivalent
access **links** backed by `ce-cap` capabilities.

> Pronounced like the rest of CE ("Sea"). Buckets in, content-addressed objects out, no egress fee.

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
ce-storage gateway --bind 127.0.0.1:9000
```

Existing S3 clients work against the core verbs by pointing at the endpoint:

```bash
aws s3 cp ./bigfile s3://my-bucket/bigfile --endpoint-url http://127.0.0.1:9000
aws s3 ls s3://my-bucket/ --endpoint-url http://127.0.0.1:9000
aws s3 cp s3://my-bucket/bigfile ./out --endpoint-url http://127.0.0.1:9000
```

Implemented (the documented core): `PutObject`, `GetObject` (incl. `Range`), `HeadObject`,
`DeleteObject`, `ListObjectsV2` (XML), `CreateBucket`, `ListBuckets`.

**Honest scope:** the gateway is a single-owner server for local/trusted use — it does **not**
implement AWS SigV4 request signing (front it with a `ce-cap` link check or run it on a trusted
host), and multipart upload / full bucket policy are out of scope for the MVP. The point is that the
bytes and listings are S3-shaped so `aws s3` get/put/list work unmodified.

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

## Durability handoff to ce-pin

Binding `key -> CID` does not by itself replicate the bytes off the owning node. For
content-availability across the mesh, hand the CID (`Store::pin_hint(bucket, key)`) to `ce-pin`,
which pins it across N hosts with payments and proof-of-retrievability. ce-storage owns the
**namespace + S3 verbs**; ce-pin owns **replication + availability**. This is the CE composition
principle: each app does one thing over shared primitives.

## Layout

```
src/
├── lib.rs       crate root + module docs
├── index.rs     bucket index: bucket -> { key -> ObjectMeta }, sorted, JSON-persisted; ListObjectsV2 logic
├── range.rs     pure ranged-read math: parse Range, compute covering chunks, slice
├── caps.rs      presigned-equivalent links: mint/verify a ce-cap chain scoped to bucket/prefix
├── store.rs     Store — the S3-verb library API over ce-rs + the index
├── gateway.rs   (feature "gateway") tiny S3-subset HTTP server
└── main.rs      ce-storage CLI
tests/
└── integration.rs   #[ignore] round trip against a running CE node
```

## Tests

```bash
cargo test                                   # unit tests (no node needed)
cargo test -- --ignored --nocapture          # integration round trip (needs `ce start`)
cargo build --features gateway               # ensure the gateway compiles
```

## License

MIT. Author: Leif Rydenfalk <ledamecrydenfalk@gmail.com>.
