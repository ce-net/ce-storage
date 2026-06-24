# ce-storage architecture

This document explains how ce-storage is built, the single-writer concurrency model, the on-disk
formats, and — deliberately — what is **deferred** to sibling apps rather than faked here. Read the
module rustdoc (`cargo doc --open`) for the per-function contracts; this is the bird's-eye view.

## Position in CE

CE is **primitives only**: identity, the mesh transport, content-addressed blobs, the ledger, and
the `ce-cap` capability verifier. ce-storage is an **app** that composes those primitives into an
S3/GCS-shaped object store. It adds **no node endpoints** and stores **no ip:port**: every byte goes
through the `ce-rs` SDK's blob API, and authorization is a signed, attenuating `ce-cap` chain.

```
        ce-storage (this app)
        ┌───────────────────────────────────────────────┐
 CLI ──▶│  Store  ──▶  Index (buckets/keys/versions)     │
 gw  ──▶│   │           Multipart state                  │
        │   │                                            │
        │   ▼                                            │
        │  ce-rs SDK  ──▶  node /blobs /objects (CIDs)   │
        │  ce-cap     ──▶  offline capability verify     │
        └───────────────────────────────────────────────┘
```

## Object model: content-addressed blobs

`ce-rs::put_object` splits bytes into 1 MiB chunks, stores each chunk content-addressed, and returns
a **manifest CID** (an ordered list of chunk CIDs + `total_size`). `get_object` resolves the
manifest, fetches every chunk, **re-verifies each chunk against its hash**, and reassembles. The
consequences ce-storage leans on:

- **The ETag is the CID.** Equal ETag ⇒ identical bytes. This makes ETags perfect cache keys and the
  version id a perfect, collision-resistant generation id.
- **Dedup is free.** Re-uploading identical bytes yields the same CID and re-stores nothing.
- **CopyObject is free.** It binds a second key to the same CID — no bytes move.
- **Ranged reads are cheap.** `src/range.rs` maps a byte window onto the covering chunk indices, so
  only those chunks are fetched (the manifest path). For a tiny inline object with no parseable
  manifest, the whole (already size-bounded) object is fetched once and sliced.

## The bucket index (`src/index.rs`)

The index is the durable map that turns the flat blob layer into named buckets/keys. Shape:

```
Index { schema, buckets: { name -> Bucket } }
Bucket { created, versioning, lifecycle[], objects: { key -> ObjectEntry } }
ObjectEntry { versions: [ ObjectVersion { meta, is_delete_marker } ] }   // newest last
ObjectMeta { cid, size, etag, content_type, last_modified, version_id, metadata, headers }
```

- A `BTreeMap` keeps keys sorted, which is exactly what `ListObjectsV2` needs: lexicographic order,
  prefix ranges (the listing seeks with `BTreeMap::range` rather than scanning from the start),
  delimiter rollups, and continuation tokens that are just "start after this key".
- **Versioning**: on a versioned bucket a put appends an `ObjectVersion` and a delete appends a
  **delete marker** (prior versions stay retrievable by `version_id`); on an unversioned bucket a put
  overwrites in place and a delete removes the key.
- **Lifecycle**: per-bucket TTL rules (prefix + `expiration_secs`); `expired_keys` is pure, and the
  `Store::sweep_*` family deletes expired objects under the lock.

### On-disk format and migration

The index is one JSON file (`<data-dir>/storage/buckets.json` by default) carrying a
`SCHEMA_VERSION`. `Index::load` reads an absent file as empty, reads older/defaulted shapes
transparently (new fields `#[serde(default)]`), and **rejects a strictly newer schema** with a clear
error rather than silently misinterpreting it. Sizes are `u64` (not JSON-`f64`), so objects larger
than 2^53 bytes round-trip losslessly — there is a property test for this.

## Concurrency model: single writer, lock-serialised

ce-storage is a **single-writer** store: the owning node is the writer. The hazard is *concurrent
processes* (a CLI invocation while the gateway runs) racing `load → mutate → save` and losing an
update. Two mechanisms close it:

1. **Atomic persistence.** Every save writes a unique temp file, `fsync`s it, then `rename`s it into
   place. A crash mid-write leaves either the old or the new file, never a half-written one.
2. **A cross-process advisory file lock** (`src/lock.rs`). Every mutating `Store` op acquires
   `<index>.lock` (atomic `create_new`, with stale-lock reclaim for a crashed holder), **reloads the
   index from disk under the lock**, mutates the freshest state, saves, and releases. A second
   process blocks rather than clobbering. The gateway additionally serialises in-process behind a
   `tokio::Mutex`. `tests/concurrency.rs` drives many `Store` handles at one file and asserts no
   lost update.

Multipart state (`<index>.multipart.json`) uses the same lock + atomic-write discipline.

## Multipart / resumable upload (`src/multipart.rs`)

Because an object is just an ordered chunk list, a multipart **part** is itself a run of chunks, and
`CompleteMultipartUpload` is **concatenating the parts' chunk lists** into one combined manifest —
**no bytes are copied**. The S3 uniform-part-size rule (every part except the last must be the same
size) maps to "every non-final part must be a whole multiple of the 1 MiB part chunk", which keeps
the assembled manifest a clean fixed-`chunk_size` manifest that the ranged-read math can index. The
in-flight count and per-part number are bounded (`MAX_INFLIGHT_UPLOADS`, `MAX_PARTS`). A live test
asserts the assembled object's CID equals a single-shot put of the same bytes.

## Sealed objects (`src/seal.rs`): the SSE-C analogue

A *sealed* object is encrypted **before** it leaves the client, so the blob store (and any
replicating host) only ever sees ciphertext. The construction is a self-contained authenticated
cipher built from the `sha2` primitives the crate already depends on (no new crypto crate):

- HKDF-style subkey derivation (enc + MAC) from the user key + a per-seal random salt.
- A SHA-256 counter-mode keystream XORed over the plaintext.
- **Encrypt-then-MAC** with HMAC-SHA256; `unseal` verifies the tag in **constant time before
  decrypting**, so a wrong key or tampered/truncated record is rejected, never returned as garbage.

This is documented as a real, tested construction — *not* a claim of AES-GCM/FIPS compliance. It
provides confidentiality + integrity against a host that can read every stored byte, which is exactly
the threat SSE addresses. Key management (who holds the key, rotation) is the caller's; ce-storage
never persists the key. This is the **SSE-C** (customer-key) analogue; managed server-side keys
(SSE-S3/SSE-KMS) are deferred.

## Authorization: presigned-equivalent `ce-cap` links (`src/caps.rs`)

An S3 presigned URL is a bearer token granting temporary scoped access. The CE equivalent is a
signed, attenuating `ce-cap` chain whose abilities are `storage:read` / `storage:write` (opaque app
strings), whose resource is the owning node, and whose caveats carry the expiry (`not_after`) and the
`bucket/prefix` scope (`path_prefix`). Any honoring node verifies it **offline in microseconds** via
`ce_cap::authorize` — no policy server, no shared secret. The holder can attenuate (narrow the
prefix) and re-delegate freely; revocation is on-chain (`RevokeCapability`) plus expiry.

The app-level scope check (`scope_allows`) is **boundary-aware**: a scope `photos` covers `photos`
and `photos/a` but **not** `photos-secret/x` — it matches on `/`-delimited path segments, not raw
`starts_with`, so a scope never leaks into a sibling namespace. The gateway's `Auth` wires
`verify_link` into every object handler (403 on failure) and polls the on-chain revocation set so
revoked links are rejected.

## What is deferred (and why it is honest, not faked)

| Concern | Status | Where it lives |
|---|---|---|
| Multi-host durability / pinning, proof-of-retrievability | **deferred** | the `ce-pin` app; `Store::pin_hint` hands it the CID. ce-storage never silently pins. |
| Managed server-side keys (SSE-S3 / SSE-KMS) | **deferred** | sealed objects are client-key only (the SSE-C analogue). |
| AWS SigV4 request signing | **deferred** | `ce-cap` links are the auth mechanism. |
| Storage-class transitions (tiering) | **deferred** | only expiration is implemented, not tiering. |
| Streaming request/response bodies | **deferred** | objects are bounded by `max_object_size` and buffered; the gateway's `DefaultBodyLimit` rejects oversize PUTs with 413. |

The single-writer design means ce-storage is the namespace + S3-verb layer; replication/availability
is `ce-pin`'s job. This is the CE composition principle: each app does one thing over shared
primitives.

## Operational limits

- Default max object size: 5 GiB (`Store::with_max_object_size` to change). Oversize is rejected
  before the bytes are buffered.
- Default gateway body limit: 256 MiB (`--max-body`).
- User metadata: ≤ 64 entries, ≤ 2048 bytes each.
- Lifecycle rules: ≤ 64 per bucket. Multipart: ≤ 10,000 parts, ≤ 4096 in-flight uploads.
- Object keys: ≤ 1024 bytes, non-empty, no NUL. Bucket names: 3–63 chars, S3 DNS subset, no slash.
