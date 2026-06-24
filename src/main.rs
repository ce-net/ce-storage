//! `ce-storage` — CLI for the S3/GCS-compatible object store over CE blobs.
//!
//! Verbs mirror `aws s3`: `mb` (make bucket), `rb` (remove bucket), `ls` (list buckets/objects),
//! `put`, `get`, `rm`, `cp`, `head`, plus `presign` (mint a `ce-cap` access link) and, when built
//! with `--features gateway`, `gateway` (run the S3-subset HTTP server).

use anyhow::{Context, Result};
use ce_storage::caps::{self, Scope};
use ce_storage::index::default_index_path;
use ce_storage::store::Store;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(
    name = "ce-storage",
    about = "S3/GCS-compatible object store over CE content-addressed blobs",
    version
)]
struct Cli {
    /// Override the bucket-index path (default: <CE data dir>/storage/buckets.json).
    #[arg(long, global = true)]
    index: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Make a bucket.
    Mb {
        /// Bucket name.
        bucket: String,
    },
    /// Remove a bucket (use --force for a non-empty bucket).
    Rb {
        /// Bucket name.
        bucket: String,
        /// Remove even if the bucket is non-empty.
        #[arg(long)]
        force: bool,
    },
    /// List buckets, or objects under a bucket/prefix when a target is given.
    Ls {
        /// Optional `bucket` or `bucket/prefix` to list objects under.
        target: Option<String>,
        /// Delimiter for directory-style rollups (e.g. "/").
        #[arg(long)]
        delimiter: Option<String>,
        /// Max keys per page.
        #[arg(long, default_value_t = 1000)]
        max_keys: usize,
    },
    /// Put a local file at bucket/key.
    Put {
        /// Destination `bucket/key`.
        target: String,
        /// Local file to upload.
        file: PathBuf,
        /// Content type (default: guessed from the extension).
        #[arg(long)]
        content_type: Option<String>,
        /// User metadata as `key=value` (repeatable; stored as x-amz-meta-*).
        #[arg(long = "meta", value_name = "KEY=VALUE")]
        meta: Vec<String>,
        /// Cache-Control header to record and serve.
        #[arg(long)]
        cache_control: Option<String>,
        /// Seal (client-side encrypt) the object under this key before storing. The host never sees
        /// plaintext; the same key is required to `get` it back.
        #[arg(long)]
        seal_key: Option<String>,
    },
    /// Get bucket/key to a local file (or stdout if no out path), optionally a byte range/version.
    Get {
        /// Source `bucket/key`.
        target: String,
        /// Output file (omit to write to stdout).
        out: Option<PathBuf>,
        /// HTTP-style byte range, e.g. "bytes=0-1023".
        #[arg(long)]
        range: Option<String>,
        /// Fetch a specific version id (CID) instead of the current version.
        #[arg(long)]
        version_id: Option<String>,
        /// Unseal (decrypt) the object under this key (required if it was `put` with --seal-key).
        #[arg(long)]
        seal_key: Option<String>,
    },
    /// Remove an object at bucket/key.
    Rm {
        /// `bucket/key` to delete.
        target: String,
    },
    /// Copy src bucket/key to dst bucket/key (free — shares the content address).
    Cp {
        /// Source `bucket/key`.
        src: String,
        /// Destination `bucket/key`.
        dst: String,
    },
    /// Show object metadata (CID/ETag, size, content type) at bucket/key.
    Head {
        /// `bucket/key`.
        target: String,
    },
    /// Mint a presigned-equivalent access link (a ce-cap chain) scoped to a bucket/prefix.
    Presign {
        /// `bucket` or `bucket/prefix` to scope the link to.
        target: String,
        /// Grant write (and delete) instead of read-only.
        #[arg(long)]
        write: bool,
        /// Expiry in seconds from now (0 = never).
        #[arg(long, default_value_t = 3600)]
        expires_in: u64,
        /// CE data dir holding the owner identity (default: CE default data dir).
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Inspect a presigned access link token (abilities + scope).
    Inspect {
        /// The link token (hex).
        token: String,
    },
    /// Enable or disable object versioning on a bucket.
    Versioning {
        /// Bucket name.
        bucket: String,
        /// Enable versioning (default); pass --disable to suspend it.
        #[arg(long)]
        disable: bool,
    },
    /// List the stored versions of an object (newest first).
    Versions {
        /// `bucket/key`.
        target: String,
    },
    /// Manage lifecycle (TTL/expiration) rules on a bucket.
    Lifecycle {
        #[command(subcommand)]
        cmd: LifecycleCmd,
    },
    /// Delete objects whose lifecycle TTL has elapsed (one bucket, or all with no argument).
    Sweep {
        /// Bucket to sweep; omit to sweep every bucket.
        bucket: Option<String>,
        /// Report what would be deleted without deleting anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Multipart / resumable upload of a (possibly large) local file in fixed-size parts.
    Multipart {
        #[command(subcommand)]
        cmd: MultipartCmd,
    },
    /// Run the S3-subset HTTP gateway (requires the `gateway` build feature).
    #[cfg(feature = "gateway")]
    Gateway {
        /// Address to bind, e.g. 127.0.0.1:9000.
        #[arg(long, default_value = "127.0.0.1:9000")]
        bind: String,
        /// Enforce ce-cap capability links on object requests (presigned-equivalent auth). Without
        /// this the gateway is open (single-owner, local/trusted use).
        #[arg(long)]
        require_cap: bool,
        /// CE data dir holding the owner identity used as the capability trust root (with
        /// --require-cap).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Max request body in bytes before a 413 (default 256 MiB).
        #[arg(long)]
        max_body: Option<usize>,
    },
}

/// Multipart upload subcommands. `upload` is a convenience that runs the full
/// create→upload-parts→complete flow for one local file; the lower-level verbs let a caller resume.
#[derive(Subcommand)]
enum MultipartCmd {
    /// Upload a local file as a multipart object in `--part-size`-byte parts (full flow).
    Upload {
        /// Destination `bucket/key`.
        target: String,
        /// Local file to upload.
        file: PathBuf,
        /// Part size in bytes (default 8 MiB; each non-final part is rounded to the 1 MiB chunk).
        #[arg(long, default_value_t = 8 * 1024 * 1024)]
        part_size: usize,
        /// Content type (default: guessed from the extension).
        #[arg(long)]
        content_type: Option<String>,
    },
    /// Begin an upload, printing its id.
    Create {
        /// Destination `bucket/key`.
        target: String,
        /// Content type for the assembled object.
        #[arg(long)]
        content_type: Option<String>,
    },
    /// List in-flight uploads (optionally for one bucket).
    List {
        /// Restrict to this bucket.
        bucket: Option<String>,
    },
    /// List the recorded parts of an in-flight upload.
    Parts {
        /// Upload id.
        upload_id: String,
    },
    /// Abort an in-flight upload, discarding its parts.
    Abort {
        /// Upload id.
        upload_id: String,
    },
}

/// Lifecycle (TTL/expiration) rule management subcommands.
#[derive(Subcommand)]
enum LifecycleCmd {
    /// Replace the bucket's lifecycle rules with a single prefix+TTL rule (or clear with --clear).
    Set {
        /// Bucket name.
        bucket: String,
        /// Key prefix the rule applies to (empty = whole bucket).
        #[arg(long, default_value = "")]
        prefix: String,
        /// Expire matching objects this many seconds after they were written.
        #[arg(long)]
        expire_secs: Option<u64>,
        /// Remove all lifecycle rules instead of setting one.
        #[arg(long)]
        clear: bool,
    },
    /// Show the bucket's current lifecycle rules.
    Get {
        /// Bucket name.
        bucket: String,
    },
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Split a `bucket/key` (or `bucket/prefix`) argument. With `require_key=false`, an argument with no
/// slash is treated as a bare bucket and the second element is empty.
fn split_target(t: &str, require_key: bool) -> Result<(String, String)> {
    match t.split_once('/') {
        Some((b, k)) => Ok((b.to_string(), k.to_string())),
        None => {
            if require_key {
                anyhow::bail!("expected bucket/key, got '{t}'");
            }
            Ok((t.to_string(), String::new()))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ce_storage=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let index_path = cli.index.unwrap_or_else(default_index_path);

    match cli.cmd {
        Cmd::Mb { bucket } => {
            let mut store = Store::open(index_path)?;
            store.make_bucket(&bucket)?;
            println!("made bucket: {bucket}");
        }
        Cmd::Rb { bucket, force } => {
            let mut store = Store::open(index_path)?;
            store.remove_bucket(&bucket, force)?;
            println!("removed bucket: {bucket}");
        }
        Cmd::Ls {
            target,
            delimiter,
            max_keys,
        } => {
            let store = Store::open(index_path)?;
            match target {
                None => {
                    for b in store.list_buckets() {
                        println!("{b}");
                    }
                }
                Some(t) => {
                    let (bucket, prefix) = split_target(&t, false)?;
                    let mut cont: Option<String> = None;
                    loop {
                        let page = store.list_objects(
                            &bucket,
                            &prefix,
                            delimiter.as_deref(),
                            cont.as_deref(),
                            max_keys,
                        )?;
                        for cp in &page.common_prefixes {
                            println!("PRE {cp}");
                        }
                        for (k, meta) in &page.keys {
                            println!(
                                "{:>12}  {}  {}",
                                meta.size,
                                &meta.etag[..meta.etag.len().min(16)],
                                k
                            );
                        }
                        match page.next_continuation {
                            Some(tok) if page.is_truncated => cont = Some(tok),
                            _ => break,
                        }
                    }
                }
            }
        }
        Cmd::Put {
            target,
            file,
            content_type,
            meta,
            cache_control,
            seal_key,
        } => {
            let (bucket, key) = split_target(&target, true)?;
            let bytes =
                std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let ct = content_type.unwrap_or_else(|| guess_content_type(&file));
            let metadata = parse_meta_pairs(&meta)?;
            let opts = ce_storage::store::PutOptions {
                content_type: ct,
                metadata,
                cache_control,
                ..Default::default()
            };
            let mut store = Store::open(index_path)?;
            let meta = match &seal_key {
                Some(sk) => {
                    store
                        .put_object_sealed(&bucket, &key, &bytes, sk.as_bytes(), &opts)
                        .await?
                }
                None => store.put_object_opts(&bucket, &key, &bytes, &opts).await?,
            };
            let sealed = if seal_key.is_some() { " (sealed)" } else { "" };
            println!(
                "put {bucket}/{key}  cid={}  size={}{sealed}",
                meta.cid, meta.size
            );
        }
        Cmd::Get {
            target,
            out,
            range,
            version_id,
            seal_key,
        } => {
            let (bucket, key) = split_target(&target, true)?;
            let store = Store::open(index_path)?;
            let res = match (&range, &seal_key) {
                (Some(_), Some(_)) => {
                    anyhow::bail!(
                        "--range cannot be combined with --seal-key (decrypt is whole-object)"
                    )
                }
                (Some(r), None) => {
                    store
                        .get_object_range_opts(&bucket, &key, r, version_id.as_deref())
                        .await?
                }
                (None, Some(sk)) => {
                    store
                        .get_object_sealed(&bucket, &key, sk.as_bytes(), version_id.as_deref())
                        .await?
                }
                (None, None) => {
                    store
                        .get_object_opts(
                            &bucket,
                            &key,
                            version_id.as_deref(),
                            &ce_storage::store::Preconditions::default(),
                        )
                        .await?
                }
            };
            match out {
                Some(path) => {
                    std::fs::write(&path, &res.bytes)
                        .with_context(|| format!("writing {}", path.display()))?;
                    println!(
                        "got {bucket}/{key} -> {} ({} bytes)",
                        path.display(),
                        res.bytes.len()
                    );
                }
                None => {
                    use std::io::Write;
                    std::io::stdout().write_all(&res.bytes)?;
                }
            }
        }
        Cmd::Rm { target } => {
            let (bucket, key) = split_target(&target, true)?;
            let mut store = Store::open(index_path)?;
            store.delete_object(&bucket, &key)?;
            println!("removed {bucket}/{key}");
        }
        Cmd::Cp { src, dst } => {
            let (sb, sk) = split_target(&src, true)?;
            let (db, dk) = split_target(&dst, true)?;
            let mut store = Store::open(index_path)?;
            store.copy_object(&sb, &sk, &db, &dk)?;
            println!("copied {sb}/{sk} -> {db}/{dk} (shared content address)");
        }
        Cmd::Head { target } => {
            let (bucket, key) = split_target(&target, true)?;
            let store = Store::open(index_path)?;
            let meta = store.head_object(&bucket, &key)?;
            println!("cid:          {}", meta.cid);
            println!("etag:         {}", meta.etag);
            println!("size:         {}", meta.size);
            println!("content-type: {}", meta.content_type);
            println!("modified:     {}", meta.last_modified);
        }
        Cmd::Presign {
            target,
            write,
            expires_in,
            data_dir,
        } => {
            let (bucket, prefix) = split_target(&target, false)?;
            let dir = data_dir.unwrap_or_else(default_data_dir);
            let owner =
                ce_identity::Identity::load_or_generate(&dir).context("loading owner identity")?;
            let scope = Scope { bucket, prefix };
            let ability = if write {
                caps::ABILITY_WRITE
            } else {
                caps::ABILITY_READ
            };
            let not_after = if expires_in == 0 {
                0
            } else {
                now() + expires_in
            };
            // Nonce must be unique per mint so each link is independently revocable by
            // (issuer, nonce). Seconds collide for two presigns in the same second; use nanoseconds
            // (62 bits of entropy below the second boundary), which never collides in practice.
            let nonce = unique_nonce();
            let token =
                caps::mint_link(&owner, owner.node_id(), ability, &scope, not_after, nonce)?;
            println!("{token}");
            let expiry = if not_after == 0 {
                "never".to_string()
            } else {
                not_after.to_string()
            };
            eprintln!(
                "link: {ability} on {}  expires_at={expiry}  (present this token to a serving node)",
                scope_for_log(&token),
            );
        }
        Cmd::Inspect { token } => {
            let (abilities, scope) = caps::inspect_link(&token)?;
            println!("abilities: {}", abilities.join(", "));
            println!("bucket:    {}", scope.bucket);
            println!("prefix:    {}", scope.prefix);
        }
        Cmd::Versioning { bucket, disable } => {
            let mut store = Store::open(index_path)?;
            store.set_versioning(&bucket, !disable)?;
            println!(
                "versioning {} on bucket: {bucket}",
                if disable { "suspended" } else { "enabled" }
            );
        }
        Cmd::Versions { target } => {
            let (bucket, key) = split_target(&target, true)?;
            let store = Store::open(index_path)?;
            let versions = store.list_versions(&bucket, &key)?;
            if versions.is_empty() {
                println!("(no versions)");
            }
            for v in versions {
                println!(
                    "{:>12}  {}  modified={}",
                    v.size,
                    &v.version_id[..v.version_id.len().min(16)],
                    v.last_modified
                );
            }
        }
        Cmd::Lifecycle { cmd } => match cmd {
            LifecycleCmd::Set {
                bucket,
                prefix,
                expire_secs,
                clear,
            } => {
                let mut store = Store::open(index_path)?;
                if clear {
                    store.set_lifecycle(&bucket, Vec::new())?;
                    println!("cleared lifecycle rules on bucket: {bucket}");
                } else {
                    let secs = expire_secs.context(
                        "lifecycle set requires --expire-secs <N> (or --clear to remove rules)",
                    )?;
                    let rule = ce_storage::index::LifecycleRule {
                        prefix: prefix.clone(),
                        expiration_secs: secs,
                    };
                    store.set_lifecycle(&bucket, vec![rule])?;
                    let scope = if prefix.is_empty() {
                        "<all>".to_string()
                    } else {
                        prefix
                    };
                    println!("set lifecycle on {bucket}: prefix={scope} expire_secs={secs}");
                }
            }
            LifecycleCmd::Get { bucket } => {
                let store = Store::open(index_path)?;
                let rules = store.lifecycle(&bucket)?;
                if rules.is_empty() {
                    println!("(no lifecycle rules)");
                }
                for r in rules {
                    let scope = if r.prefix.is_empty() {
                        "<all>"
                    } else {
                        &r.prefix
                    };
                    println!("prefix={scope}  expire_secs={}", r.expiration_secs);
                }
            }
        },
        Cmd::Sweep { bucket, dry_run } => {
            let mut store = Store::open(index_path)?;
            match bucket {
                Some(b) => {
                    if dry_run {
                        let keys = store.expired_keys(&b)?;
                        println!("{} object(s) would expire in {b}", keys.len());
                        for k in keys {
                            println!("  {b}/{k}");
                        }
                    } else {
                        let deleted = store.sweep_expired(&b)?;
                        println!("expired {} object(s) in {b}", deleted.len());
                        for k in deleted {
                            println!("  {b}/{k}");
                        }
                    }
                }
                None => {
                    if dry_run {
                        let mut total = 0usize;
                        for b in store.list_buckets() {
                            let keys = store.expired_keys(&b)?;
                            total += keys.len();
                            for k in keys {
                                println!("  {b}/{k}");
                            }
                        }
                        println!("{total} object(s) would expire across all buckets");
                    } else {
                        let report = store.sweep_all()?;
                        let total: usize = report.values().map(|v| v.len()).sum();
                        for (b, keys) in &report {
                            for k in keys {
                                println!("  {b}/{k}");
                            }
                        }
                        println!("expired {total} object(s) across all buckets");
                    }
                }
            }
        }
        Cmd::Multipart { cmd } => match cmd {
            MultipartCmd::Upload {
                target,
                file,
                part_size,
                content_type,
            } => {
                let (bucket, key) = split_target(&target, true)?;
                if part_size == 0 {
                    anyhow::bail!("--part-size must be > 0");
                }
                let bytes =
                    std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
                let ct = content_type.unwrap_or_else(|| guess_content_type(&file));
                let opts = ce_storage::store::PutOptions {
                    content_type: ct,
                    ..Default::default()
                };
                let mut store = Store::open(index_path)?;
                let upload_id = store.create_multipart_upload(&bucket, &key, &opts).await?;
                println!("created upload {upload_id}");
                // Split into parts. Every non-final part must be a multiple of the 1 MiB chunk; round
                // the requested part size down to a whole MiB so the uniform-part rule holds.
                let chunk = 1024 * 1024usize;
                let ps = (part_size / chunk).max(1) * chunk;
                let mut parts: Vec<(u32, String)> = Vec::new();
                let mut n: u32 = 0;
                for slice in bytes.chunks(ps) {
                    n += 1;
                    let etag = store.upload_part(&upload_id, n, slice).await?;
                    println!("  uploaded part {n} ({} bytes) etag={etag}", slice.len());
                    parts.push((n, etag));
                }
                if parts.is_empty() {
                    // Empty file: a single empty part is not allowed; abort and store an empty object.
                    store.abort_multipart_upload(&upload_id)?;
                    let meta = store.put_object_opts(&bucket, &key, &[], &opts).await?;
                    println!("stored empty object {bucket}/{key} cid={}", meta.cid);
                } else {
                    let meta = store.complete_multipart_upload(&upload_id, &parts).await?;
                    println!(
                        "completed {bucket}/{key}  cid={}  size={}  parts={}",
                        meta.cid,
                        meta.size,
                        parts.len()
                    );
                }
            }
            MultipartCmd::Create {
                target,
                content_type,
            } => {
                let (bucket, key) = split_target(&target, true)?;
                let opts = ce_storage::store::PutOptions {
                    content_type: content_type.unwrap_or_default(),
                    ..Default::default()
                };
                let mut store = Store::open(index_path)?;
                let id = store.create_multipart_upload(&bucket, &key, &opts).await?;
                println!("{id}");
            }
            MultipartCmd::List { bucket } => {
                let store = Store::open(index_path)?;
                let uploads = store.list_multipart_uploads(bucket.as_deref())?;
                if uploads.is_empty() {
                    println!("(no in-flight uploads)");
                }
                for (id, up) in uploads {
                    println!(
                        "{id}  {}/{}  parts={}  created={}",
                        up.bucket,
                        up.key,
                        up.parts.len(),
                        up.created
                    );
                }
            }
            MultipartCmd::Parts { upload_id } => {
                let store = Store::open(index_path)?;
                let parts = store.list_parts(&upload_id)?;
                if parts.is_empty() {
                    println!("(no parts)");
                }
                for p in parts {
                    println!(
                        "part {:>5}  {:>12} bytes  etag={}",
                        p.part_number, p.size, p.etag
                    );
                }
            }
            MultipartCmd::Abort { upload_id } => {
                let mut store = Store::open(index_path)?;
                store.abort_multipart_upload(&upload_id)?;
                println!("aborted upload {upload_id}");
            }
        },
        #[cfg(feature = "gateway")]
        Cmd::Gateway {
            bind,
            require_cap,
            data_dir,
            max_body,
        } => {
            use ce_storage::gateway::{Auth, Gateway};
            let store = Store::open(index_path)?;
            let mut gw = Gateway::new(store);
            if let Some(mb) = max_body {
                gw = gw.with_body_limit(mb);
            }
            if require_cap {
                let dir = data_dir.unwrap_or_else(default_data_dir);
                let owner = ce_identity::Identity::load_or_generate(&dir)
                    .context("loading gateway trust-root identity")?;
                // Best-effort: pull the current on-chain revocation set so revoked links are rejected.
                let revoked = fetch_revoked().await;
                gw = gw.with_auth(Auth::new(owner.node_id()).with_revoked(revoked));
                println!(
                    "ce-cap enforcement ON (root {}); present X-Ce-Cap + X-Ce-Requester",
                    owner.node_id_hex()
                );
            } else {
                println!("ce-cap enforcement OFF (open gateway — local/trusted use only)");
            }
            let app = gw.router();
            let listener = tokio::net::TcpListener::bind(&bind)
                .await
                .with_context(|| format!("binding {bind}"))?;
            println!("ce-storage S3 gateway listening on http://{bind}");
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}

/// Best-effort content type from a file extension.
fn guess_content_type(path: &std::path::Path) -> String {
    match path.extension().and_then(|e| e.to_str()) {
        Some("txt") => "text/plain",
        Some("html") => "text/html",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("pdf") => "application/pdf",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Parse `key=value` CLI metadata pairs into a sorted map. Errors on a missing `=`.
fn parse_meta_pairs(pairs: &[String]) -> Result<std::collections::BTreeMap<String, String>> {
    let mut m = std::collections::BTreeMap::new();
    for p in pairs {
        let (k, v) = p
            .split_once('=')
            .with_context(|| format!("--meta must be key=value, got '{p}'"))?;
        if k.is_empty() {
            anyhow::bail!("--meta key must not be empty: '{p}'");
        }
        m.insert(k.to_string(), v.to_string());
    }
    Ok(m)
}

/// A nonce unique per mint: nanoseconds since the epoch. Two presigns in the same second get
/// distinct nonces (unlike seconds), so each link is independently revocable.
fn unique_nonce() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Best-effort fetch of the on-chain revocation set, mapping `(issuer-hex, nonce)` to
/// `(NodeId, nonce)`. A node that is unreachable yields an empty set (fail-open on fetch, fail-closed
/// on a known revocation) — logged so the operator knows enforcement may be stale.
#[cfg(feature = "gateway")]
async fn fetch_revoked() -> Vec<(ce_identity::NodeId, u64)> {
    let ce = ce_rs::CeClient::local();
    match ce.revoked().await {
        Ok(list) => list
            .into_iter()
            .filter_map(|(issuer, nonce)| caps::parse_node_id(&issuer).ok().map(|id| (id, nonce)))
            .collect(),
        Err(e) => {
            tracing::warn!("could not fetch revocation set ({e}); starting with none");
            Vec::new()
        }
    }
}

fn default_data_dir() -> PathBuf {
    directories::ProjectDirs::from("", "", "ce")
        .map(|p| p.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn scope_for_log(token: &str) -> String {
    caps::inspect_link(token)
        .map(|(_, s)| format!("{}/{}", s.bucket, s.prefix))
        .unwrap_or_default()
}
