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
        /// Content type (default: application/octet-stream).
        #[arg(long)]
        content_type: Option<String>,
    },
    /// Get bucket/key to a local file (or stdout if no out path), optionally a byte range.
    Get {
        /// Source `bucket/key`.
        target: String,
        /// Output file (omit to write to stdout).
        out: Option<PathBuf>,
        /// HTTP-style byte range, e.g. "bytes=0-1023".
        #[arg(long)]
        range: Option<String>,
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
    /// Run the S3-subset HTTP gateway (requires the `gateway` build feature).
    #[cfg(feature = "gateway")]
    Gateway {
        /// Address to bind, e.g. 127.0.0.1:9000.
        #[arg(long, default_value = "127.0.0.1:9000")]
        bind: String,
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
                            println!("{:>12}  {}  {}", meta.size, &meta.etag[..meta.etag.len().min(16)], k);
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
        } => {
            let (bucket, key) = split_target(&target, true)?;
            let bytes = std::fs::read(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let ct = content_type.unwrap_or_else(|| guess_content_type(&file));
            let mut store = Store::open(index_path)?;
            let meta = store.put_object(&bucket, &key, &bytes, &ct).await?;
            println!("put {bucket}/{key}  cid={}  size={}", meta.cid, meta.size);
        }
        Cmd::Get { target, out, range } => {
            let (bucket, key) = split_target(&target, true)?;
            let store = Store::open(index_path)?;
            let res = match &range {
                Some(r) => store.get_object_range(&bucket, &key, r).await?,
                None => store.get_object(&bucket, &key).await?,
            };
            match out {
                Some(path) => {
                    std::fs::write(&path, &res.bytes)
                        .with_context(|| format!("writing {}", path.display()))?;
                    println!("got {bucket}/{key} -> {} ({} bytes)", path.display(), res.bytes.len());
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
            let owner = ce_identity::Identity::load_or_generate(&dir)
                .context("loading owner identity")?;
            let scope = Scope { bucket, prefix };
            let ability = if write { caps::ABILITY_WRITE } else { caps::ABILITY_READ };
            let not_after = if expires_in == 0 { 0 } else { now() + expires_in };
            let nonce = now(); // unique-enough per mint; revoke by (issuer, nonce) on-chain later
            let token = caps::mint_link(&owner, owner.node_id(), ability, &scope, not_after, nonce)?;
            println!("{token}");
            eprintln!(
                "link: {ability} on {}/{}  expires_at={}  (present this token to a serving node)",
                scope_for_log(&token),
                "",
                not_after
            );
        }
        Cmd::Inspect { token } => {
            let (abilities, scope) = caps::inspect_link(&token)?;
            println!("abilities: {}", abilities.join(", "));
            println!("bucket:    {}", scope.bucket);
            println!("prefix:    {}", scope.prefix);
        }
        #[cfg(feature = "gateway")]
        Cmd::Gateway { bind } => {
            use ce_storage::gateway::Gateway;
            let store = Store::open(index_path)?;
            let app = Gateway::new(store).router();
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
