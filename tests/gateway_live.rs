//! Live tests for the optional S3-subset HTTP gateway (feature `gateway`).
//!
//! Drives the gateway's axum router in-process with `tower::ServiceExt::oneshot` against a Store
//! backed by a real ephemeral CE node, asserting the S3 verbs map correctly: CreateBucket,
//! PutObject (with ETag), GetObject (full + Range → 206 + Content-Range), HeadObject, ListObjectsV2
//! (XML), DeleteObject (204), and the not-found paths (404). Compiled only with `--features gateway`.
//!
//! Run with: `cargo test -p ce-storage --features gateway --test gateway_live -- --nocapture`.

#![cfg(feature = "gateway")]

mod harness;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ce_storage::gateway::Gateway;
use ce_storage::store::Store;
use harness::{live_available, Node};
use http_body_util::BodyExt;
use std::path::PathBuf;
use tower::ServiceExt;

fn temp_index(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ce-storage-gw-{}-{}-{tag}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn gateway_s3_verb_roundtrip() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    let node = Node::start(None).await?;
    let index_path = temp_index("verbs");
    let _ = std::fs::remove_file(&index_path);
    let store = Store::with_client(node.client.clone(), index_path.clone())?;
    let gw = Gateway::new(store);

    // CreateBucket: PUT /photos
    let resp = gw
        .clone()
        .router()
        .oneshot(Request::builder().method("PUT").uri("/photos").body(Body::empty())?)
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);

    // Duplicate CreateBucket → 409 Conflict.
    let resp = gw
        .clone()
        .router()
        .oneshot(Request::builder().method("PUT").uri("/photos").body(Body::empty())?)
        .await?;
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // PutObject: PUT /photos/a.txt  (a multi-byte payload)
    let payload = vec![7u8; 1500];
    let resp = gw
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/photos/a.txt")
                .header("content-type", "text/plain")
                .body(Body::from(payload.clone()))?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("etag").is_some(), "PutObject returns an ETag");

    // GetObject (full): GET /photos/a.txt
    let resp = gw
        .clone()
        .router()
        .oneshot(Request::builder().method("GET").uri("/photos/a.txt").body(Body::empty())?)
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    let bytes = resp.into_body().collect().await?.to_bytes();
    assert_eq!(bytes.as_ref(), payload.as_slice());

    // GetObject (Range): GET /photos/a.txt  Range: bytes=0-9 → 206 + Content-Range
    let resp = gw
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/photos/a.txt")
                .header("range", "bytes=0-9")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    let cr = resp.headers().get("content-range").unwrap().to_str()?.to_string();
    assert_eq!(cr, "bytes 0-9/1500");
    let bytes = resp.into_body().collect().await?.to_bytes();
    assert_eq!(bytes.len(), 10);

    // HeadObject: HEAD /photos/a.txt → 200 + Content-Length
    let resp = gw
        .clone()
        .router()
        .oneshot(Request::builder().method("HEAD").uri("/photos/a.txt").body(Body::empty())?)
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("content-length").unwrap(), "1500");

    // ListObjectsV2: GET /photos?list-type=2 → XML containing the key.
    let resp = gw
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/photos?list-type=2&prefix=")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let xml = body_string(resp).await;
    assert!(xml.contains("<Key>a.txt</Key>"), "list XML must contain the key: {xml}");

    // GetObject on a missing key → 404.
    let resp = gw
        .clone()
        .router()
        .oneshot(Request::builder().method("GET").uri("/photos/missing.txt").body(Body::empty())?)
        .await?;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // DeleteObject → 204, then HEAD → 404.
    let resp = gw
        .clone()
        .router()
        .oneshot(Request::builder().method("DELETE").uri("/photos/a.txt").body(Body::empty())?)
        .await?;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = gw
        .clone()
        .router()
        .oneshot(Request::builder().method("HEAD").uri("/photos/a.txt").body(Body::empty())?)
        .await?;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // ListBuckets: GET / → XML with the bucket name.
    let resp = gw
        .router()
        .oneshot(Request::builder().method("GET").uri("/").body(Body::empty())?)
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let xml = body_string(resp).await;
    assert!(xml.contains("<Name>photos</Name>"), "ListBuckets XML must contain the bucket");

    let _ = std::fs::remove_file(&index_path);
    Ok(())
}
