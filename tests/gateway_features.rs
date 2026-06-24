//! Feature + failure-path tests for the S3-subset gateway (feature `gateway`): user metadata,
//! conditional requests (304/412), object versioning over HTTP, CopyObject via `x-amz-copy-source`,
//! bulk DeleteObjects, the body-size limit (413), and **capability enforcement** (403 without a
//! valid `ce-cap` link, 200 with one). Driven in-process via `tower::ServiceExt::oneshot` against a
//! Store backed by a real ephemeral CE node.
//!
//! Run with: `cargo test -p ce-storage --features gateway --test gateway_features -- --nocapture`.

#![cfg(feature = "gateway")]

mod harness;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ce_storage::gateway::{Auth, Gateway, HEADER_CAP, HEADER_REQUESTER};
use ce_storage::store::Store;
use harness::{Node, live_available};
use http_body_util::BodyExt;
use std::path::PathBuf;
use tower::ServiceExt;

fn temp_index(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ce-storage-gwf-{}-{}-{tag}.json",
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

/// User metadata + caching headers survive a put → get/head round trip as x-amz-meta-* / Cache-Control.
#[tokio::test]
async fn gateway_user_metadata_and_headers() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    let node = Node::start(None).await?;
    let index_path = temp_index("meta");
    let _ = std::fs::remove_file(&index_path);
    let store = Store::with_client(node.client.clone(), index_path.clone())?;
    let gw = Gateway::new(store);

    gw.clone()
        .router()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/b1")
                .body(Body::empty())?,
        )
        .await?;

    let resp = gw
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/b1/k")
                .header("content-type", "text/plain")
                .header("x-amz-meta-author", "leif")
                .header("x-amz-meta-purpose", "test")
                .header("cache-control", "max-age=60")
                .body(Body::from("hello"))?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = gw
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/b1/k")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(resp.headers().get("x-amz-meta-author").unwrap(), "leif");
    assert_eq!(resp.headers().get("x-amz-meta-purpose").unwrap(), "test");
    assert_eq!(resp.headers().get("cache-control").unwrap(), "max-age=60");

    let resp = gw
        .router()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/b1/k")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(resp.headers().get("x-amz-meta-author").unwrap(), "leif");

    let _ = std::fs::remove_file(&index_path);
    Ok(())
}

/// Conditional GET: If-None-Match with the current ETag → 304; mismatch → 200.
#[tokio::test]
async fn gateway_conditional_get_304() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    let node = Node::start(None).await?;
    let index_path = temp_index("cond");
    let _ = std::fs::remove_file(&index_path);
    let store = Store::with_client(node.client.clone(), index_path.clone())?;
    let gw = Gateway::new(store);

    gw.clone()
        .router()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/b")
                .body(Body::empty())?,
        )
        .await?;
    let put = gw
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/b/k")
                .body(Body::from("data"))?,
        )
        .await?;
    let etag = put.headers().get("etag").unwrap().to_str()?.to_string();

    // If-None-Match with the live etag → 304 Not Modified.
    let resp = gw
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/b/k")
                .header("if-none-match", &etag)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);

    // Different etag → 200 with body.
    let resp = gw
        .router()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/b/k")
                .header("if-none-match", "\"deadbeef\"")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);

    let _ = std::fs::remove_file(&index_path);
    Ok(())
}

/// Bad range → 416 (not 404, the old behaviour).
#[tokio::test]
async fn gateway_unsatisfiable_range_416() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    let node = Node::start(None).await?;
    let index_path = temp_index("range416");
    let _ = std::fs::remove_file(&index_path);
    let store = Store::with_client(node.client.clone(), index_path.clone())?;
    let gw = Gateway::new(store);
    gw.clone()
        .router()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/b")
                .body(Body::empty())?,
        )
        .await?;
    gw.clone()
        .router()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/b/k")
                .body(Body::from("12345"))?,
        )
        .await?;
    let resp = gw
        .router()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/b/k")
                .header("range", "bytes=900-999")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    let _ = std::fs::remove_file(&index_path);
    Ok(())
}

/// CopyObject via x-amz-copy-source shares the CID; bulk delete removes many keys.
#[tokio::test]
async fn gateway_copy_and_bulk_delete() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    let node = Node::start(None).await?;
    let index_path = temp_index("copybulk");
    let _ = std::fs::remove_file(&index_path);
    let store = Store::with_client(node.client.clone(), index_path.clone())?;
    let gw = Gateway::new(store);
    gw.clone()
        .router()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/b")
                .body(Body::empty())?,
        )
        .await?;
    for k in ["a", "b", "c"] {
        gw.clone()
            .router()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/b/{k}"))
                    .body(Body::from("x"))?,
            )
            .await?;
    }
    // CopyObject a → d.
    let resp = gw
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/b/d")
                .header("x-amz-copy-source", "/b/a")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let xml = body_string(resp).await;
    assert!(
        xml.contains("<CopyObjectResult>"),
        "copy returns CopyObjectResult: {xml}"
    );

    // Bulk delete a,b,c via POST /b?delete with a newline-separated list.
    let resp = gw
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/b?delete")
                .body(Body::from("a\nb\nc"))?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let xml = body_string(resp).await;
    assert!(
        xml.matches("<Deleted>").count() == 3,
        "three deletions: {xml}"
    );

    // d (the copy) survives.
    let resp = gw
        .router()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/b/d")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = std::fs::remove_file(&index_path);
    Ok(())
}

/// The body-size limit rejects an oversize PUT with 413 before buffering it all.
#[tokio::test]
async fn gateway_body_limit_413() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    let node = Node::start(None).await?;
    let index_path = temp_index("limit");
    let _ = std::fs::remove_file(&index_path);
    let store = Store::with_client(node.client.clone(), index_path.clone())?;
    // Tiny 16-byte body limit so a small payload trips it deterministically.
    let gw = Gateway::new(store).with_body_limit(16);
    gw.clone()
        .router()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/b")
                .body(Body::empty())?,
        )
        .await?;
    let resp = gw
        .router()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/b/big")
                .body(Body::from(vec![0u8; 1024]))?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let _ = std::fs::remove_file(&index_path);
    Ok(())
}

/// Versioning over HTTP: with versioning on, a second PUT keeps the prior version reachable by
/// ?versionId; a DELETE leaves prior versions retrievable.
#[tokio::test]
async fn gateway_versioning_roundtrip() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    let node = Node::start(None).await?;
    let index_path = temp_index("ver");
    let _ = std::fs::remove_file(&index_path);
    let mut store = Store::with_client(node.client.clone(), index_path.clone())?;
    store.make_bucket("vb")?;
    store.set_versioning("vb", true)?;
    let v1 = store.put_object("vb", "k", b"one", "text/plain").await?;
    let _v2 = store.put_object("vb", "k", b"two", "text/plain").await?;
    let gw = Gateway::new(store);

    // Current is "two".
    let resp = gw
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/vb/k")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(body_string(resp).await, "two");

    // Old version by id is "one".
    let resp = gw
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/vb/k?versionId={}", v1.version_id))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(body_string(resp).await, "one");

    // Delete (adds a marker), current is hidden, but the old version is still reachable.
    let resp = gw
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/vb/k")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = gw
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/vb/k")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "delete marker hides current"
    );
    let resp = gw
        .router()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/vb/k?versionId={}", v1.version_id))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        body_string(resp).await,
        "one",
        "old version survives delete"
    );

    let _ = std::fs::remove_file(&index_path);
    Ok(())
}

/// Capability enforcement: with `Auth` on, a request with no `ce-cap` link is 403; a request with a
/// valid scoped link (and matching requester) is allowed; an out-of-scope key is 403.
#[tokio::test]
async fn gateway_capability_enforcement() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    let node = Node::start(None).await?;
    let index_path = temp_index("auth");
    let _ = std::fs::remove_file(&index_path);
    let mut store = Store::with_client(node.client.clone(), index_path.clone())?;
    store.make_bucket("sec")?;
    store
        .put_object("sec", "ok/a", b"secret", "text/plain")
        .await?;

    // The owner identity is the trust root.
    let owner = ce_identity::Identity::load_or_generate(&node.data_dir_path.join("identity"))?;
    let auth = Auth::new(owner.node_id());
    let gw = Gateway::new(store).with_auth(auth);

    // No cap → 403.
    let resp = gw
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/sec/ok/a")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "missing cap → 403");

    // Mint a read link scoped to sec/ok/ for the owner as bearer.
    let scope = ce_storage::caps::Scope {
        bucket: "sec".into(),
        prefix: "ok/".into(),
    };
    let token = ce_storage::caps::mint_link(
        &owner,
        owner.node_id(),
        ce_storage::caps::ABILITY_READ,
        &scope,
        0,
        42,
    )?;
    let requester = owner.node_id_hex();

    // Valid cap on an in-scope key → 200.
    let resp = gw
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/sec/ok/a")
                .header(HEADER_CAP, &token)
                .header(HEADER_REQUESTER, &requester)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK, "valid cap → 200");
    assert_eq!(body_string(resp).await, "secret");

    // Same cap, out-of-scope key → 403.
    let resp = gw
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/sec/other/x")
                .header(HEADER_CAP, &token)
                .header(HEADER_REQUESTER, &requester)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "out-of-scope key → 403"
    );

    // A read cap used for a write (DELETE) → 403.
    let resp = gw
        .router()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/sec/ok/a")
                .header(HEADER_CAP, &token)
                .header(HEADER_REQUESTER, &requester)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "read cap can't delete → 403"
    );

    let _ = std::fs::remove_file(&index_path);
    Ok(())
}

/// Full S3 multipart flow over HTTP: POST ?uploads (initiate) → PUT ?partNumber&uploadId (parts) →
/// POST ?uploadId with an XML part list (complete) → GET returns the reassembled object. Exercises
/// the gateway's `post_object` control verbs against a real node.
#[tokio::test]
async fn gateway_multipart_http_flow() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    let node = Node::start(None).await?;
    let index_path = temp_index("mphttp");
    let _ = std::fs::remove_file(&index_path);
    let store = Store::with_client(node.client.clone(), index_path.clone())?;
    let gw = Gateway::new(store);

    gw.clone()
        .router()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/mpb")
                .body(Body::empty())?,
        )
        .await?;

    // Initiate.
    let resp = gw
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mpb/big.bin?uploads")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let xml = body_string(resp).await;
    // Extract the upload id from <UploadId>..</UploadId>.
    let uid = xml
        .split("<UploadId>")
        .nth(1)
        .and_then(|s| s.split("</UploadId>").next())
        .expect("upload id in response")
        .to_string();
    assert!(!uid.is_empty());

    // Two parts: a whole 1 MiB part (multiple of the part chunk) then a short final part.
    let mib = 1024 * 1024;
    let p1 = vec![7u8; mib];
    let p2 = b"tail".to_vec();
    let mut etags = Vec::new();
    for (n, data) in [(1u32, p1.clone()), (2u32, p2.clone())] {
        let resp = gw
            .clone()
            .router()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/mpb/big.bin?partNumber={n}&uploadId={uid}"))
                    .body(Body::from(data))?,
            )
            .await?;
        assert_eq!(resp.status(), StatusCode::OK, "part {n} uploaded");
        let etag = resp
            .headers()
            .get("etag")
            .unwrap()
            .to_str()?
            .trim_matches('"')
            .to_string();
        etags.push((n, etag));
    }

    // Complete with the XML part list.
    let part_xml: String = etags
        .iter()
        .map(|(n, e)| format!("<Part><PartNumber>{n}</PartNumber><ETag>\"{e}\"</ETag></Part>"))
        .collect();
    let complete_body = format!("<CompleteMultipartUpload>{part_xml}</CompleteMultipartUpload>");
    let resp = gw
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/mpb/big.bin?uploadId={uid}"))
                .body(Body::from(complete_body))?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let xml = body_string(resp).await;
    assert!(xml.contains("<CompleteMultipartUploadResult>"), "{xml}");

    // GET the assembled object back: it equals p1 || p2.
    let resp = gw
        .router()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mpb/big.bin")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let got = resp.into_body().collect().await.unwrap().to_bytes();
    let mut want = p1.clone();
    want.extend_from_slice(&p2);
    assert_eq!(
        got.as_ref(),
        want.as_slice(),
        "reassembled multipart object"
    );

    let _ = std::fs::remove_file(&index_path);
    Ok(())
}

/// A POST on an object with neither ?uploads nor ?uploadId is a 400 (not a silent success).
#[tokio::test]
async fn gateway_post_object_requires_multipart_query() -> anyhow::Result<()> {
    if !live_available() {
        return Ok(());
    }
    let node = Node::start(None).await?;
    let index_path = temp_index("postbad");
    let _ = std::fs::remove_file(&index_path);
    let store = Store::with_client(node.client.clone(), index_path.clone())?;
    let gw = Gateway::new(store);
    gw.clone()
        .router()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/pb")
                .body(Body::empty())?,
        )
        .await?;
    let resp = gw
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/pb/k")
                .body(Body::from("noise"))?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let _ = std::fs::remove_file(&index_path);
    Ok(())
}
