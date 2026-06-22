//! A tiny S3-subset HTTP gateway (feature `gateway`) so existing S3 clients (`aws s3`, SDKs that
//! target an `--endpoint-url`) can talk to ce-storage unmodified for the core verbs.
//!
//! Implemented (the documented core): `PUT /{bucket}/{key}` (PutObject), `GET /{bucket}/{key}`
//! (GetObject, incl. `Range`), `HEAD /{bucket}/{key}` (HeadObject), `DELETE /{bucket}/{key}`
//! (DeleteObject), `GET /{bucket}?list-type=2&prefix=&delimiter=&continuation-token=` (ListObjectsV2,
//! XML), `PUT /{bucket}` (CreateBucket), `GET /` (ListBuckets, XML).
//!
//! Scope (honest): this is a single-owner gateway for local/trusted use. It does **not** implement
//! AWS SigV4 request signing — front it with a presigned-equivalent `ce-cap` link check or run it on
//! a trusted host. Multipart upload and full bucket policy are out of scope for the MVP (the design
//! stub lists them as extensions). The point is that the *bytes* and *listing* are S3-shaped, so
//! `aws s3 cp` / `aws s3 ls` work for get/put/list against `--endpoint-url`.

use crate::store::Store;
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, put},
    Router,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Shared gateway state: the store behind a mutex (single-writer owner model).
#[derive(Clone)]
pub struct Gateway {
    store: Arc<Mutex<Store>>,
}

impl Gateway {
    /// Wrap a [`Store`] as gateway state.
    pub fn new(store: Store) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
        }
    }

    /// Build the axum router exposing the S3-subset.
    pub fn router(self) -> Router {
        Router::new()
            .route("/", get(list_buckets))
            .route("/:bucket", put(create_bucket).get(list_objects))
            .route(
                "/:bucket/*key",
                put(put_object)
                    .get(get_object)
                    .head(head_object)
                    .delete(delete_object),
            )
            .with_state(self)
    }
}

fn err(status: StatusCode, code: &str, msg: &str) -> Response {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{}</Message></Error>",
        xml_escape(msg)
    );
    (status, [(header::CONTENT_TYPE, "application/xml")], body).into_response()
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

async fn list_buckets(State(gw): State<Gateway>) -> Response {
    let store = gw.store.lock().await;
    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListAllMyBucketsResult><Buckets>",
    );
    for b in store.list_buckets() {
        body.push_str(&format!("<Bucket><Name>{}</Name></Bucket>", xml_escape(&b)));
    }
    body.push_str("</Buckets></ListAllMyBucketsResult>");
    ([(header::CONTENT_TYPE, "application/xml")], body).into_response()
}

async fn create_bucket(State(gw): State<Gateway>, Path(bucket): Path<String>) -> Response {
    let mut store = gw.store.lock().await;
    match store.make_bucket(&bucket) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => err(StatusCode::CONFLICT, "BucketAlreadyExists", &e.to_string()),
    }
}

async fn list_objects(
    State(gw): State<Gateway>,
    Path(bucket): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let store = gw.store.lock().await;
    let prefix = q.get("prefix").map(String::as_str).unwrap_or("");
    let delimiter = q.get("delimiter").map(String::as_str);
    let cont = q.get("continuation-token").map(String::as_str);
    let max_keys = q
        .get("max-keys")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1000);

    match store.list_objects(&bucket, prefix, delimiter, cont, max_keys) {
        Ok(page) => {
            let mut body = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult><Name>{}</Name><Prefix>{}</Prefix><IsTruncated>{}</IsTruncated>",
                xml_escape(&bucket),
                xml_escape(prefix),
                page.is_truncated
            );
            if let Some(tok) = &page.next_continuation {
                body.push_str(&format!(
                    "<NextContinuationToken>{}</NextContinuationToken>",
                    xml_escape(tok)
                ));
            }
            for (k, meta) in &page.keys {
                body.push_str(&format!(
                    "<Contents><Key>{}</Key><Size>{}</Size><ETag>\"{}\"</ETag></Contents>",
                    xml_escape(k),
                    meta.size,
                    xml_escape(&meta.etag)
                ));
            }
            for cp in &page.common_prefixes {
                body.push_str(&format!(
                    "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                    xml_escape(cp)
                ));
            }
            body.push_str("</ListBucketResult>");
            ([(header::CONTENT_TYPE, "application/xml")], body).into_response()
        }
        Err(e) => err(StatusCode::NOT_FOUND, "NoSuchBucket", &e.to_string()),
    }
}

async fn put_object(
    State(gw): State<Gateway>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let mut store = gw.store.lock().await;
    match store.put_object(&bucket, &key, &body, &content_type).await {
        Ok(meta) => (
            StatusCode::OK,
            [(header::ETAG, format!("\"{}\"", meta.etag))],
        )
            .into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, "InvalidRequest", &e.to_string()),
    }
}

async fn get_object(
    State(gw): State<Gateway>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let store = gw.store.lock().await;
    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let result = match range {
        Some(r) => store.get_object_range(&bucket, &key, &r).await,
        None => store.get_object(&bucket, &key).await,
    };

    match result {
        Ok(res) => {
            let mut hdrs = vec![
                (header::CONTENT_TYPE, res.content_type.clone()),
                (header::ETAG, format!("\"{}\"", res.etag)),
                (header::ACCEPT_RANGES, "bytes".to_string()),
            ];
            let status = if let Some((start, end)) = res.range {
                hdrs.push((
                    header::CONTENT_RANGE,
                    format!("bytes {start}-{end}/{}", res.total_size),
                ));
                StatusCode::PARTIAL_CONTENT
            } else {
                StatusCode::OK
            };
            let mut map = HeaderMap::new();
            for (k, v) in hdrs {
                if let Ok(val) = v.parse() {
                    map.insert(k, val);
                }
            }
            (status, map, res.bytes).into_response()
        }
        Err(e) => err(StatusCode::NOT_FOUND, "NoSuchKey", &e.to_string()),
    }
}

async fn head_object(
    State(gw): State<Gateway>,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    let store = gw.store.lock().await;
    match store.head_object(&bucket, &key) {
        Ok(meta) => {
            let mut map = HeaderMap::new();
            if let Ok(v) = meta.size.to_string().parse() {
                map.insert(header::CONTENT_LENGTH, v);
            }
            if let Ok(v) = format!("\"{}\"", meta.etag).parse() {
                map.insert(header::ETAG, v);
            }
            if let Ok(v) = meta.content_type.parse() {
                map.insert(header::CONTENT_TYPE, v);
            }
            (StatusCode::OK, map).into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn delete_object(
    State(gw): State<Gateway>,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    let mut store = gw.store.lock().await;
    match store.delete_object(&bucket, &key) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err(StatusCode::NOT_FOUND, "NoSuchBucket", &e.to_string()),
    }
}
