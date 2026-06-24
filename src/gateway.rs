//! A tiny S3-subset HTTP gateway (feature `gateway`) so existing S3 clients (`aws s3`, SDKs that
//! target an `--endpoint-url`) can talk to ce-storage unmodified for the core verbs.
//!
//! Implemented (the documented core): `PUT /{bucket}/{key}` (PutObject, incl. `x-amz-copy-source`
//! CopyObject and `x-amz-meta-*` user metadata), `GET /{bucket}/{key}` (GetObject, incl. `Range` and
//! conditional `If-*` headers), `HEAD /{bucket}/{key}` (HeadObject), `DELETE /{bucket}/{key}`
//! (DeleteObject, incl. `?versionId=`), `GET /{bucket}?list-type=2...` (ListObjectsV2, XML),
//! `POST /{bucket}?delete` (bulk DeleteObjects), `PUT /{bucket}` (CreateBucket), `GET /` (ListBuckets).
//!
//! ## Authorization
//!
//! By default the gateway is **open** (single-owner, local/trusted use) — exactly as before, so
//! `aws s3` works with no signing. Pass an [`Auth`] to [`Gateway::with_auth`] to **enforce
//! `ce-cap` capability links** on every object request: the presenter supplies a token via the
//! `X-Ce-Cap` header (or `?ce-cap=` query) and its node id via `X-Ce-Requester`, and each handler
//! runs [`crate::caps::verify_link`] for the request's ability/bucket/key before doing any work,
//! returning `403 AccessDenied` on failure. This is the presigned-equivalent enforcement point the
//! library always had but nothing previously wired in. (AWS SigV4 is still not implemented; the
//! `ce-cap` link is the auth mechanism.)
//!
//! ## Limits
//!
//! The router installs a [`DefaultBodyLimit`] (default [`DEFAULT_BODY_LIMIT`]) so an oversize PUT is
//! rejected with `413` before the whole body is buffered. The store additionally enforces its own
//! `max_object_size`.

use crate::caps::{self, ABILITY_READ, ABILITY_WRITE};
use crate::store::{Preconditions, PutOptions, StorageError, Store};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, put},
};
use ce_identity::NodeId;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Default maximum request body the gateway accepts before returning 413: 256 MiB. Tune to taste;
/// the store's own `max_object_size` is the durable cap.
pub const DEFAULT_BODY_LIMIT: usize = 256 * 1024 * 1024;

/// Header carrying the `ce-cap` access link token (presigned-equivalent).
pub const HEADER_CAP: &str = "x-ce-cap";
/// Header carrying the presenting requester's node id (hex), bound as the capability audience.
pub const HEADER_REQUESTER: &str = "x-ce-requester";
/// Header for `CopyObject` source (`bucket/key`), mirroring S3 `x-amz-copy-source`.
pub const HEADER_COPY_SOURCE: &str = "x-amz-copy-source";
/// Prefix for user-metadata request/response headers, mirroring S3 `x-amz-meta-*`.
pub const META_PREFIX: &str = "x-amz-meta-";

/// Capability-enforcement policy for the gateway. When present, object requests must carry a valid
/// `ce-cap` link covering the requested ability/bucket/key.
#[derive(Clone)]
pub struct Auth {
    /// This serving node's id (the implicit root of accepted chains).
    pub self_id: NodeId,
    /// Additional accepted root node ids.
    pub accepted_roots: Vec<NodeId>,
    /// This node's capability self-tags (for tag-scoped resources).
    pub self_tags: Vec<String>,
    /// Revoked (issuer, nonce) pairs, consulted on each verify. Refresh out of band.
    pub revoked: Arc<Vec<(NodeId, u64)>>,
}

impl Auth {
    /// Build an auth policy rooted at `self_id` with no extra roots/tags and an empty revocation set.
    pub fn new(self_id: NodeId) -> Self {
        Self {
            self_id,
            accepted_roots: Vec::new(),
            self_tags: Vec::new(),
            revoked: Arc::new(Vec::new()),
        }
    }

    /// Replace the revocation set (e.g. after polling the chain).
    pub fn with_revoked(mut self, revoked: Vec<(NodeId, u64)>) -> Self {
        self.revoked = Arc::new(revoked);
        self
    }

    fn is_revoked(&self, issuer: &NodeId, nonce: u64) -> bool {
        self.revoked.iter().any(|(i, n)| i == issuer && *n == nonce)
    }
}

/// Shared gateway state: the store behind a mutex (single-writer owner model) + optional auth.
#[derive(Clone)]
pub struct Gateway {
    store: Arc<Mutex<Store>>,
    auth: Option<Auth>,
    body_limit: usize,
}

impl Gateway {
    /// Wrap a [`Store`] as an **open** gateway (no capability enforcement).
    pub fn new(store: Store) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            auth: None,
            body_limit: DEFAULT_BODY_LIMIT,
        }
    }

    /// Enable `ce-cap` capability enforcement on object requests.
    pub fn with_auth(mut self, auth: Auth) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Override the maximum request body size (bytes) before a 413.
    pub fn with_body_limit(mut self, bytes: usize) -> Self {
        self.body_limit = bytes;
        self
    }

    /// Build the axum router exposing the S3-subset.
    pub fn router(self) -> Router {
        let limit = self.body_limit;
        Router::new()
            .route("/", get(list_buckets))
            .route(
                "/:bucket",
                put(create_bucket).get(list_objects).post(bulk_delete),
            )
            .route(
                "/:bucket/*key",
                put(put_object)
                    .get(get_object)
                    .head(head_object)
                    .post(post_object)
                    .delete(delete_object),
            )
            .layer(DefaultBodyLimit::max(limit))
            .with_state(self)
    }

    /// Enforce auth (if configured) for `ability` on `bucket/key`. Returns an error response to
    /// short-circuit the handler, or `Ok(())` to proceed. The error is boxed because an axum
    /// `Response` is large and lives only on the (rare) rejection path.
    fn authorize(
        &self,
        headers: &HeaderMap,
        q: &HashMap<String, String>,
        ability: &str,
        bucket: &str,
        key: &str,
    ) -> Result<(), Box<Response>> {
        let Some(auth) = &self.auth else {
            return Ok(()); // open gateway
        };
        let token = headers
            .get(HEADER_CAP)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .or_else(|| q.get("ce-cap").cloned());
        let token = match token {
            Some(t) => t,
            None => {
                return Err(Box::new(err(
                    StatusCode::FORBIDDEN,
                    "AccessDenied",
                    "missing capability link (X-Ce-Cap header or ?ce-cap=)",
                )));
            }
        };
        let requester = match headers
            .get(HEADER_REQUESTER)
            .and_then(|v| v.to_str().ok())
            .map(caps::parse_node_id)
        {
            Some(Ok(id)) => id,
            _ => {
                return Err(Box::new(err(
                    StatusCode::FORBIDDEN,
                    "AccessDenied",
                    "missing or invalid X-Ce-Requester node id",
                )));
            }
        };
        let now = unix_now();
        let revoked = |issuer: &NodeId, nonce: u64| auth.is_revoked(issuer, nonce);
        match caps::verify_link(
            &auth.self_id,
            &auth.accepted_roots,
            &auth.self_tags,
            now,
            &requester,
            ability,
            bucket,
            key,
            &token,
            &revoked,
        ) {
            Ok(()) => Ok(()),
            Err(e) => Err(Box::new(err(StatusCode::FORBIDDEN, "AccessDenied", &e))),
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn err(status: StatusCode, code: &str, msg: &str) -> Response {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{}</Message></Error>",
        xml_escape(msg)
    );
    (status, [(header::CONTENT_TYPE, "application/xml")], body).into_response()
}

/// Map a [`StorageError`] to the correct S3-shaped HTTP response (404 vs 412 vs 416 vs 304 vs 5xx).
fn storage_err(e: StorageError) -> Response {
    match e {
        StorageError::NoSuchBucket(b) => err(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            &format!("no such bucket: {b}"),
        ),
        StorageError::NoSuchKey(k) => err(
            StatusCode::NOT_FOUND,
            "NoSuchKey",
            &format!("no such key: {k}"),
        ),
        StorageError::InvalidRange(m) => err(StatusCode::RANGE_NOT_SATISFIABLE, "InvalidRange", &m),
        StorageError::PreconditionFailed(m) => {
            err(StatusCode::PRECONDITION_FAILED, "PreconditionFailed", &m)
        }
        StorageError::NotModified => StatusCode::NOT_MODIFIED.into_response(),
        StorageError::InvalidRequest(m) => err(StatusCode::BAD_REQUEST, "InvalidRequest", &m),
        StorageError::Backend(m) => err(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", &m),
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Extract `x-amz-meta-*` user metadata from request headers.
fn extract_user_metadata(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for (name, value) in headers.iter() {
        let n = name.as_str();
        if let Some(k) = n.strip_prefix(META_PREFIX)
            && let Ok(v) = value.to_str()
        {
            m.insert(k.to_string(), v.to_string());
        }
    }
    m
}

/// Parse conditional `If-*` headers into [`Preconditions`].
fn extract_preconditions(headers: &HeaderMap) -> Preconditions {
    let hstr = |name: header::HeaderName| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    // HTTP-date parsing is out of scope; we accept unix seconds for the *-since headers (the gateway
    // is for CE-native clients). aws-cli sends RFC dates which we ignore (treated as absent) rather
    // than mis-parse — documented behaviour.
    let parse_secs = |name: header::HeaderName| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
    };
    Preconditions {
        if_match: hstr(header::IF_MATCH),
        if_none_match: hstr(header::IF_NONE_MATCH),
        if_modified_since: parse_secs(header::IF_MODIFIED_SINCE),
        if_unmodified_since: parse_secs(header::IF_UNMODIFIED_SINCE),
    }
}

async fn list_buckets(State(gw): State<Gateway>) -> Response {
    let store = gw.store.lock().await;
    let mut body =
        String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListAllMyBucketsResult><Buckets>");
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
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Err(resp) = gw.authorize(&headers, &q, ABILITY_READ, &bucket, "") {
        return *resp;
    }
    let store = gw.store.lock().await;
    let prefix = q.get("prefix").map(String::as_str).unwrap_or("");
    let delimiter = q.get("delimiter").map(String::as_str);
    // S3 accepts both `continuation-token` and `start-after`.
    let cont = q
        .get("continuation-token")
        .or_else(|| q.get("start-after"))
        .map(String::as_str);
    let max_keys = q
        .get("max-keys")
        .and_then(|s| s.parse::<usize>().ok())
        .map(|n| n.clamp(1, 100_000))
        .unwrap_or(1000);

    match store.list_objects(&bucket, prefix, delimiter, cont, max_keys) {
        Ok(page) => {
            let mut body = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult><Name>{}</Name><Prefix>{}</Prefix><MaxKeys>{}</MaxKeys><KeyCount>{}</KeyCount><IsTruncated>{}</IsTruncated>",
                xml_escape(&bucket),
                xml_escape(prefix),
                page.max_keys,
                page.key_count,
                page.is_truncated
            );
            if let Some(d) = delimiter {
                body.push_str(&format!("<Delimiter>{}</Delimiter>", xml_escape(d)));
            }
            if let Some(tok) = &page.next_continuation {
                body.push_str(&format!(
                    "<NextContinuationToken>{}</NextContinuationToken>",
                    xml_escape(tok)
                ));
            }
            for (k, meta) in &page.keys {
                body.push_str(&format!(
                    "<Contents><Key>{}</Key><LastModified>{}</LastModified><Size>{}</Size><ETag>\"{}\"</ETag></Contents>",
                    xml_escape(k),
                    meta.last_modified,
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

/// `POST /{bucket}?delete` — bulk DeleteObjects. Body is a newline- or comma-separated key list (a
/// pragmatic CE-native shape; the AWS XML `<Delete><Object><Key>` body is also accepted heuristically
/// by extracting `<Key>...</Key>` occurrences).
async fn bulk_delete(
    State(gw): State<Gateway>,
    Path(bucket): Path<String>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    if !q.contains_key("delete") {
        return err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "POST requires ?delete",
        );
    }
    if let Err(resp) = gw.authorize(&headers, &q, ABILITY_WRITE, &bucket, "") {
        return *resp;
    }
    let text = String::from_utf8_lossy(&body);
    let keys = parse_delete_keys(&text);
    if keys.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "no keys to delete",
        );
    }
    let mut store = gw.store.lock().await;
    match store.delete_objects(&bucket, &keys) {
        Ok(results) => {
            let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?><DeleteResult>");
            for (k, r) in results {
                match r {
                    Ok(()) => {
                        xml.push_str(&format!("<Deleted><Key>{}</Key></Deleted>", xml_escape(&k)))
                    }
                    Err(e) => xml.push_str(&format!(
                        "<Error><Key>{}</Key><Message>{}</Message></Error>",
                        xml_escape(&k),
                        xml_escape(&e.to_string())
                    )),
                }
            }
            xml.push_str("</DeleteResult>");
            ([(header::CONTENT_TYPE, "application/xml")], xml).into_response()
        }
        Err(e) => err(StatusCode::NOT_FOUND, "NoSuchBucket", &e.to_string()),
    }
}

fn parse_delete_keys(text: &str) -> Vec<String> {
    // Prefer XML <Key> extraction if present (S3 client shape); else split on newline/comma.
    if text.contains("<Key>") {
        let mut keys = Vec::new();
        let mut rest = text;
        while let Some(start) = rest.find("<Key>") {
            let after = &rest[start + 5..];
            if let Some(end) = after.find("</Key>") {
                keys.push(after[..end].to_string());
                rest = &after[end + 6..];
            } else {
                break;
            }
        }
        return keys;
    }
    text.split(['\n', ','])
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

async fn put_object(
    State(gw): State<Gateway>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    if let Err(resp) = gw.authorize(&headers, &q, ABILITY_WRITE, &bucket, &key) {
        return *resp;
    }

    // UploadPart: PUT /{bucket}/{key}?partNumber=N&uploadId=ID
    if let (Some(pn), Some(uid)) = (q.get("partNumber"), q.get("uploadId")) {
        let part_number = match pn.parse::<u32>() {
            Ok(n) => n,
            Err(_) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    "InvalidArgument",
                    "partNumber must be an integer",
                );
            }
        };
        let mut store = gw.store.lock().await;
        return match store.upload_part(uid, part_number, &body).await {
            Ok(etag) => (StatusCode::OK, [(header::ETAG, format!("\"{etag}\""))]).into_response(),
            Err(e) => storage_err(e),
        };
    }

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    // CopyObject: x-amz-copy-source: <src-bucket>/<src-key>.
    if let Some(src) = headers
        .get(HEADER_COPY_SOURCE)
        .and_then(|v| v.to_str().ok())
    {
        let src = src.trim_start_matches('/');
        let (sb, sk) = match src.split_once('/') {
            Some(p) => p,
            None => {
                return err(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "x-amz-copy-source must be bucket/key",
                );
            }
        };
        // Read access to the source must also be authorized.
        if let Err(resp) = gw.authorize(&headers, &q, ABILITY_READ, sb, sk) {
            return *resp;
        }
        let mut store = gw.store.lock().await;
        return match store.copy_object(sb, sk, &bucket, &key) {
            Ok(()) => {
                let etag = store
                    .head_object(&bucket, &key)
                    .map(|m| m.etag)
                    .unwrap_or_default();
                let xml = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CopyObjectResult><ETag>\"{}\"</ETag></CopyObjectResult>",
                    xml_escape(&etag)
                );
                ([(header::CONTENT_TYPE, "application/xml")], xml).into_response()
            }
            Err(e) => err(StatusCode::NOT_FOUND, "NoSuchKey", &e.to_string()),
        };
    }

    let opts = PutOptions {
        content_type,
        metadata: extract_user_metadata(&headers),
        cache_control: headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
        content_disposition: headers
            .get(header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
        content_encoding: headers
            .get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
        preconditions: extract_preconditions(&headers),
    };
    let mut store = gw.store.lock().await;
    match store.put_object_opts(&bucket, &key, &body, &opts).await {
        Ok(meta) => (
            StatusCode::OK,
            [(header::ETAG, format!("\"{}\"", meta.etag))],
        )
            .into_response(),
        Err(e) => storage_err(e),
    }
}

/// `POST /{bucket}/{key}` — the S3 multipart-upload control verbs:
///
/// * `?uploads` → **CreateMultipartUpload**: begins an upload and returns an
///   `<InitiateMultipartUploadResult>` carrying the upload id (which the client then uses with
///   `PUT ?partNumber&uploadId` for each part).
/// * `?uploadId=ID` → **CompleteMultipartUpload**: the body is the AWS XML part list
///   (`<Part><PartNumber>..</PartNumber><ETag>..</ETag></Part>` repeated); the parts are assembled
///   into the final object and an `<CompleteMultipartUploadResult>` is returned.
///
/// Anything else is a 400 (the bare `POST /{bucket}?delete` bulk-delete lives on the bucket route).
async fn post_object(
    State(gw): State<Gateway>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    if let Err(resp) = gw.authorize(&headers, &q, ABILITY_WRITE, &bucket, &key) {
        return *resp;
    }

    // CreateMultipartUpload: POST /{bucket}/{key}?uploads
    if q.contains_key("uploads") {
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();
        let opts = PutOptions {
            content_type,
            metadata: extract_user_metadata(&headers),
            ..Default::default()
        };
        let mut store = gw.store.lock().await;
        return match store.create_multipart_upload(&bucket, &key, &opts).await {
            Ok(id) => {
                let xml = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><InitiateMultipartUploadResult><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId></InitiateMultipartUploadResult>",
                    xml_escape(&bucket),
                    xml_escape(&key),
                    xml_escape(&id)
                );
                ([(header::CONTENT_TYPE, "application/xml")], xml).into_response()
            }
            Err(e) => storage_err(e),
        };
    }

    // CompleteMultipartUpload: POST /{bucket}/{key}?uploadId=ID with an XML part list.
    if let Some(uid) = q.get("uploadId") {
        let parts = parse_complete_parts(&String::from_utf8_lossy(&body));
        if parts.is_empty() {
            return err(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "CompleteMultipartUpload requires a non-empty <Part> list",
            );
        }
        let mut store = gw.store.lock().await;
        return match store.complete_multipart_upload(uid, &parts).await {
            Ok(meta) => {
                let xml = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CompleteMultipartUploadResult><Bucket>{}</Bucket><Key>{}</Key><ETag>\"{}\"</ETag></CompleteMultipartUploadResult>",
                    xml_escape(&bucket),
                    xml_escape(&key),
                    xml_escape(&meta.etag)
                );
                ([(header::CONTENT_TYPE, "application/xml")], xml).into_response()
            }
            Err(e) => storage_err(e),
        };
    }

    err(
        StatusCode::BAD_REQUEST,
        "InvalidRequest",
        "POST on an object requires ?uploads (initiate) or ?uploadId= (complete)",
    )
}

/// Parse the `CompleteMultipartUpload` XML body into an ordered `(part_number, etag)` list. Extracts
/// each `<Part>...</Part>`'s `<PartNumber>` and `<ETag>` (quotes stripped). Robust to whitespace and
/// attribute noise; a part missing either field is skipped rather than aborting the whole parse.
fn parse_complete_parts(xml: &str) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<Part>") {
        let after = &rest[start + 6..];
        let Some(end) = after.find("</Part>") else {
            break;
        };
        let block = &after[..end];
        rest = &after[end + 7..];
        let num = extract_tag(block, "PartNumber").and_then(|s| s.trim().parse::<u32>().ok());
        let etag = extract_tag(block, "ETag").map(|s| s.trim().trim_matches('"').to_string());
        if let (Some(n), Some(e)) = (num, etag) {
            out.push((n, e));
        }
    }
    out
}

/// Extract the text content of the first `<tag>...</tag>` in `s`, if present.
fn extract_tag(s: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = s.find(&open)? + open.len();
    let end = s[start..].find(&close)? + start;
    Some(s[start..end].to_string())
}

async fn get_object(
    State(gw): State<Gateway>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Err(resp) = gw.authorize(&headers, &q, ABILITY_READ, &bucket, &key) {
        return *resp;
    }
    let store = gw.store.lock().await;
    let version_id = q.get("versionId").map(String::as_str);
    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let preconditions = extract_preconditions(&headers);

    let result = match range {
        Some(r) => {
            store
                .get_object_range_opts(&bucket, &key, &r, version_id)
                .await
        }
        None => {
            store
                .get_object_opts(&bucket, &key, version_id, &preconditions)
                .await
        }
    };

    match result {
        Ok(res) => {
            let mut map = HeaderMap::new();
            insert_str(&mut map, header::CONTENT_TYPE, &res.content_type);
            insert_str(&mut map, header::ETAG, &format!("\"{}\"", res.etag));
            insert_str(&mut map, header::ACCEPT_RANGES, "bytes");
            insert_str(
                &mut map,
                header::LAST_MODIFIED,
                &res.last_modified.to_string(),
            );
            if let Some(cc) = &res.cache_control {
                insert_str(&mut map, header::CACHE_CONTROL, cc);
            }
            if let Some(cd) = &res.content_disposition {
                insert_str(&mut map, header::CONTENT_DISPOSITION, cd);
            }
            if let Some(ce) = &res.content_encoding {
                insert_str(&mut map, header::CONTENT_ENCODING, ce);
            }
            for (k, v) in &res.metadata {
                if let (Ok(name), Ok(val)) = (
                    header::HeaderName::try_from(format!("{META_PREFIX}{k}")),
                    header::HeaderValue::try_from(v.as_str()),
                ) {
                    map.insert(name, val);
                }
            }
            let status = if let Some((start, end)) = res.range {
                insert_str(
                    &mut map,
                    header::CONTENT_RANGE,
                    &format!("bytes {start}-{end}/{}", res.total_size),
                );
                StatusCode::PARTIAL_CONTENT
            } else {
                StatusCode::OK
            };
            (status, map, res.bytes).into_response()
        }
        Err(e) => storage_err(e),
    }
}

fn insert_str(map: &mut HeaderMap, name: header::HeaderName, value: &str) {
    if let Ok(v) = header::HeaderValue::try_from(value) {
        map.insert(name, v);
    }
}

async fn head_object(
    State(gw): State<Gateway>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Err(resp) = gw.authorize(&headers, &q, ABILITY_READ, &bucket, &key) {
        return *resp;
    }
    let store = gw.store.lock().await;
    let version_id = q.get("versionId").map(String::as_str);
    let meta = match version_id {
        Some(v) => store.head_object_version(&bucket, &key, v),
        None => store.head_object(&bucket, &key),
    };
    match meta {
        Ok(meta) => {
            // Conditional HEAD: honor If-None-Match / If-Modified-Since (304).
            let pc = extract_preconditions(&headers);
            if let Err(StorageError::NotModified) = pc.check_read(&meta.etag, meta.last_modified) {
                return StatusCode::NOT_MODIFIED.into_response();
            }
            let mut map = HeaderMap::new();
            insert_str(&mut map, header::CONTENT_LENGTH, &meta.size.to_string());
            insert_str(&mut map, header::ETAG, &format!("\"{}\"", meta.etag));
            insert_str(&mut map, header::CONTENT_TYPE, &meta.content_type);
            insert_str(
                &mut map,
                header::LAST_MODIFIED,
                &meta.last_modified.to_string(),
            );
            for (k, v) in &meta.metadata {
                if let (Ok(name), Ok(val)) = (
                    header::HeaderName::try_from(format!("{META_PREFIX}{k}")),
                    header::HeaderValue::try_from(v.as_str()),
                ) {
                    map.insert(name, val);
                }
            }
            (StatusCode::OK, map).into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn delete_object(
    State(gw): State<Gateway>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Err(resp) = gw.authorize(&headers, &q, ABILITY_WRITE, &bucket, &key) {
        return *resp;
    }
    let mut store = gw.store.lock().await;
    let r = match q.get("versionId") {
        Some(v) => store.delete_object_version(&bucket, &key, v),
        None => store.delete_object(&bucket, &key),
    };
    match r {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err(StatusCode::NOT_FOUND, "NoSuchBucket", &e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_delete_keys_handles_both_shapes() {
        assert_eq!(parse_delete_keys("a\nb\nc"), vec!["a", "b", "c"]);
        assert_eq!(parse_delete_keys("a, b ,c"), vec!["a", "b", "c"]);
        assert_eq!(
            parse_delete_keys(
                "<Delete><Object><Key>x/1</Key></Object><Object><Key>y</Key></Object></Delete>"
            ),
            vec!["x/1", "y"]
        );
        assert!(parse_delete_keys("   ").is_empty());
    }

    #[test]
    fn xml_escape_handles_quotes_and_brackets() {
        assert_eq!(xml_escape("a&b<c>d\"e"), "a&amp;b&lt;c&gt;d&quot;e");
    }

    #[test]
    fn parse_complete_parts_extracts_ordered_list() {
        let xml = "<CompleteMultipartUpload>\
            <Part><PartNumber>1</PartNumber><ETag>\"abc\"</ETag></Part>\
            <Part><PartNumber>2</PartNumber><ETag>def</ETag></Part>\
            </CompleteMultipartUpload>";
        assert_eq!(
            parse_complete_parts(xml),
            vec![(1, "abc".to_string()), (2, "def".to_string())]
        );
    }

    #[test]
    fn parse_complete_parts_skips_malformed_and_handles_whitespace() {
        // A part missing its ETag is skipped; whitespace around values is trimmed.
        let xml = "<Part><PartNumber> 3 </PartNumber></Part>\
            <Part><PartNumber>4</PartNumber><ETag> ff </ETag></Part>";
        assert_eq!(parse_complete_parts(xml), vec![(4, "ff".to_string())]);
        // No parts at all → empty.
        assert!(parse_complete_parts("<nothing/>").is_empty());
        assert!(parse_complete_parts("").is_empty());
    }

    #[test]
    fn extract_tag_finds_first_occurrence() {
        assert_eq!(extract_tag("<a>x</a><a>y</a>", "a"), Some("x".to_string()));
        assert_eq!(extract_tag("<b>z</b>", "a"), None);
        assert_eq!(extract_tag("<a></a>", "a"), Some(String::new()));
    }
}
