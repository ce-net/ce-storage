//! Presigned-equivalent access links — a scoped, time-bounded `ce-cap` capability granting
//! `storage:read` (or `storage:write`) on a `bucket/prefix`, encoded as a portable token.
//!
//! S3 presigned URLs are bearer tokens that grant temporary access to one object/prefix. The CE
//! equivalent is a signed, attenuating `ce-cap` chain: the bucket owner mints a capability whose
//! abilities are `["storage:read"]` (opaque app strings — CE assigns them no meaning), whose
//! resource is the owning node, and whose caveats carry the expiry (`not_after`) and the
//! bucket/prefix scope (`path_prefix`). The holder presents the token; any honoring node verifies
//! it offline in microseconds via [`ce_cap::authorize`], with no policy server and no shared
//! secret. Re-delegation (attenuation) is free: a holder can narrow the prefix and hand it on.
//!
//! Abilities used by this app (opaque to `ce-cap`):
//! - `storage:read`  — fetch objects under the scoped bucket/prefix.
//! - `storage:write` — put/delete objects under the scoped bucket/prefix.
//!
//! The `bucket/prefix` scope lives in the `path_prefix` caveat as `"<bucket>/<prefix>"`. The
//! enforcer (a serving node / gateway) must check the requested `bucket/key` is under that prefix —
//! `ce-cap` enforces the temporal caveat and the signature/attenuation chain; the path caveat is an
//! app caveat the app honors. [`scope_allows`] implements that check.

use anyhow::{Context, Result};
use ce_cap::{Caveats, Resource, SignedCapability};
use ce_identity::{Identity, NodeId};

/// Ability string: read objects under the scoped prefix.
pub const ABILITY_READ: &str = "storage:read";
/// Ability string: write/delete objects under the scoped prefix.
pub const ABILITY_WRITE: &str = "storage:write";

/// Parse a 64-hex node id string into a [`NodeId`] (`[u8; 32]`). Used by the gateway to identify the
/// presenting requester from a header, and by the CLI to bind a link to a specific audience.
pub fn parse_node_id(hex_str: &str) -> Result<NodeId> {
    let bytes = hex::decode(hex_str.trim()).context("node id must be hex")?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "node id must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        )
    })?;
    Ok(arr)
}

/// A parsed storage access scope: which bucket and key-prefix a capability covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// Bucket the link is scoped to.
    pub bucket: String,
    /// Key prefix within the bucket (empty = whole bucket).
    pub prefix: String,
}

impl Scope {
    /// Encode as the `path_prefix` caveat string `"<bucket>/<prefix>"`.
    pub fn to_caveat(&self) -> String {
        format!("{}/{}", self.bucket, self.prefix)
    }

    /// Parse a `path_prefix` caveat string back into a scope.
    pub fn from_caveat(s: &str) -> Scope {
        match s.split_once('/') {
            Some((bucket, prefix)) => Scope {
                bucket: bucket.to_string(),
                prefix: prefix.to_string(),
            },
            None => Scope {
                bucket: s.to_string(),
                prefix: String::new(),
            },
        }
    }
}

/// Does this scope permit access to `bucket/key`? True iff the bucket matches and the key falls
/// under the scope's prefix at a path boundary. This is the app caveat enforcement that `ce-cap`
/// defers to the action.
///
/// The prefix is matched on `/`-delimited path segments, not raw bytes: scope `photos` covers
/// `photos` and `photos/a` but NOT `photos-secret/x`. Trailing slashes on the prefix are
/// normalized away so `photos` and `photos/` behave identically. An empty prefix covers the
/// whole bucket.
///
/// ```
/// use ce_storage::caps::{Scope, scope_allows};
/// let scope = Scope { bucket: "photos".into(), prefix: "2026".into() };
/// assert!(scope_allows(&scope, "photos", "2026"));        // the bare prefix key
/// assert!(scope_allows(&scope, "photos", "2026/a.jpg"));  // a child under the prefix
/// assert!(!scope_allows(&scope, "photos", "2025/x"));     // different prefix
/// assert!(!scope_allows(&scope, "photos", "2026-raw/x")); // sibling segment, NOT covered
/// assert!(!scope_allows(&scope, "docs", "2026/a.jpg"));   // different bucket
/// ```
pub fn scope_allows(scope: &Scope, bucket: &str, key: &str) -> bool {
    if scope.bucket != bucket {
        return false;
    }
    let prefix = scope.prefix.trim_end_matches('/');
    prefix.is_empty() || key == prefix || key.starts_with(&format!("{prefix}/"))
}

/// Mint a presigned-equivalent access link: a single self-issued capability granting `ability` on
/// `scope`, valid until `not_after` (unix seconds), as a portable hex token.
///
/// `owner` is the bucket-owning identity (the root of the chain — a node always implicitly accepts
/// its own key as a root). `audience` is the holder the link is issued to; pass the owner's own
/// node id for an open bearer link, or a specific node id to bind it. `nonce` should be unique per
/// issued link so it can be revoked individually on-chain later.
pub fn mint_link(
    owner: &Identity,
    audience: NodeId,
    ability: &str,
    scope: &Scope,
    not_after: u64,
    nonce: u64,
) -> Result<String> {
    let caveats = Caveats {
        not_after,
        path_prefix: Some(scope.to_caveat()),
        ..Default::default()
    };
    let cap = SignedCapability::issue(
        owner,
        audience,
        vec![ability.to_string()],
        Resource::Node(owner.node_id()),
        caveats,
        nonce,
        None,
    );
    Ok(ce_cap::encode_chain(&[cap]))
}

/// Decode a link token back into its chain, returning the leaf capability's scope and abilities for
/// inspection. Does not verify the signature/expiry — call [`verify_link`] for that.
pub fn inspect_link(token: &str) -> Result<(Vec<String>, Scope)> {
    let chain = ce_cap::decode_chain(token).context("decoding capability link")?;
    let leaf = chain.last().context("empty capability chain")?;
    let scope = leaf
        .cap
        .caveats
        .path_prefix
        .as_deref()
        .map(Scope::from_caveat)
        .unwrap_or(Scope {
            bucket: String::new(),
            prefix: String::new(),
        });
    Ok((leaf.cap.abilities.clone(), scope))
}

/// Verify a presented link against a serving node's identity for an `ability` on `bucket/key`.
///
/// Runs the full `ce-cap` chain check (signature, attenuation, temporal caveats, revocation) rooted
/// at `self_id` (or `accepted_roots`), then enforces the app-level `path_prefix` scope caveat. The
/// requester is the leaf audience. `now` is unix seconds; `is_revoked` consults the on-chain set.
#[allow(clippy::too_many_arguments)]
pub fn verify_link(
    self_id: &NodeId,
    accepted_roots: &[NodeId],
    self_tags: &[String],
    now: u64,
    requester: &NodeId,
    ability: &str,
    bucket: &str,
    key: &str,
    token: &str,
    is_revoked: &dyn Fn(&NodeId, u64) -> bool,
) -> Result<(), String> {
    let chain = ce_cap::decode_chain(token).map_err(|e| e.to_string())?;
    // ce-cap enforces signatures, attenuation, expiry, revocation, and that the leaf grants `ability`.
    ce_cap::authorize(
        self_id,
        accepted_roots,
        self_tags,
        now,
        requester,
        ability,
        &chain,
        is_revoked,
    )?;
    // App-level: the path_prefix caveat must cover the requested bucket/key.
    let leaf = chain.last().ok_or_else(|| "empty chain".to_string())?;
    let scope = leaf
        .cap
        .caveats
        .path_prefix
        .as_deref()
        .map(Scope::from_caveat)
        .ok_or_else(|| "link has no bucket/prefix scope".to_string())?;
    if !scope_allows(&scope, bucket, key) {
        return Err(format!(
            "link scope {}/{} does not cover {bucket}/{key}",
            scope.bucket, scope.prefix
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ce_identity::Identity;

    fn ident(seed: &str) -> Identity {
        let dir =
            std::env::temp_dir().join(format!("ce-storage-cap-{}-{}", seed, std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let id = Identity::load_or_generate(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        id
    }

    fn never_revoked(_: &NodeId, _: u64) -> bool {
        false
    }

    #[test]
    fn scope_roundtrip_and_allows() {
        let s = Scope {
            bucket: "photos".into(),
            prefix: "2026/".into(),
        };
        assert_eq!(s.to_caveat(), "photos/2026/");
        assert_eq!(Scope::from_caveat("photos/2026/"), s);
        assert!(scope_allows(&s, "photos", "2026/a.jpg"));
        assert!(!scope_allows(&s, "photos", "2025/a.jpg"));
        assert!(!scope_allows(&s, "docs", "2026/a.jpg"));
    }

    #[test]
    fn scope_enforces_path_boundary() {
        // Regression for H4: a `photos` scope must NOT leak into a sibling bucket-key namespace
        // like `photos-secret/`. The old `starts_with` check allowed this; the boundary-aware
        // check denies it while still covering `photos/a` and the bare `photos` key.
        let s = Scope {
            bucket: "b".into(),
            prefix: "photos".into(),
        };
        // The hole: `photos-secret/x` starts with `photos` but is a different path segment.
        assert!(
            !scope_allows(&s, "b", "photos-secret/x"),
            "scope `photos` must not grant `photos-secret/x`"
        );
        // Still allows keys genuinely under (or equal to) the prefix.
        assert!(
            scope_allows(&s, "b", "photos/a"),
            "scope `photos` must grant `photos/a`"
        );
        assert!(
            scope_allows(&s, "b", "photos"),
            "scope `photos` must grant bare `photos`"
        );
        // Trailing-slash normalization: `photos/` behaves identically to `photos`.
        let s_slash = Scope {
            bucket: "b".into(),
            prefix: "photos/".into(),
        };
        assert!(!scope_allows(&s_slash, "b", "photos-secret/x"));
        assert!(scope_allows(&s_slash, "b", "photos/a"));
        assert!(scope_allows(&s_slash, "b", "photos"));
        // Empty prefix covers the whole bucket.
        let s_all = Scope {
            bucket: "b".into(),
            prefix: String::new(),
        };
        assert!(scope_allows(&s_all, "b", "anything/at/all"));
    }

    #[test]
    fn mint_and_verify_read_link() {
        let owner = ident("owner");
        let scope = Scope {
            bucket: "photos".into(),
            prefix: "2026/".into(),
        };
        let token = mint_link(&owner, owner.node_id(), ABILITY_READ, &scope, 0, 1).unwrap();

        // owner is the requester (bearer) and the serving node.
        let r = verify_link(
            &owner.node_id(),
            &[],
            &[],
            1000,
            &owner.node_id(),
            ABILITY_READ,
            "photos",
            "2026/sunset.jpg",
            &token,
            &never_revoked,
        );
        assert!(r.is_ok(), "valid link should verify: {r:?}");
    }

    #[test]
    fn link_rejects_out_of_scope_key() {
        let owner = ident("owner2");
        let scope = Scope {
            bucket: "photos".into(),
            prefix: "2026/".into(),
        };
        let token = mint_link(&owner, owner.node_id(), ABILITY_READ, &scope, 0, 2).unwrap();
        let r = verify_link(
            &owner.node_id(),
            &[],
            &[],
            1000,
            &owner.node_id(),
            ABILITY_READ,
            "photos",
            "2025/private.jpg",
            &token,
            &never_revoked,
        );
        assert!(r.is_err(), "out-of-scope key must be rejected");
    }

    #[test]
    fn link_rejects_wrong_ability() {
        let owner = ident("owner3");
        let scope = Scope {
            bucket: "b".into(),
            prefix: String::new(),
        };
        let token = mint_link(&owner, owner.node_id(), ABILITY_READ, &scope, 0, 3).unwrap();
        let r = verify_link(
            &owner.node_id(),
            &[],
            &[],
            1000,
            &owner.node_id(),
            ABILITY_WRITE, // asked for write, link only grants read
            "b",
            "k",
            &token,
            &never_revoked,
        );
        assert!(r.is_err(), "wrong ability must be rejected");
    }

    #[test]
    fn link_rejects_expired() {
        let owner = ident("owner4");
        let scope = Scope {
            bucket: "b".into(),
            prefix: String::new(),
        };
        // not_after = 500
        let token = mint_link(&owner, owner.node_id(), ABILITY_READ, &scope, 500, 4).unwrap();
        let r = verify_link(
            &owner.node_id(),
            &[],
            &[],
            1000, // now > not_after
            &owner.node_id(),
            ABILITY_READ,
            "b",
            "k",
            &token,
            &never_revoked,
        );
        assert!(r.is_err(), "expired link must be rejected");
    }

    #[test]
    fn parse_node_id_roundtrips_and_rejects_bad() {
        let owner = ident("nid");
        let hex = owner.node_id_hex();
        assert_eq!(parse_node_id(&hex).unwrap(), owner.node_id());
        assert!(parse_node_id("not-hex").is_err());
        assert!(parse_node_id("deadbeef").is_err(), "wrong length rejected");
        assert!(
            parse_node_id(&format!("  {hex}  ")).is_ok(),
            "whitespace trimmed"
        );
    }

    #[test]
    fn inspect_reports_scope() {
        let owner = ident("owner5");
        let scope = Scope {
            bucket: "data".into(),
            prefix: "logs/".into(),
        };
        let token = mint_link(&owner, owner.node_id(), ABILITY_READ, &scope, 0, 5).unwrap();
        let (abilities, got) = inspect_link(&token).unwrap();
        assert_eq!(abilities, vec![ABILITY_READ.to_string()]);
        assert_eq!(got, scope);
    }
}
