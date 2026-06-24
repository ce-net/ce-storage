//! End-to-end **presign → verify** demo: mint a `ce-cap` access link scoped to a bucket/prefix and
//! verify it offline exactly the way the gateway's [`Auth`](ce_storage::gateway) enforcement does —
//! no node, no policy server, pure crypto.
//!
//! Run with: `cargo run --example presign_verify`
//!
//! This is the auth flow the README describes: the bucket owner mints a scoped, time-bounded link;
//! a holder presents it; any serving node verifies the signature/expiry/scope in microseconds.

use ce_storage::caps::{ABILITY_READ, Scope, mint_link, verify_link};

fn main() -> anyhow::Result<()> {
    // The bucket owner's identity is the trust root for links it mints. (In a real deployment this
    // is loaded from the CE data dir; here we generate an ephemeral one in a temp dir.)
    let dir = std::env::temp_dir().join(format!("ce-storage-example-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let owner = ce_identity::Identity::load_or_generate(&dir)?;
    let _ = std::fs::remove_dir_all(&dir);

    // Mint a READ link scoped to photos/2026/, valid forever (not_after = 0), nonce 1.
    let scope = Scope {
        bucket: "photos".into(),
        prefix: "2026/".into(),
    };
    let token = mint_link(&owner, owner.node_id(), ABILITY_READ, &scope, 0, 1)?;
    println!("minted link token ({} hex chars):\n{token}\n", token.len());

    // A serving node verifies the presented link offline. `now` is unix seconds; the owner is both
    // the serving node and the bearer here for a self-issued open link. `is_revoked` consults the
    // on-chain revocation set (none here).
    let never_revoked = |_: &ce_identity::NodeId, _: u64| false;
    let now = 1_000_000;

    // In scope: read photos/2026/sunset.jpg → authorized.
    let ok = verify_link(
        &owner.node_id(),
        &[],
        &[],
        now,
        &owner.node_id(),
        ABILITY_READ,
        "photos",
        "2026/sunset.jpg",
        &token,
        &never_revoked,
    );
    println!("read photos/2026/sunset.jpg : {}", describe(&ok));
    assert!(ok.is_ok());

    // Out of prefix: read photos/2025/private.jpg → denied.
    let denied = verify_link(
        &owner.node_id(),
        &[],
        &[],
        now,
        &owner.node_id(),
        ABILITY_READ,
        "photos",
        "2025/private.jpg",
        &token,
        &never_revoked,
    );
    println!("read photos/2025/private.jpg: {}", describe(&denied));
    assert!(denied.is_err());

    // Wrong bucket → denied.
    let wrong_bucket = verify_link(
        &owner.node_id(),
        &[],
        &[],
        now,
        &owner.node_id(),
        ABILITY_READ,
        "documents",
        "2026/sunset.jpg",
        &token,
        &never_revoked,
    );
    println!(
        "read documents/2026/sunset.jpg: {}",
        describe(&wrong_bucket)
    );
    assert!(wrong_bucket.is_err());

    println!("\nAll assertions held: the link grants exactly photos/2026/* read, nothing else.");
    Ok(())
}

fn describe(r: &Result<(), String>) -> String {
    match r {
        Ok(()) => "AUTHORIZED".to_string(),
        Err(e) => format!("DENIED ({e})"),
    }
}
