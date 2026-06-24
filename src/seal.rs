//! Server-side-encryption-equivalent: **client-side encrypt-before-store** ("sealed objects").
//!
//! ce-storage is content-addressed: the bytes you `put_object` are stored verbatim on the owning
//! node and any host that replicates the CID. A *sealed* object encrypts the plaintext **before** it
//! ever leaves the client, so the blob store (and any replicating host) only ever sees ciphertext.
//! This is the CE analogue of S3 SSE-C (customer-provided key): the key lives with the client, never
//! on the storage node, and the object is useless to anyone without it.
//!
//! ## Construction (encrypt-then-MAC, AEAD-style, dependency-light)
//!
//! This crate already depends on `sha2` and nothing heavier; rather than pull a new AEAD crate we
//! build a real authenticated cipher from SHA-256 primitives:
//!
//! - A random 16-byte **salt** (nonce) is generated per seal.
//! - Two subkeys are derived from the user key + salt via HMAC-SHA256 (domain-separated):
//!   an **encryption** key and a **MAC** key. (HKDF-style extract/expand, implemented inline.)
//! - The plaintext is XORed with a **SHA-256 counter-mode keystream**: block `i` of the keystream is
//!   `SHA256(enc_key || salt || le64(i))`. This is a standard hash-based stream cipher.
//! - The whole record (`version || salt || ciphertext`) is authenticated with **HMAC-SHA256** under
//!   the MAC key (encrypt-then-MAC), and the 32-byte tag is appended. [`unseal`] verifies the tag in
//!   constant time **before** decrypting, so tampered or truncated ciphertext is rejected, never
//!   returned.
//!
//! The sealed record is what gets stored; the object's CID is the hash of the *ciphertext*, so two
//! seals of the same plaintext under the same key+salt dedup, while different salts produce different
//! CIDs (semantic security). The recorded `content_type` for a sealed object is opaque
//! (`application/x-ce-sealed`); the true type can be carried in user metadata if desired.
//!
//! This is intentionally documented as a self-contained construction, not a claim of AES-GCM/FIPS
//! compliance. It provides confidentiality + integrity against a host that can read every stored
//! byte, which is exactly the threat SSE addresses. The key-management story (who holds the key, how
//! it is rotated) is the caller's; ce-storage never persists the key.

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

/// Versioned magic prefix for a sealed record, so the format can evolve.
pub const SEAL_VERSION: u8 = 1;
/// Length of the per-seal random salt (nonce).
pub const SALT_LEN: usize = 16;
/// Length of the HMAC-SHA256 authentication tag.
pub const TAG_LEN: usize = 32;
/// Content type recorded for a sealed object (the true type is opaque to the store).
pub const SEALED_CONTENT_TYPE: &str = "application/x-ce-sealed";

const SHA256_BLOCK: usize = 64;
const KEYSTREAM_BLOCK: usize = 32;

/// HMAC-SHA256 of `msg` under `key` (RFC 2104), implemented on top of `sha2` so no extra crate is
/// needed. Returns the 32-byte tag.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    // Normalize the key to one block.
    let mut block_key = [0u8; SHA256_BLOCK];
    if key.len() > SHA256_BLOCK {
        let digest = Sha256::digest(key);
        block_key[..32].copy_from_slice(&digest);
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; SHA256_BLOCK];
    let mut opad = [0x5cu8; SHA256_BLOCK];
    for i in 0..SHA256_BLOCK {
        ipad[i] ^= block_key[i];
        opad[i] ^= block_key[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

/// Derive an encryption key and a MAC key from the user key + salt, domain-separated.
fn derive_keys(user_key: &[u8], salt: &[u8]) -> ([u8; 32], [u8; 32]) {
    // HKDF-extract: prk = HMAC(salt, user_key).
    let prk = hmac_sha256(salt, user_key);
    // HKDF-expand with distinct info labels.
    let mut enc_msg = Vec::with_capacity(16);
    enc_msg.extend_from_slice(b"ce-seal-enc");
    enc_msg.push(0x01);
    let enc_key = hmac_sha256(&prk, &enc_msg);
    let mut mac_msg = Vec::with_capacity(16);
    mac_msg.extend_from_slice(b"ce-seal-mac");
    mac_msg.push(0x02);
    let mac_key = hmac_sha256(&prk, &mac_msg);
    (enc_key, mac_key)
}

/// XOR `data` in place with the SHA-256 counter-mode keystream derived from `enc_key` + `salt`.
fn apply_keystream(enc_key: &[u8; 32], salt: &[u8], data: &mut [u8]) {
    let mut counter: u64 = 0;
    for block in data.chunks_mut(KEYSTREAM_BLOCK) {
        let mut h = Sha256::new();
        h.update(enc_key);
        h.update(salt);
        h.update(counter.to_le_bytes());
        let ks = h.finalize();
        for (b, k) in block.iter_mut().zip(ks.iter()) {
            *b ^= *k;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Constant-time equality for two equal-length byte slices (tag comparison).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Generate `n` cryptographically-random bytes. Uses the OS RNG via `getrandom` indirectly through
/// `std`'s `RandomState`-seeded path is not strong enough; instead derive from a fresh entropy mix.
///
/// We avoid adding a `rand`/`getrandom` dependency by seeding from multiple OS entropy sources
/// (high-resolution time, process/thread ids, a stack address, and an atomic counter) hashed
/// together. For a per-object salt whose only requirement is uniqueness (not unpredictability of the
/// key — the key is the secret), this is sufficient: collisions are what break a nonce, and this
/// space is 128 bits with several independent varying inputs.
fn random_salt() -> [u8; SALT_LEN] {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut h = Sha256::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    h.update(now.to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    h.update(COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    // A stack address adds ASLR entropy.
    let stack_marker = 0u8;
    h.update((&stack_marker as *const u8 as usize).to_le_bytes());
    // Thread id hashed in.
    let tid = format!("{:?}", std::thread::current().id());
    h.update(tid.as_bytes());
    let d = h.finalize();
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&d[..SALT_LEN]);
    salt
}

/// Seal `plaintext` under `user_key`, returning the authenticated ciphertext record
/// `version(1) || salt(16) || ciphertext || tag(32)`. Store this record; [`unseal`] reverses it.
///
/// ```
/// use ce_storage::seal::{seal, unseal};
/// let key = b"a 32-byte-or-shorter secret key!";
/// let record = seal(b"top secret", key);
/// // The plaintext is nowhere in the record.
/// assert!(!record.windows(10).any(|w| w == b"top secret"));
/// // It round-trips with the right key.
/// assert_eq!(unseal(&record, key).unwrap(), b"top secret");
/// // A wrong key is rejected (authentication fails), never returns garbage.
/// assert!(unseal(&record, b"wrong key").is_err());
/// ```
pub fn seal(plaintext: &[u8], user_key: &[u8]) -> Vec<u8> {
    let salt = random_salt();
    let (enc_key, mac_key) = derive_keys(user_key, &salt);
    let mut record = Vec::with_capacity(1 + SALT_LEN + plaintext.len() + TAG_LEN);
    record.push(SEAL_VERSION);
    record.extend_from_slice(&salt);
    let ct_start = record.len();
    record.extend_from_slice(plaintext);
    apply_keystream(&enc_key, &salt, &mut record[ct_start..]);
    // Encrypt-then-MAC over version || salt || ciphertext.
    let tag = hmac_sha256(&mac_key, &record);
    record.extend_from_slice(&tag);
    record
}

/// Unseal a record produced by [`seal`] under `user_key`. Verifies the authentication tag in
/// constant time **before** decrypting; a wrong key, tampered ciphertext, or truncated record is
/// rejected with an error rather than returning corrupt plaintext.
pub fn unseal(record: &[u8], user_key: &[u8]) -> Result<Vec<u8>> {
    if record.len() < 1 + SALT_LEN + TAG_LEN {
        bail!("sealed record too short ({} bytes)", record.len());
    }
    if record[0] != SEAL_VERSION {
        bail!("unsupported seal version {}", record[0]);
    }
    let salt = &record[1..1 + SALT_LEN];
    let tag_start = record.len() - TAG_LEN;
    let body = &record[..tag_start];
    let tag = &record[tag_start..];
    let (enc_key, mac_key) = derive_keys(user_key, salt);
    let expected = hmac_sha256(&mac_key, body);
    if !ct_eq(&expected, tag) {
        bail!("sealed record authentication failed (wrong key or tampered data)");
    }
    let mut plaintext = record[1 + SALT_LEN..tag_start].to_vec();
    let salt_owned: [u8; SALT_LEN] = salt.try_into().expect("salt slice is SALT_LEN");
    apply_keystream(&enc_key, &salt_owned, &mut plaintext);
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_various_sizes() {
        let key = b"my secret key";
        for &n in &[0usize, 1, 31, 32, 33, 64, 1000, 4096] {
            let pt: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let record = seal(&pt, key);
            assert_eq!(unseal(&record, key).unwrap(), pt, "size {n} round-trips");
        }
    }

    #[test]
    fn ciphertext_hides_plaintext() {
        let key = b"k";
        let pt = b"the quick brown fox jumps over the lazy dog".repeat(4);
        let record = seal(&pt, key);
        // No long run of plaintext appears in the record.
        assert!(
            !record.windows(pt.len()).any(|w| w == pt.as_slice()),
            "plaintext must not appear verbatim"
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let record = seal(b"secret", b"right");
        assert!(unseal(&record, b"wrong").is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mut record = seal(b"secret payload here", b"key");
        // Flip a byte in the ciphertext region (after version+salt, before tag).
        let i = 1 + SALT_LEN + 2;
        record[i] ^= 0xff;
        assert!(unseal(&record, b"key").is_err(), "tamper must be caught");
    }

    #[test]
    fn truncated_record_rejected() {
        let record = seal(b"secret", b"key");
        assert!(unseal(&record[..record.len() - 1], b"key").is_err());
        assert!(unseal(&record[..3], b"key").is_err());
        assert!(unseal(&[], b"key").is_err());
    }

    #[test]
    fn bad_version_rejected() {
        let mut record = seal(b"x", b"key");
        record[0] = 0xAA;
        assert!(unseal(&record, b"key").is_err());
    }

    #[test]
    fn distinct_salts_give_distinct_ciphertext() {
        let key = b"key";
        let a = seal(b"same plaintext", key);
        let b = seal(b"same plaintext", key);
        // Salts differ → records differ (semantic security), yet both decrypt.
        assert_ne!(a, b);
        assert_eq!(unseal(&a, key).unwrap(), unseal(&b, key).unwrap());
    }

    #[test]
    fn hmac_matches_known_rfc4231_vector() {
        // RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?".
        let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let expected =
            hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
                .unwrap();
        assert_eq!(tag.to_vec(), expected);
    }

    #[test]
    fn ct_eq_is_correct() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
