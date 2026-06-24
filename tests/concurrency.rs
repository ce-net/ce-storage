//! Concurrency / lost-update tests for the cross-process index lock.
//!
//! The bucket index is a single-writer JSON file. Two `Store` instances (e.g. a CLI invocation while
//! the gateway runs) each `load → mutate → save`; without locking the last writer silently clobbers
//! the other's writes. [`ce_storage::lock::FileLock`] serialises those mutations. These tests drive
//! many independent `Store` handles (each reloading from disk under the lock) against ONE index file
//! from multiple threads and assert **every** write survives — the lost-update the audit flagged.
//!
//! These need no CE node: they exercise only the node-free, index-mutating verbs
//! (`make_bucket` / `delete_object`), which is exactly where the concurrency hazard lives. Seeding
//! uses the public [`ce_storage::index::Index`] API written straight to the index file.

use ce_storage::index::{Index, ObjectMeta};
use ce_storage::store::Store;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};

fn shared_index(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "ce-storage-conc-{}-{}-{tag}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(format!("{}.lock", p.display()));
    p
}

/// N threads, each with its own `Store` over the SAME file, create distinct buckets concurrently.
/// With the lock, all N buckets exist at the end (no lost update). Without it, some would vanish.
#[test]
fn concurrent_make_bucket_no_lost_update() {
    let path = shared_index("mb");
    const N: usize = 16;
    let barrier = Arc::new(Barrier::new(N));
    let mut handles = Vec::new();
    for i in 0..N {
        let path = path.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let mut store = Store::open(path).expect("open");
            barrier.wait(); // maximise contention: everyone hits the lock at once
            store
                .make_bucket(&format!("bucket-{i:03}"))
                .expect("make_bucket");
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }
    // Re-open and assert all N survived.
    let store = Store::open(path.clone()).unwrap();
    let buckets = store.list_buckets();
    assert_eq!(
        buckets.len(),
        N,
        "every concurrent make_bucket must survive: {buckets:?}"
    );
    for i in 0..N {
        assert!(buckets.contains(&format!("bucket-{i:03}")));
    }
    let _ = std::fs::remove_file(&path);
}

/// Concurrent deletes of distinct keys from a shared bucket: all deletes land, the untouched keys
/// remain. Interleaved load-modify-save under the lock must not drop a deletion or resurrect a key.
#[test]
fn concurrent_deletes_all_land() {
    let path = shared_index("del");
    // Seed one bucket with many keys via the public Index API, written straight to the file.
    {
        let mut idx = Index::default();
        idx.make_bucket("buk", 1).unwrap();
        for i in 0..32 {
            idx.put(
                "buk",
                &format!("k{i:02}"),
                ObjectMeta::new(format!("cid{i}"), 1, "x", 1),
            )
            .unwrap();
        }
        idx.save(&path).unwrap();
    }
    const N: usize = 30; // delete k00..k29, leave k30,k31
    let barrier = Arc::new(Barrier::new(N));
    let mut handles = Vec::new();
    for i in 0..N {
        let path = path.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let mut store = Store::open(path).expect("open");
            barrier.wait();
            store
                .delete_object("buk", &format!("k{i:02}"))
                .expect("delete");
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }
    let store = Store::open(path.clone()).unwrap();
    let page = store.list_objects("buk", "", None, None, 1000).unwrap();
    let remaining: Vec<_> = page.keys.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(
        remaining,
        vec!["k30".to_string(), "k31".to_string()],
        "exactly the untouched keys remain"
    );
    let _ = std::fs::remove_file(&path);
}
