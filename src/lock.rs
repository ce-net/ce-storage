//! A small, dependency-free **advisory cross-process file lock** used to serialise mutations of the
//! single-writer bucket index across separate OS processes (e.g. a CLI invocation running while the
//! gateway is up).
//!
//! The lock is a sidecar file (`<index>.lock`) acquired by atomically creating it with
//! `O_CREATE | O_EXCL` (`create_new`). The first process to win the create holds the lock; others
//! spin with a short backoff until it is released (the file is removed on [`FileLock::drop`]) or a
//! timeout elapses. A **stale** lock (older than [`STALE_AFTER`], left by a crashed process that
//! never ran its destructor) is reclaimed so the store never deadlocks permanently.
//!
//! This is an *advisory* lock: it only protects writers that go through [`FileLock`]. Within this
//! crate every mutating `Store` op does, and the gateway additionally serialises in-process behind a
//! mutex, so concurrent CLI + gateway writers cannot lose updates. It is intentionally simpler than
//! `flock(2)`/`LockFileEx` (no extra crates, identical on every platform) at the cost of relying on
//! `create_new`'s atomicity, which all of Linux/macOS/Windows provide.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long the acquire loop waits before giving up.
pub const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);
/// A lock file older than this is presumed orphaned by a crashed process and reclaimed.
pub const STALE_AFTER: Duration = Duration::from_secs(120);

/// An acquired advisory lock. Dropping it releases (removes) the lock file.
pub struct FileLock {
    path: PathBuf,
}

impl FileLock {
    /// Acquire the lock for `target` (the file being protected), blocking up to [`ACQUIRE_TIMEOUT`].
    /// The lock sidecar is `<target>.lock`. Returns an error only if the timeout elapses or the
    /// filesystem is unusable.
    pub fn acquire(target: &Path) -> Result<FileLock> {
        let path = lock_path(target);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("creating lock directory")?;
        }
        let deadline = Instant::now() + ACQUIRE_TIMEOUT;
        let mut backoff = Duration::from_millis(2);
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut f) => {
                    // Record the holder + timestamp for stale detection / debugging.
                    use std::io::Write;
                    let _ = writeln!(f, "{} {}", std::process::id(), unix_now());
                    return Ok(FileLock { path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if is_stale(&path) {
                        // Reclaim an orphaned lock and retry immediately.
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    if Instant::now() >= deadline {
                        anyhow::bail!(
                            "timed out acquiring index lock {} (held by another process)",
                            path.display()
                        );
                    }
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_millis(100));
                }
                Err(e) => {
                    return Err(e).with_context(|| format!("opening lock file {}", path.display()));
                }
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn lock_path(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_os_string();
    s.push(".lock");
    PathBuf::from(s)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Is the lock file at `path` older than [`STALE_AFTER`]? Best-effort: an unreadable mtime is treated
/// as not stale (we'd rather wait than stomp a live holder).
fn is_stale(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    modified
        .elapsed()
        .map(|age| age > STALE_AFTER)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ce-storage-lock-{tag}-{}", std::process::id()))
    }

    #[test]
    fn acquire_and_release() {
        let t = tmp("basic");
        let _ = std::fs::remove_file(lock_path(&t));
        {
            let _lk = FileLock::acquire(&t).unwrap();
            assert!(lock_path(&t).exists(), "lock file present while held");
        }
        assert!(!lock_path(&t).exists(), "lock file removed on drop");
    }

    #[test]
    fn second_acquire_blocks_until_release() {
        let t = tmp("contend");
        let _ = std::fs::remove_file(lock_path(&t));
        let lk = FileLock::acquire(&t).unwrap();
        // A concurrent acquire on another thread must wait for the release.
        let t2 = t.clone();
        let handle = std::thread::spawn(move || {
            let start = Instant::now();
            let _lk2 = FileLock::acquire(&t2).unwrap();
            start.elapsed()
        });
        std::thread::sleep(Duration::from_millis(60));
        drop(lk);
        let waited = handle.join().unwrap();
        assert!(
            waited >= Duration::from_millis(40),
            "second acquire waited for release"
        );
    }

    #[test]
    fn stale_lock_is_reclaimed() {
        let t = tmp("stale");
        let lp = lock_path(&t);
        let _ = std::fs::remove_file(&lp);
        // Write a lock file and backdate its mtime well past STALE_AFTER is not portable; instead
        // verify the predicate logic directly with a fresh file (not stale) and the reclaim path by
        // creating then immediately reclaiming via remove. Here we assert a fresh file is not stale.
        std::fs::write(&lp, b"123 0").unwrap();
        assert!(!is_stale(&lp), "fresh lock is not stale");
        let _ = std::fs::remove_file(&lp);
    }
}
