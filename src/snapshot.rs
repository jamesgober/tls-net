//! A versioned, read-mostly configuration cell (PLAN 6.7): a reload builds
//! the new value completely, then swaps it in one step. Readers see the old
//! value or the new one in full, never a mix; the old value is freed when the
//! last session holding it drops.

use std::sync::Arc;

use crate::sync::{AtomicU64, Mutex, Ordering, Shared};

/// The shared cell.
#[derive(Debug)]
pub(crate) struct Snapshot<T> {
    version: AtomicU64,
    current: Mutex<Shared<T>>,
}

impl<T> Snapshot<T> {
    pub(crate) fn new(value: T) -> Self {
        Snapshot {
            version: AtomicU64::new(1),
            current: Mutex::new(Shared::new(value)),
        }
    }

    /// The current value: one uncontended lock and an `Arc` clone.
    pub(crate) fn load(&self) -> Shared<T> {
        let guard = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Shared::clone(&guard)
    }

    /// The current value and its version, read together under the lock.
    fn load_versioned(&self) -> (u64, Shared<T>) {
        let guard = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (self.version.load(Ordering::Acquire), Shared::clone(&guard))
    }

    /// The current version (1 for the first value).
    pub(crate) fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// Replaces the value; returns the new version.
    pub(crate) fn publish(&self, value: T) -> u64 {
        let next = Shared::new(value);
        let mut guard = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = next;
        // Bumped while the lock is held, so a reader that sees the new version
        // and then locks always finds the new value.
        self.version.fetch_add(1, Ordering::AcqRel) + 1
    }
}

/// A per-worker reader: one atomic load per read, a lock only after a publish.
#[derive(Debug)]
pub(crate) struct Reader<T> {
    snapshot: Arc<Snapshot<T>>,
    version: u64,
    cached: Shared<T>,
}

impl<T> Reader<T> {
    pub(crate) fn new(snapshot: Arc<Snapshot<T>>) -> Self {
        let (version, cached) = snapshot.load_versioned();
        Reader {
            snapshot,
            version,
            cached,
        }
    }

    /// The current value.
    pub(crate) fn get(&mut self) -> &Shared<T> {
        if self.snapshot.version() != self.version {
            (self.version, self.cached) = self.snapshot.load_versioned();
        }
        &self.cached
    }
}

#[cfg(all(test, not(tls_net_loom)))]
mod tests {
    use super::*;

    #[test]
    fn test_publish_bumps_version_and_readers_follow() {
        let snap = Arc::new(Snapshot::new(1u32));
        let mut r = Reader::new(Arc::clone(&snap));
        assert_eq!(**r.get(), 1);
        let held = snap.load();
        assert_eq!(snap.publish(2), 2);
        assert_eq!(**r.get(), 2);
        assert_eq!(*held, 1, "a holder of the old value keeps it");
        assert_eq!(snap.version(), 2);
    }

    #[test]
    fn test_old_value_freed_when_last_holder_drops() {
        let snap = Snapshot::new(vec![0u8; 16]);
        let old = snap.load();
        let weak = Arc::downgrade(&old);
        snap.publish(vec![1u8; 16]);
        assert!(weak.upgrade().is_some());
        drop(old);
        assert!(weak.upgrade().is_none());
    }
}

#[cfg(all(test, tls_net_loom))]
mod loom_tests {
    use super::*;

    /// A reader sees the old value or the new one in full; a reader that has
    /// seen the new version never sees the old value again.
    #[test]
    fn loom_publish_and_read_never_torn() {
        loom::model(|| {
            let snap = std::sync::Arc::new(Snapshot::new((1u32, 1u32)));
            let writer = {
                let snap = std::sync::Arc::clone(&snap);
                loom::thread::spawn(move || {
                    snap.publish((2, 2));
                })
            };
            let mut r = Reader::new(std::sync::Arc::clone(&snap));
            let a = **r.get();
            assert!(a == (1, 1) || a == (2, 2));
            let b = **r.get();
            assert!(b == (1, 1) || b == (2, 2));
            if a == (2, 2) {
                assert_eq!(b, (2, 2));
            }
            writer.join().unwrap();
            assert_eq!(**r.get(), (2, 2));
        });
    }
}
