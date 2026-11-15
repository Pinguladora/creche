//! What the host makes of an observer's claim that it guards its vsock port
//! (ADR 0015). The claim arrives in the guest's own hello record, so on its own
//! it proves nothing: where the port is not guarded, any guest process can
//! connect and claim it is. The sink holds each claim against two things it
//! sees for itself, across all of a sandbox's streams (ADR 0019).
//!
//! - Whether the port is guarded is fixed for the life of a VM, by its kernel.
//!   The observer starts before anything else in the guest, so the first hello
//!   of a sandbox is the observer's. A later stream counts as guarded only when
//!   that first hello claimed so too.
//! - A guarded port lets only the observer connect, and the observer keeps one
//!   connection: it opens another only once the last one broke. A stream that
//!   still sends well after a newer stream of the same sandbox said hello shows
//!   two senders at once, so the port is not guarded. From then on no stream of
//!   the sandbox counts as guarded. What an observer wrote just before it
//!   exited may still be read after its successor's hello, so sends within
//!   [`STALE_NS`] of the first newer hello do not count. Each open stream keeps
//!   when that was, so neither more hellos nor more connections put it off.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

/// How long after a newer stream's hello an older stream may still deliver
/// what it was sent before, in nanoseconds.
pub const STALE_NS: u64 = 2_000_000_000;

/// The guard evidence of one sandbox, shared by its streams.
#[derive(Debug, Default)]
pub struct Guard {
    /// What the sandbox's first hello claimed.
    first: OnceLock<bool>,
    /// The next stream's number.
    next: AtomicU64,
    /// The open streams by number, each with when a newer stream first said
    /// hello, on the host clock. Only open streams, so it stays small.
    open: Mutex<HashMap<u64, Option<u64>>>,
    /// Whether two streams were seen sending at once.
    breached: AtomicBool,
}

impl Guard {
    /// A new stream of the sandbox. It counts as open until the handle drops.
    pub fn open(guard: &Arc<Self>) -> Handle {
        let stream = guard.next.fetch_add(1, Ordering::SeqCst);
        guard.streams().insert(stream, None);
        Handle {
            guard: Arc::clone(guard),
            stream,
        }
    }

    fn streams(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Option<u64>>> {
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether two streams of the sandbox were seen sending at once.
    #[must_use]
    pub fn breached(&self) -> bool {
        self.breached.load(Ordering::SeqCst)
    }
}

/// One stream's place in its sandbox's guard evidence.
#[derive(Debug)]
pub struct Handle {
    guard: Arc<Guard>,
    stream: u64,
}

impl Handle {
    /// The stream said hello at `now_ns`, claiming the port is guarded or not.
    /// Returns whether the sink takes it as guarded: it claims so, the
    /// sandbox's first hello claimed so, and no two streams sent at once.
    #[must_use]
    pub fn hello(&self, claimed: bool, now_ns: u64) -> bool {
        let first = *self.guard.first.get_or_init(|| claimed);
        for (_, seen) in self
            .guard
            .streams()
            .iter_mut()
            .filter(|(older, _)| **older < self.stream)
        {
            seen.get_or_insert(now_ns);
        }
        claimed && first && !self.guard.breached()
    }

    /// The stream sent records at `now_ns`. Returns whether two streams of the
    /// sandbox have now been seen sending at once: a newer stream said hello
    /// more than [`STALE_NS`] before.
    #[must_use]
    pub fn sent(&self, now_ns: u64) -> bool {
        let seen = self.guard.streams().get(&self.stream).copied().flatten();
        if seen.is_some_and(|at| now_ns.saturating_sub(at) > STALE_NS) {
            self.guard.breached.store(true, Ordering::SeqCst);
        }
        self.guard.breached()
    }

    /// Whether two streams of the sandbox were seen sending at once.
    #[must_use]
    pub fn breached(&self) -> bool {
        self.guard.breached()
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.guard.streams().remove(&self.stream);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Late enough after a newer hello to be a second sender.
    const LATE: u64 = STALE_NS + 1;

    #[test]
    fn the_first_hello_decides_what_later_ones_may_claim() {
        let guard = Arc::default();
        let (a, b) = (Guard::open(&guard), Guard::open(&guard));
        assert!(!a.hello(false, 0));
        // A later claim of a guard the first hello did not have is not taken.
        assert!(!b.hello(true, 0));
        let guard = Arc::default();
        let (a, b) = (Guard::open(&guard), Guard::open(&guard));
        assert!(a.hello(true, 0));
        assert!(b.hello(true, 0));
        assert!(!b.hello(false, 0));
    }

    #[test]
    fn a_restarted_observer_is_one_sender() {
        let guard = Arc::default();
        let old = Guard::open(&guard);
        assert!(old.hello(true, 0));
        assert!(!old.sent(1));
        let new = Guard::open(&guard);
        assert!(new.hello(true, 10));
        // What the old observer wrote before it exited is still read.
        assert!(!old.sent(10 + STALE_NS));
        drop(old);
        assert!(!new.sent(10 + LATE));
        assert!(!guard.breached());
    }

    #[test]
    fn an_older_stream_sending_well_after_a_newer_hello_is_a_second_sender() {
        let guard = Arc::default();
        let observer = Guard::open(&guard);
        assert!(observer.hello(true, 0));
        let intruder = Guard::open(&guard);
        assert!(intruder.hello(true, 0));
        assert!(!intruder.sent(LATE));
        // The observer still sends: two senders.
        assert!(observer.sent(LATE));
        assert!(intruder.sent(LATE));
        assert!(!Guard::open(&guard).hello(true, LATE));
    }

    #[test]
    fn more_hellos_and_connections_do_not_put_off_the_verdict() {
        let guard = Arc::default();
        let observer = Guard::open(&guard);
        assert!(observer.hello(true, 0));
        // An intruder saying hello again and again, and reconnecting.
        let intruder = Guard::open(&guard);
        for i in 1..40 {
            let _taken = intruder.hello(true, i * STALE_NS / 20);
            let _taken = Guard::open(&guard).hello(true, i * STALE_NS / 20);
        }
        assert!(observer.sent(STALE_NS / 20 + LATE));
    }

    #[test]
    fn streams_that_have_not_said_hello_do_not_count() {
        let guard = Arc::default();
        let observer = Guard::open(&guard);
        assert!(observer.hello(true, 0));
        let _quiet = Guard::open(&guard);
        assert!(!observer.sent(LATE));
    }

    #[test]
    fn only_open_streams_are_kept() {
        let guard: Arc<Guard> = Arc::default();
        let kept = Guard::open(&guard);
        for _ in 0..20 {
            let _taken = Guard::open(&guard).hello(true, 0);
        }
        assert_eq!(guard.streams().len(), 1);
        drop(kept);
        assert_eq!(guard.streams().len(), 0);
    }
}
