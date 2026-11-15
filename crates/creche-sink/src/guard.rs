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
//!   [`STALE_NS`] of the first newer hello do not count.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

/// How long after a newer stream's hello an older stream may still deliver
/// what it was sent before, in nanoseconds.
pub const STALE_NS: u64 = 2_000_000_000;
/// Hellos remembered, for the streams still open. A sandbox has at most a few.
const HELLOS: usize = 16;

/// The guard evidence of one sandbox, shared by its streams.
#[derive(Debug, Default)]
pub struct Guard {
    /// What the sandbox's first hello claimed.
    first: OnceLock<bool>,
    /// The next stream's number.
    next: AtomicU64,
    /// When the latest streams said hello: stream number and host clock.
    hellos: Mutex<Vec<(u64, u64)>>,
    /// Whether two streams were seen sending at once.
    breached: AtomicBool,
}

impl Guard {
    /// A number for a new stream of the sandbox, in the order they open.
    pub fn open(&self) -> u64 {
        self.next.fetch_add(1, Ordering::SeqCst)
    }

    /// Stream `stream` said hello at `now_ns`, claiming the port is guarded or
    /// not. Returns whether the sink takes it as guarded: it claims so, the
    /// sandbox's first hello claimed so, and no two streams sent at once.
    pub fn hello(&self, stream: u64, claimed: bool, now_ns: u64) -> bool {
        let first = *self.first.get_or_init(|| claimed);
        let mut hellos = self.hellos.lock().unwrap_or_else(PoisonError::into_inner);
        if hellos.len() >= HELLOS {
            hellos.remove(0);
        }
        hellos.push((stream, now_ns));
        drop(hellos);
        claimed && first && !self.breached()
    }

    /// Stream `stream` sent records at `now_ns`. Returns whether two streams of
    /// the sandbox have now been seen sending at once: a newer stream said
    /// hello more than [`STALE_NS`] before.
    pub fn sent(&self, stream: u64, now_ns: u64) -> bool {
        let hellos = self.hellos.lock().unwrap_or_else(PoisonError::into_inner);
        let first_newer = hellos
            .iter()
            .filter(|&&(other, _)| other > stream)
            .map(|&(_, at)| at)
            .min();
        drop(hellos);
        if first_newer.is_some_and(|at| now_ns.saturating_sub(at) > STALE_NS) {
            self.breached.store(true, Ordering::SeqCst);
        }
        self.breached()
    }

    /// Whether two streams of the sandbox were seen sending at once.
    #[must_use]
    pub fn breached(&self) -> bool {
        self.breached.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Late enough after a newer hello to be a second sender.
    const LATE: u64 = STALE_NS + 1;

    #[test]
    fn the_first_hello_decides_what_later_ones_may_claim() {
        let guard = Guard::default();
        let (a, b) = (guard.open(), guard.open());
        assert!(!guard.hello(a, false, 0));
        // A later claim of a guard the first hello did not have is not taken.
        assert!(!guard.hello(b, true, 0));
        let guard = Guard::default();
        let (a, b) = (guard.open(), guard.open());
        assert!(guard.hello(a, true, 0));
        assert!(guard.hello(b, true, 0));
        assert!(!guard.hello(b, false, 0));
    }

    #[test]
    fn a_restarted_observer_is_one_sender() {
        let guard = Guard::default();
        let old = guard.open();
        assert!(guard.hello(old, true, 0));
        assert!(!guard.sent(old, 1));
        let new = guard.open();
        assert!(guard.hello(new, true, 10));
        // What the old observer wrote before it exited is still read.
        assert!(!guard.sent(old, 10 + STALE_NS));
        assert!(!guard.sent(new, 10 + LATE));
        assert!(!guard.breached());
    }

    #[test]
    fn an_older_stream_sending_well_after_a_newer_hello_is_a_second_sender() {
        let guard = Guard::default();
        let observer = guard.open();
        assert!(guard.hello(observer, true, 0));
        let intruder = guard.open();
        assert!(guard.hello(intruder, true, 0));
        assert!(!guard.sent(intruder, LATE));
        // The observer still sends: two senders.
        assert!(guard.sent(observer, LATE));
        assert!(guard.sent(intruder, LATE));
        assert!(!guard.hello(guard.open(), true, LATE));
    }

    #[test]
    fn new_hellos_do_not_put_off_the_verdict() {
        let guard = Guard::default();
        let observer = guard.open();
        assert!(guard.hello(observer, true, 0));
        // An intruder reconnecting again and again: the first newer hello
        // counts.
        for i in 1..5 {
            guard.hello(guard.open(), true, i * STALE_NS / 2);
        }
        assert!(guard.sent(observer, 2 * STALE_NS));
    }

    #[test]
    fn streams_that_have_not_said_hello_do_not_count() {
        let guard = Guard::default();
        let observer = guard.open();
        assert!(guard.hello(observer, true, 0));
        let _quiet = guard.open();
        assert!(!guard.sent(observer, LATE));
    }

    #[test]
    fn only_the_latest_hellos_are_kept() {
        let guard = Guard::default();
        for _ in 0..HELLOS + 4 {
            guard.hello(guard.open(), true, 0);
        }
        assert_eq!(guard.hellos.lock().unwrap().len(), HELLOS);
    }
}
