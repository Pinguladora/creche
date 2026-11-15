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
//!   still sends after a newer stream of the same sandbox said hello shows two
//!   senders at once, so the port is not guarded. From then on no stream of
//!   the sandbox counts as guarded.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The guard evidence of one sandbox, shared by its streams.
#[derive(Debug, Default)]
pub struct Guard {
    /// What the sandbox's first hello claimed.
    first: OnceLock<bool>,
    /// The next stream's number.
    next: AtomicU64,
    /// The newest stream that said hello, plus one. 0 before any did.
    newest: AtomicU64,
    /// Whether two streams were seen sending at once.
    breached: AtomicBool,
}

impl Guard {
    /// A number for a new stream of the sandbox, in the order they open.
    pub fn open(&self) -> u64 {
        self.next.fetch_add(1, Ordering::SeqCst)
    }

    /// Stream `stream` said hello, claiming the port is guarded or not.
    /// Returns whether the sink takes it as guarded: it claims so, the
    /// sandbox's first hello claimed so, and no two streams sent at once.
    pub fn hello(&self, stream: u64, claimed: bool) -> bool {
        let first = *self.first.get_or_init(|| claimed);
        self.newest
            .fetch_max(stream.saturating_add(1), Ordering::SeqCst);
        claimed && first && !self.breached()
    }

    /// Stream `stream` sent records. Returns whether two streams of the
    /// sandbox have now been seen sending at once.
    pub fn sent(&self, stream: u64) -> bool {
        if self.newest.load(Ordering::SeqCst) > stream.saturating_add(1) {
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

    #[test]
    fn the_first_hello_decides_what_later_ones_may_claim() {
        let guard = Guard::default();
        let (a, b) = (guard.open(), guard.open());
        assert!(!guard.hello(a, false));
        // A later claim of a guard the first hello did not have is not taken.
        assert!(!guard.hello(b, true));
        let guard = Guard::default();
        let (a, b) = (guard.open(), guard.open());
        assert!(guard.hello(a, true));
        assert!(guard.hello(b, true));
        assert!(!guard.hello(b, false));
    }

    #[test]
    fn a_restarted_observer_is_one_sender() {
        let guard = Guard::default();
        let old = guard.open();
        assert!(guard.hello(old, true));
        assert!(!guard.sent(old));
        // The old connection broke and sends nothing more.
        let new = guard.open();
        assert!(guard.hello(new, true));
        assert!(!guard.sent(new));
        assert!(!guard.breached());
    }

    #[test]
    fn an_older_stream_sending_after_a_newer_hello_is_a_second_sender() {
        let guard = Guard::default();
        let observer = guard.open();
        assert!(guard.hello(observer, true));
        let intruder = guard.open();
        // The intruder's own records show nothing yet.
        assert!(guard.hello(intruder, true));
        assert!(!guard.sent(intruder));
        // The observer still sends: two senders.
        assert!(guard.sent(observer));
        assert!(guard.sent(intruder));
        assert!(!guard.hello(guard.open(), true));
    }

    #[test]
    fn streams_that_have_not_said_hello_do_not_count() {
        let guard = Guard::default();
        let observer = guard.open();
        assert!(guard.hello(observer, true));
        // Opened, but no hello yet: no sender to compare with.
        let _quiet = guard.open();
        assert!(!guard.sent(observer));
    }
}
