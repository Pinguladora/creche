//! Bounded queue of whole records waiting to be sent to the host.
//!
//! Records are never split across connections: when a write fails part-way
//! through a record, the next flush resends that record from its start (on a
//! new connection), so the receiver always sees a stream of whole records.
//!
//! The queue keeps no per-record bookkeeping. Every record carries its length in
//! its header, read once when the record is queued and again only after a failed
//! write, to find where the cut-off record starts.

use std::io::{self, Write};

use creche_wire::peek_len;

/// Records waiting to be sent, as one contiguous byte buffer.
#[derive(Debug)]
pub struct RecordQueue {
    /// Queued bytes. `buf[head..]` is unsent.
    buf: Vec<u8>,
    /// Start of the first unsent record in `buf`.
    head: usize,
    /// Maximum number of unsent bytes.
    capacity: usize,
    /// Bytes delivered so far.
    sent_bytes: u64,
    /// Bytes refused because the queue was full or the record was malformed.
    dropped_bytes: u64,
}

impl RecordQueue {
    /// An empty queue holding at most `capacity` unsent bytes.
    #[must_use]
    pub const fn new(capacity: usize) -> Self {
        Self {
            buf: Vec::new(),
            head: 0,
            capacity,
            sent_bytes: 0,
            dropped_bytes: 0,
        }
    }

    /// Queues a whole record. Returns `false` (and counts it as dropped) when
    /// the record does not fit or its header length is not its actual length.
    pub fn push(&mut self, record: &[u8]) -> bool {
        if peek_len(record) != Some(record.len())
            || self.queued_bytes().saturating_add(record.len()) > self.capacity
        {
            self.dropped_bytes = self.dropped_bytes.saturating_add(record.len() as u64);
            return false;
        }
        append(&mut self.buf, record);
        true
    }

    /// Unsent bytes, including any partially sent record.
    #[must_use]
    pub fn queued_bytes(&self) -> usize {
        self.buf.len().saturating_sub(self.head)
    }

    /// Bytes delivered so far.
    #[must_use]
    pub const fn sent_bytes(&self) -> u64 {
        self.sent_bytes
    }

    /// Bytes refused because the queue was full or the record was malformed.
    #[must_use]
    pub const fn dropped_bytes(&self) -> u64 {
        self.dropped_bytes
    }

    /// Writes as much as `out` accepts.
    ///
    /// # Errors
    ///
    /// The write error. The partially written record, if any, is then rewound
    /// so the next flush (on a new connection) sends it whole.
    pub fn flush(&mut self, out: &mut impl Write) -> io::Result<()> {
        let mut written = self.head;
        while let Some(pending) = self.buf.get(written..).filter(|p| !p.is_empty()) {
            match out.write(pending) {
                Ok(0) => return Err(self.rewind(written, io::ErrorKind::WriteZero.into())),
                Ok(n) => {
                    written = written.saturating_add(n);
                    self.sent_bytes = self.sent_bytes.saturating_add(n as u64);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(self.rewind(written, e)),
            }
        }
        self.buf.clear();
        self.head = 0;
        Ok(())
    }

    /// After a failed write that got up to `written`: retires the records that
    /// went out whole, so only the cut-off one is sent again. Returns `err`.
    /// Runs only when a connection breaks.
    #[cold]
    fn rewind(&mut self, written: usize, err: io::Error) -> io::Error {
        while let Some(len) = self.buf.get(self.head..).and_then(peek_len) {
            let end = self.head.saturating_add(len);
            if end > written {
                break;
            }
            self.head = end;
        }
        // Reclaim the sent prefix once it dominates the buffer.
        if self.head > self.buf.len() / 2 {
            self.buf.drain(..self.head);
            self.head = 0;
        }
        err
    }
}

/// Appends `record` to `buf` in fixed-size 16-byte copies, which compile to plain
/// vector moves. A copy of runtime length calls the C library's memcpy, and musl's
/// moves small unaligned buffers a byte at a time: it was the observer's hottest
/// userspace path, about 3 times slower than this for typical records.
fn append(buf: &mut Vec<u8>, record: &[u8]) {
    let Some(last) = record.last_chunk::<16>() else {
        buf.extend_from_slice(record);
        return;
    };
    let end = buf.len().saturating_add(record.len());
    buf.reserve(record.len());
    for chunk in record.as_chunks::<16>().0 {
        buf.extend_from_slice(chunk);
    }
    // The tail: the record's last 16 bytes, overlapping what is already there.
    buf.truncate(end.saturating_sub(16));
    buf.extend_from_slice(last);
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A record of `len` bytes filled with `fill`, with a valid length field.
    fn rec(len: usize, fill: u8) -> Vec<u8> {
        let mut r = vec![fill; len];
        r[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_ne_bytes());
        r
    }

    /// A writer that accepts at most `chunk` bytes per call and fails after
    /// `fail_after` successful calls.
    #[derive(Default)]
    struct Flaky {
        written: Vec<u8>,
        chunk: usize,
        fail_after: Option<usize>,
        calls: usize,
    }

    impl Write for Flaky {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            if self.fail_after.is_some_and(|limit| self.calls >= limit) {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            self.calls += 1;
            let n = data.len().min(self.chunk);
            self.written.extend_from_slice(&data[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn writer(chunk: usize) -> Flaky {
        Flaky {
            chunk,
            ..Flaky::default()
        }
    }

    #[test]
    fn delivers_records_in_order_through_short_writes() {
        let (a, b) = (rec(60, 1), rec(48, 2));
        let mut q = RecordQueue::new(1024);
        assert!(q.push(&a));
        assert!(q.push(&b));
        let mut out = writer(7);
        q.flush(&mut out).unwrap();
        assert_eq!(out.written, [a, b].concat());
        assert_eq!(q.queued_bytes(), 0);
        assert_eq!(q.sent_bytes(), 108);
    }

    #[test]
    fn refuses_records_beyond_capacity() {
        let mut q = RecordQueue::new(110);
        assert!(q.push(&rec(60, 1)));
        assert!(!q.push(&rec(51, 2)));
        assert!(q.push(&rec(50, 3)));
        assert_eq!(q.queued_bytes(), 110);
        assert_eq!(q.dropped_bytes(), 51);
        assert!(!q.push(&rec(48, 4)));
    }

    #[test]
    fn refuses_records_whose_header_length_is_wrong() {
        let mut q = RecordQueue::new(1024);
        let mut short = rec(60, 1);
        short.truncate(59);
        assert!(!q.push(&short));
        assert!(!q.push(&[0; 47]));
        assert!(!q.push(b""));
        assert_eq!(q.queued_bytes(), 0);
        assert_eq!(q.dropped_bytes(), 59 + 47);
    }

    #[test]
    fn a_failed_write_resends_the_partial_record_whole() {
        let (first, second) = (rec(50, 1), rec(60, 2));
        let mut q = RecordQueue::new(1024);
        q.push(&first);
        q.push(&second);
        // 2 calls of 40 bytes: all of first and 30 bytes of second, then fail.
        let mut out = Flaky {
            chunk: 40,
            fail_after: Some(2),
            ..Flaky::default()
        };
        assert_eq!(
            q.flush(&mut out).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(out.written, [&first[..], &second[..30]].concat());

        let mut next = writer(100);
        q.flush(&mut next).unwrap();
        assert_eq!(next.written, second);
        assert_eq!(q.queued_bytes(), 0);
    }

    #[test]
    fn write_zero_is_an_error_and_keeps_the_record() {
        let r = rec(48, 1);
        let mut q = RecordQueue::new(1024);
        q.push(&r);
        let mut stuck = writer(0);
        assert_eq!(
            q.flush(&mut stuck).unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
        assert_eq!(q.queued_bytes(), 48);
        let mut out = writer(100);
        q.flush(&mut out).unwrap();
        assert_eq!(out.written, r);
    }

    #[test]
    fn interrupted_writes_are_retried() {
        struct InterruptOnce(bool, Vec<u8>);
        impl Write for InterruptOnce {
            fn write(&mut self, data: &[u8]) -> io::Result<usize> {
                if !self.0 {
                    self.0 = true;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                self.1.extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let r = rec(48, 1);
        let mut q = RecordQueue::new(64);
        q.push(&r);
        let mut out = InterruptOnce(false, Vec::new());
        q.flush(&mut out).unwrap();
        assert_eq!(out.1, r);
    }

    /// Queues `count` 50-byte records, flushes `sent` bytes, then fails.
    fn partly_sent(count: usize, sent: usize) -> RecordQueue {
        let mut q = RecordQueue::new(1024);
        for _ in 0..count {
            q.push(&rec(50, 7));
        }
        let mut out = Flaky {
            chunk: sent,
            fail_after: Some(1),
            ..Flaky::default()
        };
        assert!(q.flush(&mut out).is_err());
        q
    }

    #[test]
    fn the_sent_prefix_is_reclaimed_only_once_it_exceeds_half() {
        // More than half sent: reclaimed.
        let q = partly_sent(3, 100);
        assert_eq!((q.buf.len(), q.head), (50, 0));
        // Exactly half: kept.
        let q = partly_sent(2, 50);
        assert_eq!((q.buf.len(), q.head), (100, 50));
        // Less than half: kept.
        let q = partly_sent(3, 50);
        assert_eq!((q.buf.len(), q.head), (150, 50));
        // A record cut short is not retired.
        let q = partly_sent(3, 99);
        assert_eq!((q.buf.len(), q.head), (150, 50));
    }

    #[test]
    fn space_is_reclaimed_after_sending() {
        let mut q = RecordQueue::new(64);
        q.push(&rec(64, 1));
        q.flush(&mut writer(64)).unwrap();
        assert!(q.push(&rec(64, 2)));
        assert_eq!(q.queued_bytes(), 64);
    }

    proptest! {
        /// The chunked append is a plain append, whatever the lengths.
        #[test]
        fn append_matches_extend(
            prefix in proptest::collection::vec(any::<u8>(), 0..40),
            record in proptest::collection::vec(any::<u8>(), 0..200),
        ) {
            let mut buf = prefix.clone();
            append(&mut buf, &record);
            prop_assert_eq!(buf, [prefix, record].concat());
        }

        /// Whatever the write sizes and failures: every connection carries whole
        /// records in order, possibly followed by one cut-off record where it
        /// failed, and the final successful flush completes the stream.
        #[test]
        fn connections_only_ever_carry_whole_records(
            shapes in proptest::collection::vec((48_usize..120, any::<u8>()), 1..30),
            chunk in 1_usize..200,
            failures in proptest::collection::vec(0_usize..6, 0..4),
        ) {
            let records: Vec<_> = shapes.into_iter().map(|(len, fill)| rec(len, fill)).collect();
            let mut q = RecordQueue::new(usize::MAX);
            for r in &records {
                prop_assert!(q.push(r));
            }
            let mut next = 0;
            for fail_after in failures.into_iter().map(Some).chain([None]) {
                let mut out = Flaky { chunk, fail_after, ..Flaky::default() };
                let ok = q.flush(&mut out).is_ok();
                let mut rest = out.written.as_slice();
                while next < records.len() && rest.starts_with(&records[next]) {
                    rest = &rest[records[next].len()..];
                    next += 1;
                }
                if !rest.is_empty() {
                    prop_assert!(!ok);
                    prop_assert!(next < records.len() && records[next].starts_with(rest));
                }
                if ok {
                    break;
                }
            }
            prop_assert_eq!(next, records.len());
            prop_assert_eq!(q.queued_bytes(), 0);
        }
    }
}
