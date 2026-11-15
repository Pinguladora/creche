//! The audit verifier on arbitrary archive bytes: its report never holds a
//! control character or anything else but printable ASCII, and has exactly the
//! lines its streams account for, so an archive cannot forge report lines.
#![no_main]

use creche_sink::audit::verify;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|archive: &[u8]| {
    let report = verify(archive, None);
    let text = report.to_string();
    assert!(
        text.bytes()
            .all(|b| b == b'\n' || (b' '..=b'~').contains(&b)),
        "{text:?}"
    );
    let starts = text.lines().filter(|l| l.starts_with("stream ")).count();
    assert_eq!(starts, report.streams.len(), "{text:?}");
    for line in text.lines() {
        assert!(
            line.starts_with("stream ") || line.starts_with("  ") || line.ends_with(" unreadable"),
            "{line:?}"
        );
    }
    assert!(!report.complete() || report.intact());
});
