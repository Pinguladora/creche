//! The sink's stream decoder on arbitrary guest bytes, in both output formats.
//! Fed whole or in chunks it writes the same output, every JSON line is valid
//! JSON of bounded size, and raw frames carry the input unchanged.
#![no_main]

use creche_sink::json::Origin;
use creche_sink::stream::{Format, StreamDecoder};
use libfuzzer_sys::fuzz_target;

/// Largest JSON line one record can produce: every field at its maximum and
/// every byte escaped as \u00XX.
const MAX_LINE: usize = 8 * 1024;

/// Feeds `data` in chunks of `chunk` bytes (all at once for 0). Returns the
/// output and whether the stream was found corrupt.
fn feed(format: Format, data: &[u8], chunk: usize) -> (Vec<u8>, bool) {
    let mut decoder = StreamDecoder::new(format);
    let origin = Origin::from("sb");
    let mut out = Vec::new();
    let size = if chunk == 0 { data.len().max(1) } else { chunk };
    for part in data.chunks(size) {
        if decoder.feed_at(part, &origin, 1, &mut out).is_err() {
            return (out, true);
        }
    }
    (out, false)
}

/// The record bytes in a stream of raw frames.
fn unframe(mut frames: &[u8]) -> Vec<u8> {
    let mut records = Vec::new();
    while !frames.is_empty() {
        let id_len = usize::from(u16::from_ne_bytes([frames[0], frames[1]]));
        assert_eq!(&frames[2..2 + id_len], b"sb");
        let at = 2 + id_len;
        let len = u32::from_ne_bytes(frames[at..at + 4].try_into().unwrap());
        let body = &frames[at + 4..at + 4 + len as usize];
        records.extend_from_slice(body);
        frames = &frames[at + 4 + body.len()..];
    }
    records
}

fuzz_target!(|input: &[u8]| {
    let Some((&chunk, data)) = input.split_first() else {
        return;
    };
    let chunk = usize::from(chunk);

    let (whole, corrupt) = feed(Format::Json, data, 0);
    assert_eq!(feed(Format::Json, data, chunk), (whole.clone(), corrupt));
    for line in whole.split_inclusive(|&b| b == b'\n') {
        assert!(line.len() <= MAX_LINE, "line of {} bytes", line.len());
        let value: serde_json::Value = serde_json::from_slice(line).unwrap();
        assert_eq!(value["creche.sandbox.id"], "sb");
        assert!(value["event.name"].is_string());
    }

    let (frames, raw_corrupt) = feed(Format::Raw, data, chunk);
    assert_eq!(raw_corrupt, corrupt);
    let records = unframe(&frames);
    assert!(data.starts_with(&records));
});
