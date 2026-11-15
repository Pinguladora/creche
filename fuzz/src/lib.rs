//! Checks and fixtures shared by the fuzz targets and their seeds.

use std::collections::HashSet;
use std::fmt;

use creche_sink::json::Origin;
use creche_sink::stream::{Format, StreamDecoder};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

/// The archive a sink writes for one stream of `records`: its start line, the
/// records' lines, its end line and its checkpoints. A corrupt stream still
/// ends, as the sink ends it.
#[must_use]
pub fn archive(records: &[u8]) -> Vec<u8> {
    let origin = Origin::from("sb").with_stream("s1");
    let mut decoder = StreamDecoder::new(Format::Json).with_audit();
    let mut out = Vec::new();
    decoder.event(&origin, "creche.stream.start", 1, &[], &mut out);
    let _ = decoder.feed_at(records, &origin, 2, &mut out);
    decoder.event(&origin, "creche.stream.end", 3, &[], &mut out);
    decoder.finish(&origin, 3, &mut out);
    out
}

/// Whether `json` is one JSON value in which no object names a member twice,
/// at any depth. `serde_json` keeps the last of repeated names, so parsing
/// into its `Value` cannot tell.
#[must_use]
pub fn unique_names(json: &[u8]) -> bool {
    serde_json::from_slice::<Unique>(json).is_ok()
}

/// A JSON value whose objects have unique member names.
struct Unique;

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value with unique member names")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Unique, E> {
        Ok(Unique)
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Unique, E> {
        Ok(Unique)
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Unique, E> {
        Ok(Unique)
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Unique, E> {
        Ok(Unique)
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<Unique, E> {
        Ok(Unique)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
        Ok(Unique)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
        while seq.next_element::<Unique>()?.is_some() {}
        Ok(Unique)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
        let mut names = HashSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !names.insert(name) {
                return Err(de::Error::custom("a member name repeats"));
            }
            map.next_value::<Unique>()?;
        }
        Ok(Unique)
    }
}

#[cfg(test)]
mod tests {
    use super::unique_names;

    #[test]
    fn repeated_names_are_found_at_any_depth() {
        assert!(unique_names(br#"{"a":1,"b":[{"c":null}],"d":"x"}"#));
        assert!(!unique_names(br#"{"a":1,"a":2}"#));
        assert!(!unique_names(br#"{"a":[{"b":1,"b":1}]}"#));
        assert!(!unique_names(b"{"));
    }
}
