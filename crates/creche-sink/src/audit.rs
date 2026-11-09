//! Tamper evidence for the sink's output.
//!
//! Every line of a stream carries `creche.seq`, its place in the stream from 0.
//! Once [`CHECKPOINT_LINES`] lines are not yet covered, or [`CHECKPOINT_NS`]
//! after the first of them, and when the stream ends, the sink writes a
//! `creche.audit.checkpoint` line after the input it is decoding. It covers the
//! lines since the previous one, `creche.seq.first` to `creche.seq.last`, with
//! `creche.audit.hash = SHA-256(previous hash || the exact bytes of those lines)`.
//! The first checkpoint's previous hash is 32 zero bytes. Checkpoint lines are
//! not hashed themselves.
//!
//! A gap in `creche.seq` shows a removed line, and a hash that does not match
//! shows a changed, reordered or inserted one.
//!
//! A signed stream also proves who wrote it and that its past was sealed. Its
//! start line carries a fresh P-256 public key, `creche.audit.key`, signed by
//! the sink's SPIFFE SVID (see [`crate::spiffe`]). Each checkpoint is signed by
//! the stream's current key and names the next one, derived as
//! `SHA-256("creche next key v1" || current seed || checkpoint hash)`, and the
//! current key is then erased. Whoever takes over the sink later holds only the
//! current key and cannot sign earlier checkpoints again. [`verify`] checks a
//! file of sink output.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{self, Read as _};
use std::mem;

use base64ct::{Base64, Encoding as _};
use miniserde::{Deserialize, json};
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::json::{Origin, Value, sink_event};
use crate::spiffe::{self, Svid, TrustBundle};

/// Uncovered lines that make a checkpoint due. It is written after the input
/// that crossed the mark, so it may cover a few more.
pub const CHECKPOINT_LINES: u64 = 256;
/// How long the first uncovered line waits before a checkpoint is due, checked
/// whenever the stream has new input.
pub const CHECKPOINT_NS: u64 = 1_000_000_000;

/// The audit chain of one stream.
#[derive(Debug)]
pub struct Chain {
    /// Hash of the lines since the last checkpoint, seeded with `prev`.
    hasher: Sha256,
    /// The last checkpoint's hash, zero before the first.
    prev: [u8; 32],
    /// First line not yet covered by a checkpoint.
    first: u64,
    /// One past the last line hashed.
    next: u64,
    /// When the first line not yet covered was hashed.
    since_ns: Option<u64>,
    /// The stream's current signing key, when the stream is signed.
    ratchet: Option<Ratchet>,
}

/// A signed stream's current key. It zeroizes itself when replaced or dropped.
struct Ratchet {
    stream: Box<str>,
    key: SigningKey,
}

impl std::fmt::Debug for Ratchet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ratchet")
            .field("stream", &self.stream)
            .finish_non_exhaustive()
    }
}

impl Default for Chain {
    fn default() -> Self {
        let prev = [0; 32];
        Self {
            hasher: seeded(&prev),
            prev,
            first: 0,
            next: 0,
            since_ns: None,
            ratchet: None,
        }
    }
}

fn seeded(prev: &[u8; 32]) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher
}

/// What the SVID signs: a stream's first key.
fn key_message(stream: &str, key: &str) -> Vec<u8> {
    format!("creche stream key v1\n{stream}\n{key}\n").into_bytes()
}

/// What a stream key signs: a checkpoint and the key after it.
fn checkpoint_message(
    stream: &str,
    first: u64,
    last: u64,
    prev: &str,
    hash: &str,
    next_key: &str,
) -> Vec<u8> {
    format!("creche checkpoint v1\n{stream}\n{first}\n{last}\n{prev}\n{hash}\n{next_key}\n")
        .into_bytes()
}

/// A P-256 key from 32 bytes of key material. A hash of the material and a
/// counter is tried until it is a valid scalar, which fails about once in 2^32.
fn key_from(material: &[u8]) -> Option<SigningKey> {
    (0..=u8::MAX).find_map(|counter| {
        let mut hasher = Sha256::new();
        hasher.update(b"creche key v1");
        hasher.update([counter]);
        hasher.update(material);
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(hasher.finalize().into());
        SigningKey::from_slice(seed.as_ref()).ok()
    })
}

/// The key after `key`, bound to the checkpoint `hash` it signs.
fn next_key(key: &SigningKey, hash: &[u8; 32]) -> Option<SigningKey> {
    let mut material = Zeroizing::new(Vec::with_capacity(96));
    material.extend_from_slice(b"creche next key v1");
    material.extend_from_slice(key.to_bytes().as_slice());
    material.extend_from_slice(hash);
    key_from(&material)
}

/// A public key as `creche.audit.key` writes it: SEC1 compressed, in hex.
fn key_hex(key: &VerifyingKey) -> String {
    hex(key.to_sec1_point(true).as_bytes())
}

/// The public key in `creche.audit.key` or `creche.audit.next_key`.
fn parse_key(text: &str) -> Option<VerifyingKey> {
    VerifyingKey::from_sec1_bytes(&unhex::<33>(text)?).ok()
}

impl Chain {
    /// A chain for stream `stream` whose checkpoints are signed, starting from a
    /// random key that `svid` vouches for. Also returns the fields the stream's
    /// start line must carry.
    ///
    /// # Errors
    ///
    /// When the system's random source cannot be read.
    pub fn signed(stream: &str, svid: &Svid) -> io::Result<(Self, Vec<(&'static str, String)>)> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        std::fs::File::open("/dev/urandom")?.read_exact(seed.as_mut())?;
        let key = key_from(seed.as_ref()).ok_or_else(|| io::Error::other("no valid key"))?;
        let public = key_hex(key.verifying_key());
        let fields = vec![
            ("creche.audit.spiffe_id", svid.spiffe_id().to_owned()),
            ("creche.audit.svid", Base64::encode_string(svid.chain())),
            ("creche.audit.key", public.clone()),
            (
                "creche.audit.key_sig",
                Base64::encode_string(&svid.sign(&key_message(stream, &public))),
            ),
        ];
        let chain = Self {
            ratchet: Some(Ratchet {
                stream: stream.into(),
                key,
            }),
            ..Self::default()
        };
        Ok((chain, fields))
    }

    /// Hashes `lines`, the bytes of the stream's lines up to, not including,
    /// line `next`, written at `now_ns`.
    pub fn absorb(&mut self, lines: &[u8], next: u64, now_ns: u64) {
        if lines.is_empty() {
            return;
        }
        self.hasher.update(lines);
        self.next = next;
        self.since_ns.get_or_insert(now_ns);
    }

    /// Whether a checkpoint is due at `now_ns`.
    #[must_use]
    pub fn due(&self, now_ns: u64) -> bool {
        let pending = self.next.saturating_sub(self.first);
        pending >= CHECKPOINT_LINES
            || self
                .since_ns
                .is_some_and(|since| now_ns.saturating_sub(since) >= CHECKPOINT_NS)
    }

    /// Writes a checkpoint for the lines hashed since the last one, if any.
    /// In a signed stream, signs it and moves on to the next key.
    pub fn checkpoint(&mut self, origin: &Origin, now_ns: u64, out: &mut Vec<u8>) {
        if self.next == self.first {
            return;
        }
        let hasher = mem::replace(&mut self.hasher, Sha256::new());
        let hash: [u8; 32] = hasher.finalize().into();
        let (first, last) = (self.first, self.next.saturating_sub(1));
        let (prev_hex, hash_hex) = (hex(&self.prev), hex(&hash));
        let mut fields = vec![
            ("creche.seq.first", Value::Num(first)),
            ("creche.seq.last", Value::Num(last)),
            ("creche.audit.prev", Value::Str(&prev_hex)),
            ("creche.audit.hash", Value::Str(&hash_hex)),
        ];
        let signed = self.ratchet.as_mut().and_then(|ratchet| {
            let next = next_key(&ratchet.key, &hash)?;
            let next_hex = key_hex(next.verifying_key());
            let message = checkpoint_message(
                &ratchet.stream,
                first,
                last,
                &prev_hex,
                &hash_hex,
                &next_hex,
            );
            let signature: Signature = ratchet.key.sign(&message);
            // The old key is dropped, and zeroized, here.
            ratchet.key = next;
            Some((next_hex, hex(&signature.to_bytes())))
        });
        if let Some((next_hex, signature)) = &signed {
            fields.push(("creche.audit.next_key", Value::Str(next_hex)));
            fields.push(("creche.audit.sig", Value::Str(signature)));
        }
        sink_event(
            origin,
            "creche.audit.checkpoint",
            now_ns,
            None,
            &fields,
            out,
        );
        self.prev = hash;
        self.hasher = seeded(&hash);
        self.first = self.next;
        self.since_ns = None;
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let bytes = text.as_bytes();
    if bytes.len() != N.saturating_mul(2) {
        return None;
    }
    let mut out = [0_u8; N];
    let (pairs, _) = bytes.as_chunks::<2>();
    for (byte, pair) in out.iter_mut().zip(pairs) {
        // from_str_radix alone would also take a leading sign.
        if !pair.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        let digits = std::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(digits, 16).ok()?;
    }
    Some(out)
}

/// The fields of an output line the verifier reads. Others are skipped.
#[derive(Deserialize)]
struct Entry {
    #[serde(rename = "creche.stream.id")]
    stream: Option<String>,
    #[serde(rename = "event.name")]
    event: Option<String>,
    #[serde(rename = "creche.seq")]
    seq: Option<u64>,
    #[serde(rename = "observed_time_unix_nano")]
    observed: Option<u64>,
    #[serde(rename = "creche.seq.first")]
    first: Option<u64>,
    #[serde(rename = "creche.seq.last")]
    last: Option<u64>,
    #[serde(rename = "creche.audit.prev")]
    prev: Option<String>,
    #[serde(rename = "creche.audit.hash")]
    hash: Option<String>,
    #[serde(rename = "creche.audit.next_key")]
    next_key: Option<String>,
    #[serde(rename = "creche.audit.sig")]
    sig: Option<String>,
    #[serde(rename = "creche.audit.spiffe_id")]
    spiffe_id: Option<String>,
    #[serde(rename = "creche.audit.svid")]
    svid: Option<String>,
    #[serde(rename = "creche.audit.key")]
    key: Option<String>,
    #[serde(rename = "creche.audit.key_sig")]
    key_sig: Option<String>,
    #[serde(rename = "creche.sandbox.id")]
    sandbox: Option<String>,
    #[serde(rename = "k8s.pod.uid")]
    pod_uid: Option<String>,
}

/// A checkpoint as read back. It orders by place first, then by every
/// other field, so identical copies sort next to each other.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Checkpoint {
    first: u64,
    last: u64,
    prev: String,
    hash: String,
    /// The next key and the signature, in a signed stream.
    signed: Option<(String, String)>,
}

/// A signed stream's start, as read back.
struct Start {
    observed_ns: u64,
    spiffe_id: String,
    svid: String,
    key: String,
    key_sig: String,
    sandbox: Option<String>,
    pod_uid: Option<String>,
}

/// What [`verify`] found in one stream.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StreamReport {
    /// Lines with a sequence number.
    pub lines: u64,
    /// Checkpoints that matched.
    pub checkpoints: u64,
    /// Lines covered by a matching checkpoint.
    pub verified: u64,
    /// Whether the stream's end event is present.
    pub ended: bool,
    /// Byte-identical repeats of a line or checkpoint, dropped before checking.
    /// A retry after a lost response delivers lines twice, which is no sign of
    /// tampering.
    pub duplicates: u64,
    /// The SPIFFE ID that signed the stream, when its signatures hold.
    pub signer: Option<String>,
    /// Whether the signer's SVID was checked against a trust bundle.
    pub trusted: bool,
    /// The node the stream's sandbox ran on, when the signer was checked
    /// against it.
    pub node: Option<String>,
    /// Everything that does not add up. Empty when the stream is intact.
    pub problems: Vec<String>,
}

/// What [`verify`] found, per stream id.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Per stream.
    pub streams: BTreeMap<String, StreamReport>,
    /// Lines that belong to no stream, such as refused connections.
    pub outside: u64,
    /// Lines that are not JSON objects.
    pub unreadable: u64,
}

impl Report {
    /// Whether every stream is intact and every line was readable.
    #[must_use]
    pub fn intact(&self) -> bool {
        self.unreadable == 0 && self.streams.values().all(|s| s.problems.is_empty())
    }
}

/// Who may have signed the streams a verifier checks.
#[derive(Clone, Debug)]
pub struct Trust {
    /// The SPIFFE trust bundle SVIDs must chain to.
    bundle: TrustBundle,
    /// The SPIFFE IDs of the sinks expected to sign. Any other workload with an
    /// SVID from the same trust domain could otherwise sign a made-up stream.
    /// With `nodes`, each holds [`NODE`] in place of the node's name.
    sinks: Vec<String>,
    nodes: Option<Nodes>,
}

/// What stands for the node's name in a sink's SPIFFE ID, once streams are
/// bound to their nodes.
pub const NODE: &str = "{node}";

impl Trust {
    /// Streams must be signed by one of `sinks`, with an SVID that chains to
    /// `bundle`. With `nodes`, every sink ID holds [`NODE`], and a stream must
    /// be signed by the sink on the node its sandbox ran on. Otherwise any
    /// authorised sink could sign a stream for a sandbox on another node.
    ///
    /// # Errors
    ///
    /// When there are no sinks, or when some hold [`NODE`] and there are no
    /// `nodes`, or the other way round.
    pub fn new(
        bundle: TrustBundle,
        sinks: Vec<String>,
        nodes: Option<Nodes>,
    ) -> Result<Self, String> {
        if sinks.is_empty() {
            return Err("no sink may sign".into());
        }
        let bound = nodes.is_some();
        if let Some(sink) = sinks.iter().find(|s| s.contains(NODE) != bound) {
            return Err(if bound {
                format!("{sink} does not name the node with {NODE}")
            } else {
                format!("{sink} names a node, but no nodes are known")
            });
        }
        Ok(Self {
            bundle,
            sinks,
            nodes,
        })
    }

    /// Whether `id` may sign the stream `start` begins. With nodes, the node
    /// that decided it.
    fn allows(&self, id: &str, start: &Start) -> Result<Option<String>, String> {
        let Some(nodes) = &self.nodes else {
            return if self.sinks.iter().any(|s| s == id) {
                Ok(None)
            } else {
                Err(format!("signed by {id}, which is not an expected sink"))
            };
        };
        let node = nodes.node_of(start.pod_uid.as_deref(), start.sandbox.as_deref())?;
        if self.sinks.iter().any(|s| s.replace(NODE, node) == id) {
            Ok(Some(node.to_owned()))
        } else {
            Err(format!(
                "signed by {id}, which is not the sink on node {node}"
            ))
        }
    }
}

/// Which node each sandbox ran on, by pod uid or sandbox id, as the cluster's
/// pod history tells.
#[derive(Clone, Debug, Default)]
pub struct Nodes(BTreeMap<String, String>);

impl Nodes {
    /// Reads lines of `<pod uid or sandbox id> <node>`. Blank lines, `#`
    /// comments and pods with no node, which never ran, are skipped.
    ///
    /// # Errors
    ///
    /// On a line with more than two fields, a node name that is not a DNS
    /// subdomain, or one pod on two nodes.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut nodes = BTreeMap::new();
        for (number, line) in (1_u32..).zip(text.lines()) {
            let line = line.split('#').next().unwrap_or_default();
            let mut fields = line.split_whitespace();
            let (Some(key), Some(node)) = (fields.next(), fields.next()) else {
                continue;
            };
            if fields.next().is_some() {
                return Err(format!(
                    "line {number}: expected <pod uid or sandbox id> <node>"
                ));
            }
            if !is_node_name(node) {
                return Err(format!("line {number}: {node:?} is not a node name"));
            }
            match nodes.insert(key.to_owned(), node.to_owned()) {
                Some(other) if other != node => {
                    return Err(format!(
                        "line {number}: {key} is on both {other} and {node}"
                    ));
                }
                _ => {}
            }
        }
        Ok(Self(nodes))
    }

    /// The node of a sandbox, by its pod uid first, then its sandbox id.
    fn node_of(&self, pod_uid: Option<&str>, sandbox: Option<&str>) -> Result<&str, String> {
        [pod_uid, sandbox]
            .into_iter()
            .flatten()
            .find_map(|key| self.0.get(key))
            .map(String::as_str)
            .ok_or_else(|| match (pod_uid, sandbox) {
                (Some(uid), _) => format!("no node is known for pod {uid}"),
                (None, Some(id)) => format!("no node is known for sandbox {id}"),
                (None, None) => "the stream names no sandbox".to_owned(),
            })
    }
}

/// Whether `name` is a Kubernetes node name: a DNS subdomain, lowercase
/// letters, digits, `-` and `.`, starting and ending with a letter or digit.
fn is_node_name(name: &str) -> bool {
    let alnum = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let bytes = name.as_bytes();
    (1..=253).contains(&bytes.len())
        && bytes.first().is_some_and(alnum)
        && bytes.last().is_some_and(alnum)
        && bytes.iter().all(|b| alnum(b) || *b == b'-' || *b == b'.')
}

/// Checks the audit chains in `output`, the bytes the sink wrote. Lines of
/// different streams may be interleaved and each stream's lines may be in any
/// order, but their bytes must be unchanged.
///
/// With `trust`, every stream must be signed by an SVID of one of its sinks that
/// chains to its bundle. Without it, signatures are still checked, but not whom
/// they belong to.
#[must_use]
pub fn verify(output: &[u8], trust: Option<&Trust>) -> Report {
    let mut report = Report::default();
    let mut lines: BTreeMap<String, Vec<(u64, &[u8])>> = BTreeMap::new();
    let mut checkpoints: BTreeMap<String, Vec<Checkpoint>> = BTreeMap::new();
    let mut starts: BTreeMap<String, Start> = BTreeMap::new();
    for line in output.split_inclusive(|&b| b == b'\n') {
        let entry = std::str::from_utf8(line)
            .ok()
            .and_then(|text| json::from_str::<Entry>(text).ok());
        let Some(entry) = entry else {
            report.unreadable = report.unreadable.saturating_add(1);
            continue;
        };
        let Some(stream) = entry.stream else {
            report.outside = report.outside.saturating_add(1);
            continue;
        };
        let event = entry.event.unwrap_or_default();
        let status = report.streams.entry(stream.clone()).or_default();
        match event.as_str() {
            "creche.stream.end" => status.ended = true,
            "creche.stream.start" => {
                if let (Some(spiffe_id), Some(svid), Some(key), Some(key_sig)) =
                    (entry.spiffe_id, entry.svid, entry.key, entry.key_sig)
                {
                    let observed_ns = entry.observed.unwrap_or_default();
                    starts.insert(
                        stream.clone(),
                        Start {
                            observed_ns,
                            spiffe_id,
                            svid,
                            key,
                            key_sig,
                            sandbox: entry.sandbox,
                            pod_uid: entry.pod_uid,
                        },
                    );
                }
            }
            _ => {}
        }
        if event == "creche.audit.checkpoint" {
            if let (Some(first), Some(last), Some(prev), Some(hash)) =
                (entry.first, entry.last, entry.prev, entry.hash)
            {
                let signed = entry.next_key.zip(entry.sig);
                checkpoints.entry(stream).or_default().push(Checkpoint {
                    first,
                    last,
                    prev,
                    hash,
                    signed,
                });
            } else {
                status
                    .problems
                    .push("checkpoint with missing fields".into());
            }
        } else if let Some(seq) = entry.seq {
            lines.entry(stream).or_default().push((seq, line));
        } else {
            status
                .problems
                .push(format!("{event} line without creche.seq"));
        }
    }
    for (stream, status) in &mut report.streams {
        let mut stream_lines = lines.remove(stream).unwrap_or_default();
        let mut stream_checkpoints = checkpoints.remove(stream).unwrap_or_default();
        let key = match (starts.remove(stream), trust) {
            (Some(start), _) => match first_key(stream, &start, trust) {
                Ok((signer, node, key)) => {
                    status.signer = Some(signer);
                    status.trusted = trust.is_some();
                    status.node = node;
                    Some(key)
                }
                Err(problem) => {
                    status.problems.push(problem);
                    continue;
                }
            },
            (None, Some(_)) => {
                status.problems.push("the stream is not signed".into());
                continue;
            }
            (None, None) => None,
        };
        check(
            stream,
            &mut stream_lines,
            &mut stream_checkpoints,
            key,
            status,
        );
    }
    report
}

/// The SPIFFE ID, the node it was checked against and the first key of a
/// signed stream, once the SVID's signature over that key holds, and with
/// `trust`, once the SVID chains to its bundle at the stream's start and
/// belongs to a sink it allows.
fn first_key(
    stream: &str,
    start: &Start,
    trust: Option<&Trust>,
) -> Result<(String, Option<String>, VerifyingKey), String> {
    let chain = Base64::decode_vec(&start.svid).map_err(|_| "the SVID is not base64".to_owned())?;
    let (id, node, svid_key) = if let Some(trust) = trust {
        let (id, key) = trust
            .bundle
            .verify(&chain, start.observed_ns / 1_000_000_000)
            .map_err(|e| format!("the SVID is not trusted: {e}"))?;
        let node = trust.allows(&id, start)?;
        (Some(id), node, key)
    } else {
        let (id, key) =
            spiffe::leaf_key(&chain).map_err(|e| format!("the SVID does not parse: {e}"))?;
        (id, None, key)
    };
    if id.as_deref() != Some(start.spiffe_id.as_str()) {
        return Err("the SVID does not carry the stream's SPIFFE ID".into());
    }
    let signature = Base64::decode_vec(&start.key_sig).unwrap_or_default();
    if !spiffe::verify_signature(&svid_key, &key_message(stream, &start.key), &signature) {
        return Err("the SVID did not sign the stream's key".into());
    }
    let key = parse_key(&start.key).ok_or("the stream's key is not a P-256 key")?;
    Ok((start.spiffe_id.clone(), node, key))
}

/// Checks one stream's lines against its checkpoints, and in a signed stream,
/// each checkpoint's signature with the key the one before it named.
fn check(
    stream: &str,
    lines: &mut Vec<(u64, &[u8])>,
    checkpoints: &mut Vec<Checkpoint>,
    mut key: Option<VerifyingKey>,
    status: &mut StreamReport,
) {
    // Byte-identical repeats go. Two different lines or checkpoints for the
    // same place stay, and fail below.
    let before = lines.len().saturating_add(checkpoints.len());
    lines.sort_unstable();
    lines.dedup();
    checkpoints.sort_unstable();
    checkpoints.dedup();
    let after = lines.len().saturating_add(checkpoints.len());
    status.duplicates = u64::try_from(before.saturating_sub(after)).unwrap_or(u64::MAX);
    status.lines = u64::try_from(lines.len()).unwrap_or(u64::MAX);
    for (expected, (seq, _)) in (0_u64..).zip(lines.iter()) {
        if *seq != expected {
            let problem = if expected.checked_sub(1) == Some(*seq) {
                format!("two different lines claim line {seq}")
            } else {
                format!("expected line {expected}, found {seq}")
            };
            status.problems.push(problem);
            return;
        }
    }
    if let Some(pair) = checkpoints.windows(2).find(|w| w[0].first == w[1].first) {
        status.problems.push(format!(
            "two different checkpoints start at line {}",
            pair[0].first
        ));
        return;
    }
    let mut prev = [0_u8; 32];
    let mut next = 0_u64;
    for checkpoint in checkpoints.iter() {
        if checkpoint.first != next || checkpoint.last < checkpoint.first {
            status.problems.push(format!(
                "checkpoint covers {} to {}, expected one from {next}",
                checkpoint.first, checkpoint.last
            ));
            return;
        }
        if checkpoint.prev != hex(&prev) {
            status.problems.push(format!(
                "checkpoint from {} does not follow the previous one",
                checkpoint.first
            ));
            return;
        }
        let covered = usize::try_from(checkpoint.first)
            .ok()
            .zip(usize::try_from(checkpoint.last).ok())
            .and_then(|(first, last)| lines.get(first..=last));
        let Some(covered) = covered else {
            status.problems.push(format!(
                "checkpoint covers {} to {}, beyond the lines present",
                checkpoint.first, checkpoint.last
            ));
            return;
        };
        let mut hasher = seeded(&prev);
        for (_, bytes) in covered {
            hasher.update(bytes);
        }
        let hash: [u8; 32] = hasher.finalize().into();
        if checkpoint.hash != hex(&hash) {
            status.problems.push(format!(
                "lines {} to {} do not match their checkpoint",
                checkpoint.first, checkpoint.last
            ));
            return;
        }
        if let Some(current) = key {
            match signed_by(stream, checkpoint, &current) {
                Ok(following) => key = Some(following),
                Err(problem) => {
                    status.problems.push(problem);
                    return;
                }
            }
        }
        status.checkpoints = status.checkpoints.saturating_add(1);
        prev = hash;
        next = checkpoint.last.saturating_add(1);
    }
    status.verified = next;
    if status.ended && next != status.lines {
        status.problems.push(format!(
            "lines {next} to {} of an ended stream have no checkpoint",
            status.lines.saturating_sub(1)
        ));
    }
}

/// The key after `checkpoint`, once its signature by `key` holds.
fn signed_by(
    stream: &str,
    checkpoint: &Checkpoint,
    key: &VerifyingKey,
) -> Result<VerifyingKey, String> {
    let from = checkpoint.first;
    let (next_hex, signature) = checkpoint
        .signed
        .as_ref()
        .ok_or_else(|| format!("checkpoint from {from} is not signed"))?;
    let message = checkpoint_message(
        stream,
        checkpoint.first,
        checkpoint.last,
        &checkpoint.prev,
        &checkpoint.hash,
        next_hex,
    );
    let signature = unhex::<64>(signature).and_then(|bytes| Signature::from_slice(&bytes).ok());
    if signature.is_none_or(|s| key.verify(&message, &s).is_err()) {
        return Err(format!(
            "checkpoint from {from} is not signed by the stream's key"
        ));
    }
    parse_key(next_hex).ok_or_else(|| format!("checkpoint from {from} names no valid next key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> Origin {
        Origin::from("sb").with_stream("s1")
    }

    /// `n` sink event lines of stream `s1`, from seq `from`, through `chain`,
    /// with checkpoints as they fall due, then a final one.
    fn stream(n: u64) -> Vec<u8> {
        let (origin, mut chain, mut out) = (origin(), Chain::default(), Vec::new());
        for seq in 0..n {
            let start = out.len();
            sink_event(&origin, "creche.test", seq, Some(seq), &[], &mut out);
            let line = out[start..].to_vec();
            chain.absorb(&line, seq + 1, seq);
            if chain.due(seq) {
                chain.checkpoint(&origin, seq, &mut out);
            }
        }
        let start = out.len();
        sink_event(&origin, "creche.stream.end", n, Some(n), &[], &mut out);
        let line = out[start..].to_vec();
        chain.absorb(&line, n + 1, n);
        chain.checkpoint(&origin, n, &mut out);
        out
    }

    fn lines(out: &[u8]) -> Vec<&[u8]> {
        out.split_inclusive(|&b| b == b'\n').collect()
    }

    #[test]
    fn an_untouched_stream_verifies() {
        let out = stream(600);
        let report = verify(&out, None);
        let s = &report.streams["s1"];
        assert!(report.intact(), "{report:?}");
        assert_eq!(
            (s.lines, s.verified, s.checkpoints, s.ended),
            (601, 601, 3, true)
        );
    }

    #[test]
    fn repeated_deliveries_are_not_tampering() {
        let out = stream(300);
        let l = lines(&out);
        // A retried batch: lines and a checkpoint delivered twice.
        let repeated = [l.concat(), l[100..260].concat()].concat();
        let report = verify(&repeated, None);
        let s = &report.streams["s1"];
        assert!(report.intact(), "{report:?}");
        assert_eq!((s.lines, s.verified, s.duplicates), (301, 301, 160));
    }

    #[test]
    fn two_different_lines_for_one_place_still_fail() {
        let out = String::from_utf8(stream(10)).unwrap();
        let line3 = out.lines().nth(3).unwrap();
        let forged = format!("{out}{}\n", line3.replace("creche.test", "creche.tesT"));
        let report = verify(forged.as_bytes(), None);
        assert_eq!(
            report.streams["s1"].problems,
            ["two different lines claim line 3"]
        );
    }

    #[test]
    fn two_different_checkpoints_for_one_range_fail() {
        let out = String::from_utf8(stream(10)).unwrap();
        let checkpoint = out
            .lines()
            .find(|l| l.contains("creche.audit.checkpoint"))
            .unwrap();
        let tag = "\"creche.audit.hash\":\"";
        let at = checkpoint.find(tag).unwrap() + tag.len();
        let mut other = checkpoint.to_owned();
        let flipped = if &other[at..=at] == "0" { "1" } else { "0" };
        other.replace_range(at..=at, flipped);
        let forged = format!("{out}{other}\n");
        let report = verify(forged.as_bytes(), None);
        assert_eq!(
            report.streams["s1"].problems,
            ["two different checkpoints start at line 0"]
        );
    }

    #[test]
    fn a_repeat_around_a_conflicting_checkpoint_is_still_counted() {
        let out = String::from_utf8(stream(10)).unwrap();
        let checkpoint = out
            .lines()
            .find(|l| l.contains("creche.audit.checkpoint"))
            .unwrap();
        // Same place and hash, a different prev: the copies of the real
        // checkpoint must still meet, so the repeat counts once.
        let tag = "\"creche.audit.prev\":\"";
        let at = checkpoint.find(tag).unwrap() + tag.len();
        let mut other = checkpoint.to_owned();
        let flipped = if &other[at..=at] == "0" { "1" } else { "0" };
        other.replace_range(at..=at, flipped);
        let forged = format!("{out}{other}\n{checkpoint}\n");
        let report = verify(forged.as_bytes(), None);
        let s = &report.streams["s1"];
        assert_eq!(s.duplicates, 1);
        assert_eq!(s.problems, ["two different checkpoints start at line 0"]);
    }

    #[test]
    fn a_one_line_checkpoint_is_valid_and_a_backwards_one_is_not() {
        // 257 lines: a checkpoint for the first 256, then one for the last line.
        let out = stream(256);
        let report = verify(&out, None);
        assert!(report.intact(), "{report:?}");
        assert!(
            String::from_utf8_lossy(&out)
                .contains("\"creche.seq.first\":256,\"creche.seq.last\":256,")
        );

        let text = String::from_utf8(stream(600)).unwrap();
        let backwards = text.replacen("\"creche.seq.last\":511,", "\"creche.seq.last\":100,", 1);
        assert_ne!(backwards, text);
        assert_eq!(
            verify(backwards.as_bytes(), None).streams["s1"].problems,
            ["checkpoint covers 256 to 100, expected one from 256"]
        );
    }

    #[test]
    fn lines_may_arrive_in_any_order() {
        let out = stream(300);
        let mut shuffled = lines(&out);
        shuffled.reverse();
        assert!(verify(&shuffled.concat(), None).intact());
    }

    #[test]
    fn a_removed_line_is_a_gap() {
        let out = stream(10);
        let mut l = lines(&out);
        l.remove(3);
        let report = verify(&l.concat(), None);
        assert_eq!(report.streams["s1"].problems, ["expected line 3, found 4"]);
    }

    #[test]
    fn a_changed_line_breaks_its_checkpoint() {
        let out = String::from_utf8(stream(10)).unwrap();
        let changed = out.replacen("creche.test", "creche.tesT", 1);
        let report = verify(changed.as_bytes(), None);
        assert_eq!(
            report.streams["s1"].problems,
            ["lines 0 to 10 do not match their checkpoint"]
        );
    }

    #[test]
    fn swapped_lines_break_the_checkpoint() {
        // Same bytes, but their sequence numbers swapped.
        let out = String::from_utf8(stream(10)).unwrap();
        let swapped = out
            .replacen("\"creche.seq\":1,", "\"creche.seq\":X,", 1)
            .replacen("\"creche.seq\":2,", "\"creche.seq\":1,", 1)
            .replacen("\"creche.seq\":X,", "\"creche.seq\":2,", 1);
        assert!(!verify(swapped.as_bytes(), None).intact());
    }

    #[test]
    fn a_removed_checkpoint_leaves_lines_unverified() {
        let out = stream(600);
        let l: Vec<_> = lines(&out)
            .into_iter()
            .filter(|l| !String::from_utf8_lossy(l).contains("\"creche.seq.first\":512"))
            .collect();
        let report = verify(&l.concat(), None);
        let s = &report.streams["s1"];
        assert_eq!(s.verified, 512);
        assert_eq!(
            s.problems,
            ["lines 512 to 600 of an ended stream have no checkpoint"]
        );
    }

    #[test]
    fn a_forged_checkpoint_does_not_chain() {
        let out = String::from_utf8(stream(600)).unwrap();
        let forged = out.replacen(
            "\"creche.audit.prev\":\"00",
            "\"creche.audit.prev\":\"11",
            1,
        );
        let report = verify(forged.as_bytes(), None);
        assert_eq!(
            report.streams["s1"].problems,
            ["checkpoint from 0 does not follow the previous one"]
        );
    }

    #[test]
    fn checkpoints_fall_due_by_count_and_by_time() {
        let mut chain = Chain::default();
        assert!(!chain.due(u64::MAX));
        chain.absorb(b"x\n", 1, 100);
        assert!(!chain.due(100 + CHECKPOINT_NS - 1));
        assert!(chain.due(100 + CHECKPOINT_NS));
        let mut out = Vec::new();
        chain.checkpoint(&origin(), 0, &mut out);
        assert!(!chain.due(u64::MAX));
        chain.absorb(b"", 9, 0);
        assert!(!chain.due(u64::MAX), "nothing absorbed");
        chain.absorb(&b"x\n".repeat(255), CHECKPOINT_LINES, 0);
        assert!(!chain.due(0));
        chain.absorb(b"x\n", CHECKPOINT_LINES + 1, 0);
        assert!(chain.due(0));
        // A checkpoint with nothing new writes nothing.
        let mut out = Vec::new();
        chain.checkpoint(&origin(), 0, &mut out);
        let len = out.len();
        chain.checkpoint(&origin(), 0, &mut out);
        assert_eq!(out.len(), len);
    }

    #[test]
    fn other_lines_are_counted_apart() {
        let mut out = stream(2);
        sink_event(
            &Origin::from("sb"),
            "creche.sink.refused",
            0,
            None,
            &[],
            &mut out,
        );
        out.extend_from_slice(b"not json\n");
        let report = verify(&out, None);
        assert_eq!((report.outside, report.unreadable), (1, 1));
        assert!(!report.intact());
    }

    fn svid(chain: &[u8]) -> Svid {
        let key = include_bytes!("../tests/fixtures/spiffe/sink.key.der");
        Svid::from_der("spiffe://creche.test/sink", chain, key).unwrap()
    }

    fn fixture_bundle() -> TrustBundle {
        TrustBundle::from_pem(include_bytes!("../tests/fixtures/spiffe/bundle.pem")).unwrap()
    }

    fn trust(sinks: &[&str]) -> Trust {
        let sinks = sinks.iter().map(|s| (*s).to_owned()).collect();
        Trust::new(fixture_bundle(), sinks, None).unwrap()
    }

    /// Sinks named `spiffe://creche.test/{node}`, so the fixture SVID is the
    /// sink on node `sink`.
    fn on_nodes(nodes: &str) -> Trust {
        let sinks = vec![format!("spiffe://creche.test/{NODE}")];
        Trust::new(fixture_bundle(), sinks, Some(Nodes::parse(nodes).unwrap())).unwrap()
    }

    fn bundle() -> Trust {
        trust(&["spiffe://creche.test/sink"])
    }

    /// 2027-01-15, inside the fixtures' validity, in nanoseconds.
    const START_NS: u64 = 1_800_000_000_000_000_000;

    /// A signed stream of `n` lines after its start line, from `svid`, with its
    /// chain as it stands at the end.
    fn signed_stream(n: u64, svid: &Svid) -> (Vec<u8>, Chain) {
        let origin = origin();
        let (mut chain, fields) = Chain::signed("s1", svid).unwrap();
        let fields: Vec<_> = fields.iter().map(|(k, v)| (*k, Value::Str(v))).collect();
        let mut out = Vec::new();
        sink_event(
            &origin,
            "creche.stream.start",
            START_NS,
            Some(0),
            &fields,
            &mut out,
        );
        chain.absorb(&out.clone(), 1, START_NS);
        for seq in 1..=n {
            let start = out.len();
            sink_event(&origin, "creche.test", START_NS, Some(seq), &[], &mut out);
            let line = out[start..].to_vec();
            chain.absorb(&line, seq + 1, START_NS);
            if chain.due(START_NS) {
                chain.checkpoint(&origin, START_NS, &mut out);
            }
        }
        chain.checkpoint(&origin, START_NS, &mut out);
        (out, chain)
    }

    fn sink_svid() -> Svid {
        svid(include_bytes!("../tests/fixtures/spiffe/sink.der"))
    }

    #[test]
    fn a_signed_stream_verifies_against_the_bundle() {
        let (out, _) = signed_stream(600, &sink_svid());
        let report = verify(&out, Some(&bundle()));
        assert!(report.intact(), "{report:?}");
        let s = &report.streams["s1"];
        assert_eq!(s.signer.as_deref(), Some("spiffe://creche.test/sink"));
        assert!(s.trusted);
        assert_eq!((s.verified, s.checkpoints), (601, 3));
        // Without a bundle the signatures still hold, but nobody vouches for them.
        let report = verify(&out, None);
        assert!(report.intact());
        assert!(!report.streams["s1"].trusted);
        assert!(report.streams["s1"].signer.is_some());
    }

    #[test]
    fn signed_checkpoints_cannot_be_moved_or_redirected() {
        let (out, _) = signed_stream(600, &sink_svid());
        let text = String::from_utf8(out).unwrap();
        let sigs: Vec<&str> = text
            .match_indices("\"creche.audit.sig\":\"")
            .map(|(i, m)| &text[i + m.len()..i + m.len() + 128])
            .collect();
        // The first checkpoint carrying the second one's signature.
        let swapped = text.replacen(sigs[0], sigs[1], 1);
        assert_eq!(
            verify(swapped.as_bytes(), None).streams["s1"].problems,
            ["checkpoint from 0 is not signed by the stream's key"]
        );
        // A different next key: the signature covers it.
        let tag = "\"creche.audit.next_key\":\"";
        let at = text.find(tag).unwrap() + tag.len();
        let mut redirected = text.clone();
        let flipped = if &text[at..=at] == "0" { "1" } else { "0" };
        redirected.replace_range(at..=at, flipped);
        assert_eq!(
            verify(redirected.as_bytes(), None).streams["s1"].problems,
            ["checkpoint from 0 is not signed by the stream's key"]
        );
    }

    #[test]
    fn a_later_key_cannot_sign_an_earlier_checkpoint() {
        let (out, chain) = signed_stream(600, &sink_svid());
        // What someone who took over the sink at the end would hold.
        let current = &chain.ratchet.as_ref().unwrap().key;
        let text = String::from_utf8(out).unwrap();
        let first = text
            .lines()
            .find(|l| l.contains("\"creche.seq.first\":0,"))
            .unwrap();
        let field = |name: &str| {
            let tag = format!("\"{name}\":\"");
            let from = first.find(&tag).unwrap() + tag.len();
            first[from..from + first[from..].find('"').unwrap()].to_owned()
        };
        let message = checkpoint_message(
            "s1",
            0,
            first
                .split("\"creche.seq.last\":")
                .nth(1)
                .unwrap()
                .split(',')
                .next()
                .unwrap()
                .parse()
                .unwrap(),
            &field("creche.audit.prev"),
            &field("creche.audit.hash"),
            &field("creche.audit.next_key"),
        );
        let forged: Signature = current.sign(&message);
        let forged = hex(&forged.to_bytes());
        let tampered = text.replacen(&field("creche.audit.sig"), &forged, 1);
        assert_eq!(
            verify(tampered.as_bytes(), None).streams["s1"].problems,
            ["checkpoint from 0 is not signed by the stream's key"]
        );
    }

    #[test]
    fn the_start_key_must_be_the_one_the_svid_signed() {
        let (out, _) = signed_stream(10, &sink_svid());
        let text = String::from_utf8(out).unwrap();
        let tag = "\"creche.audit.key\":\"";
        let at = text.find(tag).unwrap() + tag.len();
        let mut swapped = text.clone();
        let flipped = if &text[at..=at] == "0" { "1" } else { "0" };
        swapped.replace_range(at..=at, flipped);
        assert_eq!(
            verify(swapped.as_bytes(), None).streams["s1"].problems,
            ["the SVID did not sign the stream's key"]
        );
    }

    #[test]
    fn a_bundle_requires_trusted_signed_streams() {
        let report = verify(&stream(10), Some(&bundle()));
        assert_eq!(report.streams["s1"].problems, ["the stream is not signed"]);
        let foreign = svid(include_bytes!("../tests/fixtures/spiffe/foreign.der"));
        let (out, _) = signed_stream(10, &foreign);
        let problems = &verify(&out, Some(&bundle())).streams["s1"].problems;
        assert_eq!(problems.len(), 1);
        assert!(
            problems[0].starts_with("the SVID is not trusted"),
            "{problems:?}"
        );
        // The foreign SVID's own signatures are fine without a bundle.
        assert!(verify(&out, None).intact());
    }

    #[test]
    fn only_expected_sinks_may_sign() {
        let (out, _) = signed_stream(10, &sink_svid());
        let report = verify(&out, Some(&trust(&["spiffe://creche.test/other"])));
        assert_eq!(
            report.streams["s1"].problems,
            ["signed by spiffe://creche.test/sink, which is not an expected sink"]
        );
        let report = verify(
            &out,
            Some(&trust(&[
                "spiffe://creche.test/other",
                "spiffe://creche.test/sink",
            ])),
        );
        assert!(report.intact());
    }

    #[test]
    fn a_stream_must_be_signed_by_the_sink_on_its_node() {
        let (out, _) = signed_stream(10, &sink_svid());
        // The fixture stream's sandbox is "sb", with no pod.
        let report = verify(&out, Some(&on_nodes("sb sink\n")));
        assert!(report.intact(), "{report:?}");
        assert_eq!(report.streams["s1"].node.as_deref(), Some("sink"));

        let report = verify(&out, Some(&on_nodes("sb other\nsb2 sink\n")));
        assert_eq!(
            report.streams["s1"].problems,
            ["signed by spiffe://creche.test/sink, which is not the sink on node other"]
        );
        let report = verify(&out, Some(&on_nodes("sb2 sink\n")));
        assert_eq!(
            report.streams["s1"].problems,
            ["no node is known for sandbox sb"]
        );
    }

    #[test]
    fn a_pod_uid_decides_before_the_sandbox_id() {
        let start = |pod_uid: Option<&str>| Start {
            observed_ns: 0,
            spiffe_id: String::new(),
            svid: String::new(),
            key: String::new(),
            key_sig: String::new(),
            sandbox: Some("sb".into()),
            pod_uid: pod_uid.map(Into::into),
        };
        let trust = on_nodes("sb other\nuid-1 sink\n");
        let id = "spiffe://creche.test/sink";
        assert_eq!(
            trust.allows(id, &start(Some("uid-1"))),
            Ok(Some("sink".into()))
        );
        // A pod missing from the history falls back to the sandbox id.
        assert!(trust.allows(id, &start(Some("uid-2"))).is_err());
        assert_eq!(
            trust.allows("spiffe://creche.test/other", &start(Some("uid-2"))),
            Ok(Some("other".into()))
        );
        let mut nameless = start(None);
        nameless.sandbox = None;
        assert_eq!(
            trust.allows(id, &nameless),
            Err("the stream names no sandbox".into())
        );
    }

    #[test]
    fn node_files_are_read_strictly() {
        let nodes =
            Nodes::parse("# uid node\n\nuid-1 node-a  # first\npending\nuid-1 node-a\n").unwrap();
        assert_eq!(nodes.0.len(), 1);
        assert_eq!(nodes.node_of(Some("uid-1"), None), Ok("node-a"));
        for (text, problem) in [
            (
                "uid-1 a b",
                "line 1: expected <pod uid or sandbox id> <node>",
            ),
            ("uid-1 Node", "line 1: \"Node\" is not a node name"),
            ("uid-1 a/b", "line 1: \"a/b\" is not a node name"),
            ("uid-1 -a", "line 1: \"-a\" is not a node name"),
            ("uid-1 a\nuid-1 b", "line 2: uid-1 is on both a and b"),
        ] {
            assert_eq!(Nodes::parse(text).unwrap_err(), problem, "{text}");
        }
        assert!(is_node_name("kairos-e694.lab"));
        assert!(!is_node_name(&"a".repeat(254)));
    }

    #[test]
    fn node_templates_go_with_a_node_file() {
        let template = vec![format!("spiffe://creche.test/{NODE}")];
        let plain = vec!["spiffe://creche.test/sink".to_owned()];
        assert!(Trust::new(fixture_bundle(), template.clone(), Some(Nodes::default())).is_ok());
        assert!(Trust::new(fixture_bundle(), plain.clone(), None).is_ok());
        assert_eq!(
            Trust::new(fixture_bundle(), template, None).unwrap_err(),
            "spiffe://creche.test/{node} names a node, but no nodes are known"
        );
        assert_eq!(
            Trust::new(fixture_bundle(), plain, Some(Nodes::default())).unwrap_err(),
            "spiffe://creche.test/sink does not name the node with {node}"
        );
        assert!(Trust::new(fixture_bundle(), Vec::new(), None).is_err());
    }

    #[test]
    fn signed_checkpoints_must_carry_their_signature() {
        let (out, _) = signed_stream(10, &sink_svid());
        let text = String::from_utf8(out).unwrap();
        let stripped: String = text
            .lines()
            .map(|l| match l.find(",\"creche.audit.next_key\"") {
                Some(at) => format!("{}}}\n", &l[..at]),
                None => format!("{l}\n"),
            })
            .collect();
        assert_eq!(
            verify(stripped.as_bytes(), None).streams["s1"].problems,
            ["checkpoint from 0 is not signed"]
        );
    }

    #[test]
    fn next_keys_depend_on_the_key_and_the_checkpoint() {
        let a = SigningKey::from_slice(&[1; 32]).unwrap();
        let b = SigningKey::from_slice(&[2; 32]).unwrap();
        let k = |key: &SigningKey, hash| next_key(key, hash).unwrap().to_bytes();
        assert_ne!(k(&a, &[0; 32]), k(&a, &[1; 32]));
        assert_ne!(k(&a, &[0; 32]), k(&b, &[0; 32]));
        assert_eq!(k(&a, &[0; 32]), k(&a, &[0; 32]));
        assert_ne!(k(&a, &[0; 32]), a.to_bytes());
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(unhex::<2>("00ff"), Some([0, 255]));
        assert_eq!(unhex::<2>("00f"), None);
        assert_eq!(unhex::<2>("00fff"), None);
        assert_eq!(unhex::<2>("zz00"), None);
        assert_eq!(unhex::<1>("+1"), None);
    }

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(hex(&[0, 1, 0xab, 0xff]), "0001abff");
    }
}
