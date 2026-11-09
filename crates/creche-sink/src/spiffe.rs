//! The sink's SPIFFE identity, and checking one.
//!
//! The SPIRE agent hands the sink an X.509-SVID over the SPIFFE Workload API, a
//! gRPC service on a local unix socket. The agent attests the sink by its
//! process and node, and rotates the SVID before it expires. The sink keeps no
//! key of its own: it signs each stream's first audit key with the current
//! SVID, so a stream is attributable to a SPIFFE identity (see [`crate::audit`]).
//!
//! Only P-256 SVIDs, SPIRE's default, are supported. A verifier checks the SVID
//! against the SPIFFE trust bundle with [`TrustBundle::verify`].

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf as _, Bytes, BytesMut};
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{DerSignature, Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
use prost::Message as _;
use tokio::net::UnixStream;
use tokio::sync::watch;
use x509_cert::Certificate;
use x509_cert::der::{Decode as _, Encode as _};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{BasicConstraints, SubjectAltName};

/// The Workload API method that streams the workload's X.509-SVIDs.
const FETCH_X509_SVID: &str = "/SpiffeWorkloadAPI/FetchX509SVID";
/// Longest wait between attempts to reach the agent.
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Certificates in a chain, leaf included, at most.
const MAX_CHAIN: usize = 8;
/// `ecdsa-with-SHA256`.
const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";

/// The Workload API messages used here, with the same field numbers as
/// `workload.proto`.
mod proto {
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct X509SvidRequest {}

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct X509SvidResponse {
        #[prost(message, repeated, tag = "1")]
        pub svids: Vec<X509Svid>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct X509Svid {
        #[prost(string, tag = "1")]
        pub spiffe_id: String,
        /// `x509_svid`: DER certificates, leaf first, concatenated.
        #[prost(bytes = "vec", tag = "2")]
        pub chain: Vec<u8>,
        /// `x509_svid_key`: the leaf's private key, PKCS#8 DER.
        #[prost(bytes = "vec", tag = "3")]
        pub key: Vec<u8>,
    }
}

/// An X.509-SVID the sink signs with.
pub struct Svid {
    spiffe_id: String,
    /// DER certificates, leaf first, concatenated.
    chain: Vec<u8>,
    key: SigningKey,
}

impl std::fmt::Debug for Svid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Svid")
            .field("spiffe_id", &self.spiffe_id)
            .finish_non_exhaustive()
    }
}

impl Svid {
    /// An SVID from its DER chain and PKCS#8 DER key, as the Workload API sends
    /// them.
    ///
    /// # Errors
    ///
    /// When the key is not a P-256 key or the chain does not start with a
    /// certificate for it.
    pub fn from_der(spiffe_id: &str, chain: &[u8], key: &[u8]) -> Result<Self, String> {
        let key = SigningKey::from_pkcs8_der(key)
            .map_err(|e| format!("the SVID key is not a P-256 key: {e}"))?;
        let leaf = certificates(chain)?
            .into_iter()
            .next()
            .ok_or("empty SVID chain")?;
        if public_key(&leaf)? != *key.verifying_key() {
            return Err("the SVID key does not match its certificate".to_owned());
        }
        Ok(Self {
            spiffe_id: spiffe_id.to_owned(),
            chain: chain.to_vec(),
            key,
        })
    }

    /// The SVID's SPIFFE ID.
    #[must_use]
    pub fn spiffe_id(&self) -> &str {
        &self.spiffe_id
    }

    /// The DER certificate chain, leaf first, concatenated.
    #[must_use]
    pub fn chain(&self) -> &[u8] {
        &self.chain
    }

    /// An ECDSA P-256 SHA-256 signature of `message`, DER encoded.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature: Signature = self.key.sign(message);
        signature.to_der().as_bytes().to_vec()
    }
}

/// The certificates in `der`, one after another.
fn certificates(mut der: &[u8]) -> Result<Vec<Certificate>, String> {
    let mut chain = Vec::new();
    while !der.is_empty() {
        if chain.len() == MAX_CHAIN {
            return Err(format!("more than {MAX_CHAIN} certificates"));
        }
        let (cert, rest) =
            Certificate::from_der_partial(der).map_err(|e| format!("bad certificate: {e}"))?;
        chain.push(cert);
        der = rest;
    }
    Ok(chain)
}

/// The P-256 key a certificate certifies.
fn public_key(cert: &Certificate) -> Result<VerifyingKey, String> {
    let spki = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| e.to_string())?;
    VerifyingKey::from_public_key_der(&spki).map_err(|_| "not a P-256 key".to_owned())
}

/// Whether `issuer` signed `cert`, with ECDSA P-256 and SHA-256.
fn signed_by(cert: &Certificate, issuer: &Certificate) -> bool {
    if cert.signature_algorithm().oid.to_string() != ECDSA_WITH_SHA256
        || cert.tbs_certificate().issuer() != issuer.tbs_certificate().subject()
    {
        return false;
    }
    let (Ok(key), Ok(tbs), Some(signature)) = (
        public_key(issuer),
        cert.tbs_certificate().to_der(),
        cert.signature().as_bytes(),
    ) else {
        return false;
    };
    Signature::from_der(signature).is_ok_and(|s| key.verify(&tbs, &s).is_ok())
}

/// Whether `cert` is valid at `at`, in seconds since the Unix epoch.
fn valid_at(cert: &Certificate, at: u64) -> bool {
    let validity = cert.tbs_certificate().validity();
    validity.not_before.to_unix_duration().as_secs() <= at
        && at <= validity.not_after.to_unix_duration().as_secs()
}

/// Whether `cert` is a CA certificate.
fn is_ca(cert: &Certificate) -> bool {
    matches!(
        cert.tbs_certificate().get_extension::<BasicConstraints>(),
        Ok(Some((_, BasicConstraints { ca: true, .. })))
    )
}

/// The SPIFFE ID in a certificate's URI SAN, when it has exactly one.
fn spiffe_id(cert: &Certificate) -> Option<String> {
    let (_, san) = cert
        .tbs_certificate()
        .get_extension::<SubjectAltName>()
        .ok()??;
    let mut uris = san.0.iter().filter_map(|name| match name {
        GeneralName::UniformResourceIdentifier(uri) => Some(uri.to_string()),
        _ => None,
    });
    let uri = uris.next().filter(|u| u.starts_with("spiffe://"))?;
    uris.next().is_none().then_some(uri)
}

/// The CA certificates a verifier trusts for SVIDs: a SPIFFE trust bundle.
#[derive(Clone, Debug)]
pub struct TrustBundle {
    roots: Vec<Certificate>,
}

impl TrustBundle {
    /// The CA certificates in PEM `text`, as `spire-server bundle show` prints
    /// them.
    ///
    /// # Errors
    ///
    /// When `text` holds no certificate or one that does not parse.
    pub fn from_pem(text: &[u8]) -> Result<Self, String> {
        let roots = Certificate::load_pem_chain(text).map_err(|e| e.to_string())?;
        if roots.is_empty() {
            return Err("no certificate in the trust bundle".to_owned());
        }
        Ok(Self { roots })
    }

    /// Checks an SVID chain, DER certificates concatenated leaf first, at time
    /// `at` in seconds since the Unix epoch. Returns the SPIFFE ID and the leaf
    /// key.
    ///
    /// The leaf must carry one SPIFFE ID, not be a CA and chain, through CA
    /// intermediates in `chain`, to a certificate in this bundle. Every
    /// certificate must be valid at `at`.
    ///
    /// # Errors
    ///
    /// Why the SVID is not trusted.
    pub fn verify(&self, chain: &[u8], at: u64) -> Result<(String, VerifyingKey), String> {
        let certs = certificates(chain)?;
        let (leaf, intermediates) = certs.split_first().ok_or("empty SVID chain")?;
        let id = spiffe_id(leaf).ok_or("the leaf has no single SPIFFE ID")?;
        if is_ca(leaf) {
            return Err("the leaf is a CA certificate".to_owned());
        }
        let mut current = leaf;
        for _ in 0..MAX_CHAIN {
            if !valid_at(current, at) {
                return Err(
                    "a certificate in the chain is not valid at the stream's start".to_owned(),
                );
            }
            if self
                .roots
                .iter()
                .any(|root| valid_at(root, at) && signed_by(current, root))
            {
                return Ok((id, public_key(leaf)?));
            }
            current = intermediates
                .iter()
                .find(|i| is_ca(i) && signed_by(current, i))
                .ok_or("the chain does not lead to the trust bundle")?;
        }
        Err("the chain is too long".to_owned())
    }
}

/// Checks that `signature`, DER encoded, is `key`'s over `message`.
#[must_use]
pub fn verify_signature(key: &VerifyingKey, message: &[u8], signature: &[u8]) -> bool {
    DerSignature::try_from(signature).is_ok_and(|s| key.verify(message, &s).is_ok())
}

/// The leaf key of an SVID chain, without checking whom it chains to.
///
/// # Errors
///
/// When the chain does not parse or its leaf is not a P-256 key.
pub fn leaf_key(chain: &[u8]) -> Result<(Option<String>, VerifyingKey), String> {
    let leaf = certificates(chain)?
        .into_iter()
        .next()
        .ok_or("empty SVID chain")?;
    Ok((spiffe_id(&leaf), public_key(&leaf)?))
}

/// Keeps `svid` set to the workload's current X.509-SVID from the Workload API
/// at `socket`, reconnecting whenever the agent goes away, until every receiver
/// is gone.
pub async fn watch(socket: PathBuf, svid: watch::Sender<Option<Arc<Svid>>>) {
    let mut backoff = Duration::from_secs(1);
    while !svid.is_closed() {
        match fetch(&socket, &svid).await {
            Ok(()) => backoff = Duration::from_secs(1),
            Err(e) => {
                eprintln!(
                    "creche-sink: SPIFFE Workload API at {}: {e}",
                    socket.display()
                );
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
    }
}

/// One `FetchX509SVID` stream: every update the agent sends replaces `svid`.
async fn fetch(socket: &PathBuf, svid: &watch::Sender<Option<Arc<Svid>>>) -> io::Result<()> {
    let stream = UnixStream::connect(socket).await?;
    let (client, connection) = h2::client::handshake(stream)
        .await
        .map_err(io::Error::other)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut client = client.ready().await.map_err(io::Error::other)?;
    let request = http::Request::post(format!("http://localhost{FETCH_X509_SVID}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("workload.spiffe.io", "true")
        .body(())
        .map_err(io::Error::other)?;
    let (response, mut send) = client
        .send_request(request, false)
        .map_err(io::Error::other)?;
    // An empty request message: not compressed, zero length.
    let empty = proto::X509SvidRequest {}.encode_to_vec();
    let mut frame = vec![0, 0, 0, 0, 0];
    frame.extend_from_slice(&empty);
    send.send_data(Bytes::from(frame), true)
        .map_err(io::Error::other)?;
    let response = response.await.map_err(io::Error::other)?;
    if let Some(status) = response.headers().get("grpc-status") {
        return Err(io::Error::other(format!("grpc status {status:?}")));
    }
    let mut body = response.into_body();
    let mut buffer = BytesMut::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(io::Error::other)?;
        let _ = body.flow_control().release_capacity(chunk.len());
        buffer.extend_from_slice(&chunk);
        while let Some(message) = next_message(&mut buffer)? {
            let update = proto::X509SvidResponse::decode(message).map_err(io::Error::other)?;
            let first = update
                .svids
                .first()
                .ok_or_else(|| io::Error::other("an update without SVIDs"))?;
            let current = Svid::from_der(&first.spiffe_id, &first.chain, &first.key)
                .map_err(io::Error::other)?;
            eprintln!("creche-sink: signing as {}", current.spiffe_id());
            svid.send_replace(Some(Arc::new(current)));
        }
    }
    Ok(())
}

/// Takes the next whole gRPC message off the front of `buffer`, if there is
/// one. Compressed messages are refused: none was asked for.
fn next_message(buffer: &mut BytesMut) -> io::Result<Option<Bytes>> {
    let Some(header) = buffer.get(..5) else {
        return Ok(None);
    };
    let compressed = header.first().copied().unwrap_or(0);
    let len = header
        .get(1..5)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_be_bytes)
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(usize::MAX);
    if compressed != 0 {
        return Err(io::Error::other("compressed Workload API message"));
    }
    if len > 4 << 20 {
        return Err(io::Error::other("Workload API message too large"));
    }
    if buffer.len() < len.saturating_add(5) {
        return Ok(None);
    }
    buffer.advance(5);
    Ok(Some(buffer.split_to(len).freeze()))
}

#[cfg(test)]
mod tests;
