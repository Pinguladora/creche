use tokio::net::UnixListener;

use super::*;

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!("../../tests/fixtures/spiffe/", $name))
    };
}

/// 2027-01-15, inside the fixtures' validity.
const NOW: u64 = 1_800_000_000;
const ID: &str = "spiffe://creche.test/sink";

fn bundle() -> TrustBundle {
    TrustBundle::from_pem(fixture!("bundle.pem")).unwrap()
}

fn svid() -> Svid {
    Svid::from_der(ID, fixture!("sink.der"), fixture!("sink.key.der")).unwrap()
}

#[test]
fn an_svid_needs_a_p256_key_matching_its_certificate() {
    let svid = svid();
    assert_eq!(svid.spiffe_id(), ID);
    assert_eq!(svid.chain(), fixture!("sink.der"));
    assert!(format!("{svid:?}").contains(ID));
    let mismatched = Svid::from_der(ID, fixture!("not-ca.der"), fixture!("sink.key.der"));
    assert_eq!(
        mismatched.unwrap_err(),
        "the SVID key does not match its certificate"
    );
    assert!(Svid::from_der(ID, fixture!("sink.der"), b"not a key").is_err());
    assert_eq!(
        Svid::from_der(ID, b"", fixture!("sink.key.der")).unwrap_err(),
        "empty SVID chain"
    );
}

#[test]
fn signatures_verify_with_the_leaf_key_only_for_their_message() {
    let svid = svid();
    let signature = svid.sign(b"creche stream key v1\n");
    let (id, key) = leaf_key(svid.chain()).unwrap();
    assert_eq!(id.as_deref(), Some(ID));
    assert!(verify_signature(
        &key,
        b"creche stream key v1\n",
        &signature
    ));
    assert!(!verify_signature(
        &key,
        b"creche stream key v2\n",
        &signature
    ));
    assert!(!verify_signature(
        &key,
        b"creche stream key v1\n",
        b"garbage"
    ));
}

#[test]
fn svids_that_chain_to_the_bundle_are_trusted() {
    let (id, key) = bundle().verify(fixture!("sink.der"), NOW).unwrap();
    assert_eq!(id, ID);
    assert_eq!(key, *svid().key.verifying_key());
    let chain = [&fixture!("via-inter.der")[..], fixture!("inter.der")].concat();
    assert_eq!(bundle().verify(&chain, NOW).unwrap().0, ID);
}

#[test]
fn other_svids_are_refused_with_the_reason() {
    let cases: [(&[u8], u64, &str); 9] = [
        (
            fixture!("expired.der"),
            NOW,
            "not valid at the stream's start",
        ),
        (
            fixture!("sink.der"),
            1_700_000_000,
            "not valid at the stream's start",
        ),
        (
            fixture!("foreign.der"),
            NOW,
            "does not lead to the trust bundle",
        ),
        (
            fixture!("via-inter.der"),
            NOW,
            "does not lead to the trust bundle",
        ),
        (fixture!("no-spiffe-id.der"), NOW, "no single SPIFFE ID"),
        (
            fixture!("leaf-is-ca.der"),
            NOW,
            "the leaf is a CA certificate",
        ),
        (b"", NOW, "empty SVID chain"),
        (b"garbage", NOW, "bad certificate"),
        (
            &fixture!("sink.der").repeat(9),
            NOW,
            "more than 8 certificates",
        ),
    ];
    for (chain, at, reason) in cases {
        let err = bundle().verify(chain, at).unwrap_err();
        assert!(err.contains(reason), "{err} should say {reason}");
    }
    let through_non_ca = [&fixture!("via-not-ca.der")[..], fixture!("not-ca.der")].concat();
    assert!(bundle().verify(&through_non_ca, NOW).is_err());
}

#[test]
fn trust_bundles_need_certificates() {
    assert!(TrustBundle::from_pem(b"").is_err());
    assert!(
        TrustBundle::from_pem(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
            .is_err()
    );
    assert!(format!("{:?}", bundle()).contains("roots"));
}

fn frame(message: &[u8]) -> Vec<u8> {
    let mut f = vec![0];
    f.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
    f.extend_from_slice(message);
    f
}

#[test]
fn grpc_messages_are_cut_from_a_buffer() {
    let mut buffer = BytesMut::new();
    assert!(next_message(&mut buffer).unwrap().is_none());
    let both = [frame(b"one"), frame(b"two")].concat();
    buffer.extend_from_slice(&both[..6]);
    assert!(next_message(&mut buffer).unwrap().is_none(), "partial");
    buffer.extend_from_slice(&both[6..]);
    assert_eq!(&next_message(&mut buffer).unwrap().unwrap()[..], b"one");
    assert_eq!(&next_message(&mut buffer).unwrap().unwrap()[..], b"two");
    assert!(next_message(&mut buffer).unwrap().is_none());
    assert!(buffer.is_empty());
    buffer.extend_from_slice(&[1, 0, 0, 0, 0]);
    assert!(next_message(&mut buffer).is_err(), "compressed");
    let mut big = BytesMut::from(&[0, 0, 0x40, 0, 1][..]);
    assert!(next_message(&mut big).is_err(), "too large");
}

#[test]
fn the_workload_api_keeps_the_current_svid() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let tmp = tempfile::tempdir().unwrap();
            let socket = tmp.path().join("agent.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let agent = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut connection = h2::server::handshake(stream).await.unwrap();
                let (request, mut respond) = connection.accept().await.unwrap().unwrap();
                let (parts, _) = request.into_parts();
                let response = http::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .body(())
                    .unwrap();
                let mut send = respond.send_response(response, false).unwrap();
                let update = proto::X509SvidResponse {
                    svids: vec![proto::X509Svid {
                        spiffe_id: ID.to_owned(),
                        chain: fixture!("sink.der").to_vec(),
                        key: fixture!("sink.key.der").to_vec(),
                    }],
                }
                .encode_to_vec();
                // Split across two DATA frames, as an agent may.
                let framed = frame(&update);
                let (a, b) = framed.split_at(7);
                send.send_data(Bytes::copy_from_slice(a), false).unwrap();
                send.send_data(Bytes::copy_from_slice(b), false).unwrap();
                tokio::spawn(async move { while connection.accept().await.is_some() {} });
                (parts, send)
            });
            let (tx, mut rx) = watch::channel(None);
            let watcher = tokio::spawn(watch(socket, tx));
            tokio::time::timeout(Duration::from_secs(5), rx.changed())
                .await
                .unwrap()
                .unwrap();
            let current = rx.borrow().clone().unwrap();
            assert_eq!(current.spiffe_id(), ID);
            let (parts, _send) = agent.await.unwrap();
            assert_eq!(parts.uri.path(), FETCH_X509_SVID);
            assert_eq!(parts.headers["workload.spiffe.io"], "true");
            drop(rx);
            watcher.abort();
        });
}
