use std::io::Read as _;

use tokio::net::TcpListener;

use super::*;
use crate::json::{Attribution, Value, sink_event};
use crate::k8s::Pod;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn pod_origin() -> Arc<Origin> {
    let pod = Pod {
        name: "agent-7".into(),
        namespace: "agents".into(),
        uid: "1f2e".into(),
    };
    Arc::new(Origin::new("sb1", &Attribution::Pod(pod)).with_stream("18e6-0"))
}

/// A batch of `names` as sink event lines from `origin`.
fn batch(origin: &Arc<Origin>, names: &[&str], observed_ns: u64) -> Batch {
    let mut lines = Vec::new();
    for (seq, name) in (0..).zip(names) {
        let fields = [("creche.note", Value::Str("a \"quoted\" value"))];
        sink_event(origin, name, observed_ns, Some(seq), &fields, &mut lines);
    }
    Batch {
        origin: Arc::clone(origin),
        observed_ns,
        lines,
    }
}

fn decode(body: &[u8]) -> proto::ExportLogsServiceRequest {
    let mut message = Vec::new();
    ruzstd::decoding::StreamingDecoder::new(body)
        .unwrap()
        .read_to_end(&mut message)
        .unwrap();
    proto::ExportLogsServiceRequest::decode(message.as_slice()).unwrap()
}

fn attributes(r: &proto::ResourceLogs) -> Vec<(String, String)> {
    r.resource
        .as_ref()
        .unwrap()
        .attributes
        .iter()
        .map(|kv| {
            let value = kv.value.as_ref().unwrap().string_value.clone().unwrap();
            (kv.key.clone(), value)
        })
        .collect()
}

#[test]
fn endpoints_default_their_port_and_path() {
    let parse = |url, protocol| Endpoint::parse(url, protocol).map(|e| (e.authority, e.path));
    let ok = |a: &str, p: &str| Ok((a.to_owned(), p.to_owned()));
    assert_eq!(
        parse("http://127.0.0.1", Protocol::Grpc),
        ok("127.0.0.1:4317", "/v1/logs")
    );
    assert_eq!(
        parse("http://otel:4318/", Protocol::Http),
        ok("otel:4318", "/v1/logs")
    );
    assert_eq!(
        parse("http://otel", Protocol::Http),
        ok("otel:4318", "/v1/logs")
    );
    assert_eq!(
        parse("http://otel:9/x/logs", Protocol::Http),
        ok("otel:9", "/x/logs")
    );
    assert_eq!(
        parse("http://[::1]", Protocol::Grpc),
        ok("[::1]:4317", "/v1/logs")
    );
    assert_eq!(
        parse("http://[::1]:5000", Protocol::Grpc),
        ok("[::1]:5000", "/v1/logs")
    );
    assert!(
        parse("https://otel:4317", Protocol::Grpc)
            .unwrap_err()
            .contains("TLS")
    );
    for url in [
        "otel:4317",
        "http://",
        "http:///v1/logs",
        "http://user@otel",
        "grpc://otel",
    ] {
        assert!(parse(url, Protocol::Grpc).is_err(), "{url}");
    }
    let endpoint = Endpoint::parse("http://otel", Protocol::Http).unwrap();
    assert_eq!(endpoint.to_string(), "http http://otel:4318/v1/logs");
    let endpoint = Endpoint::parse("http://otel", Protocol::Grpc).unwrap();
    assert_eq!(endpoint.to_string(), "grpc http://otel:4317");
}

#[test]
fn event_names_come_right_after_the_origin() {
    let origin = pod_origin();
    let b = batch(&origin, &["creche.stream.start"], 1);
    let line = std::str::from_utf8(&b.lines).unwrap();
    assert_eq!(event_name(&origin, line), "creche.stream.start");
    assert_eq!(event_name(&origin, "{\"other\":1}"), "");
    assert_eq!(event_name(&origin, ""), "");
}

#[test]
fn each_stream_is_a_resource_and_each_line_a_record_with_its_exact_text() {
    let (a, b) = (
        pod_origin(),
        Arc::new(Origin::from("sb2").with_stream("18e6-1")),
    );
    let batches = [
        batch(&a, &["creche.stream.start", "creche.observer.hello"], 10),
        batch(&b, &["creche.sink.refused"], 20),
        batch(&a, &["creche.stream.end"], 30),
    ];
    let request = decode(&encode(&batches));
    assert_eq!(request.resource_logs.len(), 2);
    assert_eq!(
        attributes(&request.resource_logs[0]),
        [
            ("service.name", "creche-sink"),
            ("creche.sandbox.id", "sb1"),
            ("k8s.pod.name", "agent-7"),
            ("k8s.namespace.name", "agents"),
            ("k8s.pod.uid", "1f2e"),
            ("creche.stream.id", "18e6-0"),
        ]
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
    );
    let scope = &request.resource_logs[0].scope_logs[0];
    assert_eq!(scope.scope.as_ref().unwrap().name, "creche-sink");
    let records: Vec<_> = scope
        .log_records
        .iter()
        .map(|r| (r.event_name.as_str(), r.observed_time_unix_nano))
        .collect();
    assert_eq!(
        records,
        [
            ("creche.stream.start", 10),
            ("creche.observer.hello", 10),
            ("creche.stream.end", 30)
        ]
    );
    // The bodies, each with its newline back, are the bytes the sink wrote.
    let bodies: Vec<u8> = scope
        .log_records
        .iter()
        .flat_map(|r| {
            let text = r.body.as_ref().unwrap().string_value.clone().unwrap();
            text.into_bytes().into_iter().chain(*b"\n")
        })
        .collect();
    assert_eq!(
        bodies,
        [batches[0].lines.clone(), batches[2].lines.clone()].concat()
    );
    assert_eq!(request.resource_logs[1].scope_logs[0].log_records.len(), 1);
}

#[test]
fn http_status_lines_are_read() {
    assert_eq!(status_code(b"HTTP/1.1 200 OK\r\n\r\n"), Some(200));
    assert_eq!(status_code(b"HTTP/1.0 503 Busy\r\n"), Some(503));
    assert_eq!(status_code(b"HTTP/2 200\r\n"), None);
    assert_eq!(status_code(b"garbage"), None);
    assert_eq!(status_code(b""), None);
}

#[test]
fn only_transient_grpc_statuses_are_retried() {
    let retried: Vec<u32> = (0..17).filter(|&c| grpc_retryable(c)).collect();
    assert_eq!(retried, [1, 4, 8, 10, 11, 14, 15]);
}

/// Reads one HTTP/1.1 request: its head and its body.
async fn read_http(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut data = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let n = stream.read(&mut chunk).await.unwrap();
        data.extend_from_slice(&chunk[..n]);
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8(data[..end].to_vec()).unwrap();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .unwrap()
                .parse()
                .unwrap();
            let mut body = data[end + 4..].to_vec();
            while body.len() < len {
                let n = stream.read(&mut chunk).await.unwrap();
                body.extend_from_slice(&chunk[..n]);
            }
            return (head, body);
        }
    }
}

#[test]
fn http_export_retries_until_the_collector_takes_the_lines() {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let collector = tokio::spawn(async move {
            let mut requests = Vec::new();
            for status in ["503 Busy", "200 OK"] {
                let (mut stream, _) = listener.accept().await.unwrap();
                requests.push(read_http(&mut stream).await);
                let reply = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n");
                stream.write_all(reply.as_bytes()).await.unwrap();
            }
            requests
        });
        let (tx, rx) = mpsc::channel(4);
        let origin = pod_origin();
        tx.send(batch(&origin, &["creche.stream.start"], 5))
            .await
            .unwrap();
        drop(tx);
        export(Endpoint::parse(&url, Protocol::Http).unwrap(), rx).await;
        let requests = collector.await.unwrap();
        assert_eq!(requests.len(), 2);
        let (head, body) = &requests[1];
        assert!(head.starts_with("POST /v1/logs HTTP/1.1\r\n"), "{head}");
        assert!(
            head.contains("\r\nContent-Type: application/x-protobuf"),
            "{head}"
        );
        assert!(head.contains("\r\nContent-Encoding: zstd"), "{head}");
        let request = decode(body);
        assert_eq!(request.resource_logs[0].scope_logs[0].log_records.len(), 1);
    });
}

#[test]
fn http_export_gives_up_on_a_rejection() {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let collector = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_http(&mut stream).await;
            stream.write_all(b"HTTP/1.1 400 Bad\r\n\r\n").await.unwrap();
            drop(stream);
            // No second attempt arrives.
            timeout(Duration::from_millis(600), listener.accept())
                .await
                .is_err()
        });
        let (tx, rx) = mpsc::channel(4);
        tx.send(batch(&pod_origin(), &["creche.stream.start"], 5))
            .await
            .unwrap();
        drop(tx);
        export(Endpoint::parse(&url, Protocol::Http).unwrap(), rx).await;
        assert!(collector.await.unwrap());
    });
}

#[test]
fn grpc_export_sends_zstd_messages_and_retries_unavailable() {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let collector = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(tcp).await.unwrap();
            let mut seen = Vec::new();
            for status in ["14", "0"] {
                let (request, mut respond) = connection.accept().await.unwrap().unwrap();
                let (parts, mut body) = request.into_parts();
                let mut message = Vec::new();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.unwrap();
                    let _ = body.flow_control().release_capacity(chunk.len());
                    message.extend_from_slice(&chunk);
                }
                seen.push((parts, message));
                let response = http::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .body(())
                    .unwrap();
                let mut stream = respond.send_response(response, false).unwrap();
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", status.parse().unwrap());
                stream.send_trailers(trailers).unwrap();
            }
            // Keep the connection served until the client is done.
            tokio::spawn(async move { while connection.accept().await.is_some() {} });
            seen
        });
        let (tx, rx) = mpsc::channel(4);
        let origin = pod_origin();
        tx.send(batch(
            &origin,
            &["creche.stream.start", "creche.stream.end"],
            7,
        ))
        .await
        .unwrap();
        drop(tx);
        export(Endpoint::parse(&url, Protocol::Grpc).unwrap(), rx).await;
        let seen = collector.await.unwrap();
        assert_eq!(seen.len(), 2, "retried once on the same connection");
        let (parts, message) = &seen[1];
        assert_eq!(parts.uri.path(), GRPC_PATH);
        assert_eq!(parts.headers["grpc-encoding"], "zstd");
        assert_eq!(parts.headers["te"], "trailers");
        assert_eq!(message[0], 1, "compressed");
        let len = u32::from_be_bytes(message[1..5].try_into().unwrap());
        assert_eq!(len as usize, message.len() - 5);
        let request = decode(&message[5..]);
        let records = &request.resource_logs[0].scope_logs[0].log_records;
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].event_name, "creche.stream.end");
    });
}

#[test]
fn grpc_export_gives_up_on_a_permanent_status() {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let collector = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(tcp).await.unwrap();
            let (_, mut respond) = connection.accept().await.unwrap().unwrap();
            let response = http::Response::builder().status(200).body(()).unwrap();
            let mut stream = respond.send_response(response, false).unwrap();
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", "3".parse().unwrap());
            stream.send_trailers(trailers).unwrap();
            // No second request arrives before the client hangs up.
            !matches!(
                timeout(Duration::from_millis(600), connection.accept()).await,
                Ok(Some(_))
            )
        });
        let (tx, rx) = mpsc::channel(4);
        tx.send(batch(&pod_origin(), &["creche.stream.start"], 5))
            .await
            .unwrap();
        drop(tx);
        export(Endpoint::parse(&url, Protocol::Grpc).unwrap(), rx).await;
        assert!(collector.await.unwrap());
    });
}

#[test]
fn an_unreachable_collector_is_retried_then_dropped() {
    runtime().block_on(async {
        // A port nothing listens on: bind, note it, close.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let (tx, rx) = mpsc::channel(4);
        tx.send(batch(&pod_origin(), &["creche.stream.start"], 5))
            .await
            .unwrap();
        drop(tx);
        let started = Instant::now();
        export(Endpoint::parse(&url, Protocol::Http).unwrap(), rx).await;
        // Four waits between five attempts: 250 + 500 + 1000 + 2000 ms.
        assert!(started.elapsed() >= Duration::from_millis(3750));
    });
}
