//! Exporting the JSON lines as OpenTelemetry logs (OTLP).
//!
//! Each line becomes one log record whose body is the line's exact text, so a
//! collector can parse it into attributes while the bytes the audit chain covers
//! survive unchanged (see [`crate::audit`]). The stream's attested origin, its
//! sandbox, pod and stream id, becomes the resource. Requests are protobuf,
//! zstd compressed, sent with gRPC (`LogsService/Export`) by default or with
//! OTLP/HTTP as a fallback, in cleartext to a collector on the node. That
//! collector owns TLS and authentication onward.
//!
//! The exporter never holds up the sink's own output: lines reach it through a
//! bounded queue, and when the queue is full they are dropped and counted. A
//! dropped line shows downstream as a gap in its stream's `creche.seq`.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use prost::Message as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};

use crate::json::Origin;

/// Lines sent per request at most, as uncompressed bytes.
const MAX_REQUEST: usize = 1 << 20;
/// Longest a line waits in the exporter before its request is sent.
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
/// Attempts per request before its lines are dropped.
const ATTEMPTS: u32 = 5;
/// Wait before the first retry. It doubles for each further one.
const FIRST_BACKOFF: Duration = Duration::from_millis(250);
/// Longest a connection, a request or its response may take.
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest HTTP response read, headers and body.
const MAX_RESPONSE: usize = 64 * 1024;
/// gRPC method of the OTLP logs service.
const GRPC_PATH: &str = "/opentelemetry.proto.collector.logs.v1.LogsService/Export";

/// How requests travel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Protocol {
    /// OTLP over gRPC, port 4317 by default.
    #[default]
    Grpc,
    /// OTLP over HTTP/1.1, port 4318 by default.
    Http,
}

/// Where the collector listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// How requests travel.
    pub protocol: Protocol,
    /// `host:port`, as connected to and as sent in requests.
    authority: String,
    /// Request path for OTLP/HTTP.
    path: String,
}

impl Endpoint {
    /// Reads `http://host[:port][/path]`. The port defaults to the protocol's
    /// and the OTLP/HTTP path to `/v1/logs`.
    ///
    /// # Errors
    ///
    /// When `url` is not a cleartext `http` URL with a host.
    pub fn parse(url: &str, protocol: Protocol) -> Result<Self, String> {
        let rest = url.strip_prefix("http://").ok_or_else(|| {
            if url.starts_with("https://") {
                "TLS is left to the collector: export to a collector on the node over http://"
                    .to_owned()
            } else {
                format!("{url}: expected http://host[:port]")
            }
        })?;
        let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        if authority.is_empty() || authority.contains(['@', ' ']) {
            return Err(format!("{url}: expected http://host[:port]"));
        }
        // A port follows the last colon, unless that colon is inside an IPv6 literal.
        let has_port = authority
            .rsplit_once(':')
            .is_some_and(|(host, port)| !host.ends_with(':') && !port.ends_with(']'));
        let authority = if has_port {
            authority.to_owned()
        } else {
            let port = match protocol {
                Protocol::Grpc => 4317,
                Protocol::Http => 4318,
            };
            format!("{authority}:{port}")
        };
        let path = if path.is_empty() || path == "/" {
            "/v1/logs".to_owned()
        } else {
            path.to_owned()
        };
        Ok(Self {
            protocol,
            authority,
            path,
        })
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.protocol {
            Protocol::Grpc => write!(f, "grpc http://{}", self.authority),
            Protocol::Http => write!(f, "http http://{}{}", self.authority, self.path),
        }
    }
}

/// Lines from one stream, as the sink wrote them.
#[derive(Clone, Debug)]
pub struct Batch {
    /// What every line starts with: the stream's attested origin.
    pub origin: Arc<Origin>,
    /// When the lines were written, in nanoseconds since the Unix epoch.
    pub observed_ns: u64,
    /// Whole lines, each ending in a newline.
    pub lines: Vec<u8>,
}

/// The OTLP messages used here, a subset of `opentelemetry/proto` with the same
/// field numbers.
mod proto {
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ExportLogsServiceRequest {
        #[prost(message, repeated, tag = "1")]
        pub resource_logs: Vec<ResourceLogs>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ResourceLogs {
        #[prost(message, optional, tag = "1")]
        pub resource: Option<Resource>,
        #[prost(message, repeated, tag = "2")]
        pub scope_logs: Vec<ScopeLogs>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Resource {
        #[prost(message, repeated, tag = "1")]
        pub attributes: Vec<KeyValue>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct KeyValue {
        #[prost(string, tag = "1")]
        pub key: String,
        #[prost(message, optional, tag = "2")]
        pub value: Option<AnyValue>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct AnyValue {
        #[prost(string, optional, tag = "1")]
        pub string_value: Option<String>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ScopeLogs {
        #[prost(message, optional, tag = "1")]
        pub scope: Option<InstrumentationScope>,
        #[prost(message, repeated, tag = "2")]
        pub log_records: Vec<LogRecord>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct InstrumentationScope {
        #[prost(string, tag = "1")]
        pub name: String,
        #[prost(string, tag = "2")]
        pub version: String,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct LogRecord {
        #[prost(message, optional, tag = "5")]
        pub body: Option<AnyValue>,
        #[prost(fixed64, tag = "11")]
        pub observed_time_unix_nano: u64,
        #[prost(string, tag = "12")]
        pub event_name: String,
    }
}

fn string(value: &str) -> proto::AnyValue {
    proto::AnyValue {
        string_value: Some(value.to_owned()),
    }
}

/// The `event.name` of a line the sink wrote for `origin`: every line starts
/// with the origin's attributes, then the event name.
fn event_name<'a>(origin: &Origin, line: &'a str) -> &'a str {
    let prefix_len = origin.json_len();
    line.get(prefix_len..)
        .and_then(|rest| rest.strip_prefix(",\"event.name\":\""))
        .and_then(|rest| rest.split_once('"'))
        .map_or("", |(name, _)| name)
}

/// The export request for `batches`, one resource per stream.
fn request(batches: &[Batch]) -> proto::ExportLogsServiceRequest {
    let mut resources: Vec<proto::ResourceLogs> = Vec::new();
    let mut index: HashMap<*const Origin, usize> = HashMap::new();
    for batch in batches {
        let at = *index.entry(Arc::as_ptr(&batch.origin)).or_insert_with(|| {
            resources.push(proto::ResourceLogs {
                resource: Some(proto::Resource {
                    attributes: std::iter::once(("service.name", "creche-sink"))
                        .chain(batch.origin.attributes())
                        .map(|(key, value)| proto::KeyValue {
                            key: key.to_owned(),
                            value: Some(string(value)),
                        })
                        .collect(),
                }),
                scope_logs: vec![proto::ScopeLogs {
                    scope: Some(proto::InstrumentationScope {
                        name: "creche-sink".to_owned(),
                        version: env!("CARGO_PKG_VERSION").to_owned(),
                    }),
                    log_records: Vec::new(),
                }],
            });
            resources.len().saturating_sub(1)
        });
        let Some(records) = resources
            .get_mut(at)
            .and_then(|r| r.scope_logs.first_mut())
            .map(|s| &mut s.log_records)
        else {
            continue;
        };
        let text = String::from_utf8_lossy(&batch.lines);
        for line in text.lines() {
            records.push(proto::LogRecord {
                body: Some(string(line)),
                observed_time_unix_nano: batch.observed_ns,
                event_name: event_name(&batch.origin, line).to_owned(),
            });
        }
    }
    proto::ExportLogsServiceRequest {
        resource_logs: resources,
    }
}

/// The zstd-compressed protobuf encoding of the request for `batches`.
fn encode(batches: &[Batch]) -> Vec<u8> {
    let message = request(batches).encode_to_vec();
    ruzstd::encoding::compress_to_vec(
        message.as_slice(),
        ruzstd::encoding::CompressionLevel::Fastest,
    )
}

/// How an attempt ended.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The collector took the lines.
    Accepted,
    /// Worth trying again: the collector is busy or unreachable.
    Retry(String),
    /// The collector refused the lines for good.
    Rejected(String),
}

/// gRPC status codes worth retrying: cancelled, deadline exceeded, resource
/// exhausted, aborted, out of range, unavailable and data loss, as OTLP says.
fn grpc_retryable(code: u32) -> bool {
    matches!(code, 1 | 4 | 8 | 10 | 11 | 14 | 15)
}

/// A gRPC connection to the collector, opened on first use and again after it
/// fails.
#[derive(Default)]
struct Grpc {
    client: Option<h2::client::SendRequest<Bytes>>,
}

impl Grpc {
    async fn send(&mut self, endpoint: &Endpoint, body: &[u8]) -> Outcome {
        match timeout(IO_TIMEOUT, self.try_send(endpoint, body)).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(e)) => {
                self.client = None;
                Outcome::Retry(e.to_string())
            }
            Err(_) => {
                self.client = None;
                Outcome::Retry("timed out".to_owned())
            }
        }
    }

    async fn try_send(&mut self, endpoint: &Endpoint, body: &[u8]) -> io::Result<Outcome> {
        let client = if let Some(client) = self.client.take() {
            client
        } else {
            let tcp = TcpStream::connect(&endpoint.authority).await?;
            let (client, connection) =
                h2::client::handshake(tcp).await.map_err(io::Error::other)?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            client
        };
        let mut client = client.ready().await.map_err(io::Error::other)?;
        let request = http::Request::post(format!("http://{}{GRPC_PATH}", endpoint.authority))
            .header("content-type", "application/grpc+proto")
            .header("te", "trailers")
            .header("grpc-encoding", "zstd")
            .header("grpc-accept-encoding", "identity,zstd")
            .body(())
            .map_err(io::Error::other)?;
        let (response, mut stream) = client
            .send_request(request, false)
            .map_err(io::Error::other)?;
        // A gRPC message: a compressed flag, a big-endian length, the bytes.
        let len = u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes();
        let mut frame = Vec::with_capacity(body.len().saturating_add(5));
        frame.push(1);
        frame.extend_from_slice(&len);
        frame.extend_from_slice(body);
        stream
            .send_data(Bytes::from(frame), true)
            .map_err(io::Error::other)?;
        let response = response.await.map_err(io::Error::other)?;
        self.client = Some(client);
        let status = response.status();
        let headers = response.headers().clone();
        let mut body = response.into_body();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(io::Error::other)?;
            let _ = body.flow_control().release_capacity(chunk.len());
        }
        let trailers = body
            .trailers()
            .await
            .map_err(io::Error::other)?
            .unwrap_or_default();
        // A response without a message carries its status in the headers.
        let grpc = trailers
            .get("grpc-status")
            .or_else(|| headers.get("grpc-status"))
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok());
        let message = trailers
            .get("grpc-message")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        Ok(match (status.as_u16(), grpc) {
            (200, Some(0)) => Outcome::Accepted,
            (200, Some(code)) if grpc_retryable(code) => {
                Outcome::Retry(format!("grpc status {code} {message}"))
            }
            (200, Some(code)) => Outcome::Rejected(format!("grpc status {code} {message}")),
            (code, _) => Outcome::Retry(format!("http status {code}")),
        })
    }
}

/// One OTLP/HTTP request on a fresh connection.
async fn send_http(endpoint: &Endpoint, body: &[u8]) -> Outcome {
    match timeout(IO_TIMEOUT, try_send_http(endpoint, body)).await {
        Ok(Ok(code)) if (200..300).contains(&code) => Outcome::Accepted,
        Ok(Ok(code @ (429 | 502 | 503 | 504))) => Outcome::Retry(format!("http status {code}")),
        Ok(Ok(code)) => Outcome::Rejected(format!("http status {code}")),
        Ok(Err(e)) => Outcome::Retry(e.to_string()),
        Err(_) => Outcome::Retry("timed out".to_owned()),
    }
}

async fn try_send_http(endpoint: &Endpoint, body: &[u8]) -> io::Result<u16> {
    let mut tcp = TcpStream::connect(&endpoint.authority).await?;
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-protobuf\r\n\
         Content-Encoding: zstd\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        endpoint.path,
        endpoint.authority,
        body.len()
    );
    tcp.write_all(head.as_bytes()).await?;
    tcp.write_all(body).await?;
    let mut response = Vec::new();
    (&mut tcp)
        .take(u64::try_from(MAX_RESPONSE).unwrap_or(u64::MAX))
        .read_to_end(&mut response)
        .await?;
    status_code(&response).ok_or_else(|| io::Error::other("malformed HTTP response"))
}

/// The status code in an HTTP/1.x response's status line.
fn status_code(response: &[u8]) -> Option<u16> {
    let line = response.split(|&b| b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split(' ');
    parts.next().filter(|v| v.starts_with("HTTP/1."))?;
    parts.next()?.parse().ok()
}

/// Sends what arrives on `rx` to `endpoint` until `rx` closes.
pub async fn export(endpoint: Endpoint, mut rx: mpsc::Receiver<Batch>) {
    let mut grpc = Grpc::default();
    while let Some(first) = rx.recv().await {
        let deadline = Instant::now() + FLUSH_INTERVAL;
        let mut size = first.lines.len();
        let mut batches = vec![first];
        while size < MAX_REQUEST {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(batch)) => {
                    size = size.saturating_add(batch.lines.len());
                    batches.push(batch);
                }
                Ok(None) | Err(_) => break,
            }
        }
        let body = encode(&batches);
        let mut backoff = FIRST_BACKOFF;
        for attempt in 1..=ATTEMPTS {
            let outcome = match endpoint.protocol {
                Protocol::Grpc => grpc.send(&endpoint, &body).await,
                Protocol::Http => send_http(&endpoint, &body).await,
            };
            match outcome {
                Outcome::Accepted => break,
                Outcome::Rejected(why) => {
                    eprintln!("creche-sink: {endpoint} rejected {size} bytes of lines: {why}");
                    break;
                }
                Outcome::Retry(why) if attempt == ATTEMPTS => {
                    eprintln!(
                        "creche-sink: dropping {size} bytes of lines after {ATTEMPTS} attempts to {endpoint}: {why}"
                    );
                }
                Outcome::Retry(_) => {
                    tokio::time::sleep(backoff).await;
                    backoff = backoff.saturating_mul(2);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
