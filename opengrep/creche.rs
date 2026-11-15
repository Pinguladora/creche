// Test cases for creche.yaml. Not compiled: `opengrep --test` reads the
// comments above each line to know which rule must or must not match it.

use std::fs;

// The peer admission before ADR 0018: a bound path out of /proc, followed.
fn holds_listener(pid: i32, file: (u64, u64)) -> bool {
    let table = fs::read(format!("/proc/{pid}/net/unix")).unwrap();
    for path in table.split(|&b| b == b'\n') {
        let path = std::str::from_utf8(path).unwrap();
        // ruleid: host-follows-a-path
        if fs::metadata(path).is_ok_and(|m| (m.dev(), m.ino()) == file) {
            return true;
        }
    }
    false
}

fn own_paths(dir: &Path) -> bool {
    // ruleid: host-follows-a-path
    fs::metadata(dir.join("clh.sock")).is_ok()
}

fn fixed_paths() -> bool {
    // ok: host-follows-a-path
    fs::metadata("/proc/self").is_ok()
}

struct Cgroups {
    described: HashSet<u64>,
    paths: Vec<u64>,
}

impl Cgroups {
    // The observer before the walk was bounded.
    fn describe(&mut self, id: u64) -> bool {
        // ruleid: unbounded-insert
        self.described.insert(id)
    }

    fn describe_bounded(&mut self, id: u64) -> bool {
        if self.described.len() >= MAX {
            self.described.clear();
        }
        // ok: unbounded-insert
        self.described.insert(id)
    }

    fn evicting(&mut self, id: u64) {
        if self.described.len() >= MAX
            && !self.described.contains(&id)
            && let Some(&evict) = self.described.iter().next()
        {
            self.described.remove(&evict);
        }
        // ok: unbounded-insert
        self.described.insert(id);
    }

    fn reported(&mut self, id: u64) {
        // ruleid: unbounded-insert
        self.described.insert(id);
        gauge(self.described.len());
    }

    fn remember(&mut self, id: u64) {
        // ok: unbounded-insert
        self.paths.push(id);
    }
}

// The sink's read loop before decoding moved off the runtime thread.
async fn receive(mut decoder: StreamDecoder, data: Vec<u8>) {
    let mut lines = Vec::new();
    // ruleid: decoding-on-the-runtime-thread
    let _ = decoder.feed_at(&data, &origin, 1, &mut lines);
    let done = tokio::task::spawn_blocking(move || {
        // ok: decoding-on-the-runtime-thread
        decoder.feed_at(&data, &origin, 1, &mut lines)
    })
    .await;
}

async fn scan(dir: &Path) {
    // ruleid: blocking-fs-in-async-fn
    let entries = std::fs::read_dir(dir);
    // ok: blocking-fs-in-async-fn
    let entries = tokio::fs::read_dir(dir).await;
    let found = tokio::task::spawn_blocking(move || {
        // ok: blocking-fs-in-async-fn
        fs::read_to_string(dir)
    })
    .await;
}

fn not_async(dir: &Path) {
    // ok: blocking-fs-in-async-fn
    let _ = fs::read_dir(dir);
}

// The OTLP/HTTP request head as written, with a continued line.
fn continued(endpoint: &Endpoint, body: &[u8]) -> String {
    // ruleid: interpolated-protocol-head
    format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-protobuf\r\n\
         Content-Length: {}\r\n\r\n",
        endpoint.path,
        endpoint.authority,
        body.len()
    )
}

// The OTLP/HTTP request head before URLs were checked.
fn head(endpoint: &Endpoint, body: &[u8]) -> String {
    // ruleid: interpolated-protocol-head
    format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n",
        endpoint.path,
        endpoint.authority,
        body.len()
    )
}

fn inline(status: &str) -> String {
    // ruleid: interpolated-protocol-head
    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n")
}

fn into_writer(&mut self, status: &str) {
    // ruleid: interpolated-protocol-head
    write!(self.out, "HTTP/1.1 {status}\r\n");
    // ruleid: interpolated-protocol-head
    write!(&mut buf, "X-Status: {}\r\n", status);
}

fn with_spec(host: &str) -> String {
    // ruleid: interpolated-protocol-head
    format!("Host: {host:>8}\r\n")
}

fn fixed() -> String {
    // ok: interpolated-protocol-head
    format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
}
