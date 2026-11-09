//! creche-observer: runs inside a Kata microVM, started before kata-agent, and
//! streams process, connect and file-write events to the host over vsock.
//!
//! The BPF records are the wire format (crate `creche-wire`): the observer
//! forwards them untouched, so the guest spends no CPU on encoding.
//!
//! Memory profile: allocation-conscious. The forwarding queue is bounded and
//! grows only while the host is not reading.

mod bpf;
mod metrics;
mod output;

use std::os::fd::AsFd as _;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use creche_wire::{
    HEARTBEAT_LEN, HELLO_LEN, Header, HeartbeatRecord, HelloFlags, HelloRecord, Kind, VERSION,
};
use nix::errno::Errno;
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};
use zerocopy::IntoBytes as _;

use crate::bpf::{Probes, Stage};
use crate::output::{Output, Target};
use creche_observer::queue::RecordQueue;

/// Heartbeat period, also the longest the observer sleeps when idle.
const BEAT: Duration = Duration::from_secs(5);
/// Drain at most once per this many milliseconds. Each drain costs a few VM
/// exits (wakeup interrupt, timer, vsock doorbell), so under load records are
/// batched. 20 ms halved the observer's CPU against 5 ms with no ring buffer
/// drops. 50 ms overflowed the 1 MiB ring buffer in a tight open loop.
const BATCH_WINDOW_MS: u64 = 20;
/// Most bytes kept while the host is not reading. Later records are dropped and counted.
const QUEUE_CAPACITY: usize = 1 << 20;

const USAGE: &str = "\
usage: creche-observer [-p PORT] [-s] [-S] [-d]
  -p, --port PORT  vsock port on the host (default 7000)
  -s, --stdout     write the record stream to stdout instead of vsock
  -S, --stats      enable kernel BPF run-time stats (reported in heartbeats)
  -d, --dedup      collapse repeated opens of a file by the same process (1 s window)
  -b, --batch-ms MS  drain at most once per MS milliseconds (default 20)
Overhead breakdown only:
  --stage STAGE    attach (programs return at once), logic (no ring buffer output) or full
  --discard        drain the ring buffer but send nothing";

#[derive(Debug)]
struct Args {
    target: Target,
    stats: bool,
    dedup: bool,
    stage: Stage,
    discard: bool,
    batch_window: Duration,
}

fn parse_args() -> Result<Option<Args>, lexopt::Error> {
    use lexopt::prelude::*;

    let mut args = Args {
        target: Target::Vsock(7000),
        stats: false,
        dedup: false,
        stage: Stage::Full,
        discard: false,
        batch_window: Duration::from_millis(BATCH_WINDOW_MS),
    };
    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Short('p') | Long("port") => {
                if !matches!(args.target, Target::Stdout) {
                    args.target = Target::Vsock(parser.value()?.parse()?);
                }
            }
            Short('s') | Long("stdout") => args.target = Target::Stdout,
            Short('S') | Long("stats") => args.stats = true,
            Short('d') | Long("dedup") => args.dedup = true,
            Long("stage") => {
                args.stage = match parser.value()?.to_str() {
                    Some("full") => Stage::Full,
                    Some("attach") => Stage::Attach,
                    Some("logic") => Stage::Logic,
                    _ => return Err("--stage takes attach, logic or full".into()),
                }
            }
            Long("discard") => args.discard = true,
            Short('b') | Long("batch-ms") => {
                args.batch_window = Duration::from_millis(parser.value()?.parse()?);
            }
            Short('h') | Long("help") => return Ok(None),
            _ => return Err(arg.unexpected()),
        }
    }
    Ok(Some(args))
}

fn main() -> ExitCode {
    match parse_args() {
        Ok(Some(args)) => match run(&args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("creche-observer: {e:#}");
                ExitCode::FAILURE
            }
        },
        Ok(None) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("creche-observer: {e}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &Args) -> Result<()> {
    let port = match args.target {
        Target::Vsock(port) => Some(port),
        Target::Stdout => None,
    };
    let mut probes = Probes::load(args.dedup, args.stage, port)?;
    // Kernel-side run-time accounting stays on while this fd is open.
    let _stats = args
        .stats
        .then(|| aya::sys::enable_stats(aya::sys::Stats::RunTime))
        .transpose()
        .context("enabling BPF run-time stats")?;

    let pid = std::process::id();
    let mut flags = HelloFlags::default();
    if args.dedup {
        flags = flags.with(HelloFlags::DEDUP);
    }
    if probes.process_only {
        flags = flags.with(HelloFlags::PROCESS_ONLY);
    }
    // Built on each new connection, after the guard has had the chance to see
    // the observer's own connect.
    let hello = |guarded: bool| HelloRecord {
        header: Header::for_observer(Kind::Hello, HELLO_LEN, pid, metrics::boottime_ns()),
        version: VERSION,
        flags: if guarded {
            flags.with(HelloFlags::GUARDED)
        } else {
            flags
        },
    };

    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC)?;
    epoll.add(
        probes.events.as_fd(),
        EpollEvent::new(EpollFlags::EPOLLIN, 0),
    )?;
    let mut queue = RecordQueue::new(QUEUE_CAPACITY);
    let mut output = Output::new(args.target);
    eprintln!("creche-observer: ready");

    let mut next_beat = Instant::now();
    let mut last_drain = Instant::now();
    let mut dropped = 0;
    let mut drained = false;
    loop {
        // Idle: sleep until the next heartbeat. Woken (the BPF side only wakes
        // us for the first record after a drain): drain right away if the last
        // drain was a batch window ago, so sparse events arrive without delay.
        // Otherwise wait out the window, so a burst is drained in one go.
        //
        // A program decides on the wakeup before it writes its record. If we
        // drained in between, that record would wait for the heartbeat, so
        // after a drain that found records, sleep at most one more window.
        let mut wait = next_beat.saturating_duration_since(Instant::now());
        if drained {
            wait = wait.min(args.batch_window);
        }
        let timeout = EpollTimeout::try_from(wait).unwrap_or(EpollTimeout::NONE);
        let mut ready = [EpollEvent::empty()];
        match epoll.wait(&mut ready, timeout) {
            Ok(n) if n > 0 => {
                thread::sleep(args.batch_window.saturating_sub(last_drain.elapsed()));
            }
            Ok(_) | Err(Errno::EINTR) => {}
            Err(e) => return Err(e).context("waiting for events"),
        }
        last_drain = Instant::now();
        drained = false;
        while let Some(record) = probes.events.next() {
            drained = true;
            if !args.discard {
                queue.push(&record);
            }
        }
        if Instant::now() >= next_beat {
            next_beat += BEAT;
            let (bpf_run_ns, bpf_run_cnt) = probes.run_stats();
            let heartbeat = HeartbeatRecord {
                header: Header::for_observer(
                    Kind::Heartbeat,
                    HEARTBEAT_LEN,
                    pid,
                    metrics::boottime_ns(),
                ),
                ringbuf_drops: probes.ringbuf_drops(),
                sent_bytes: queue.sent_bytes(),
                dropped_bytes: queue.dropped_bytes(),
                rss_kb: metrics::rss_kb(),
                cpu_ms: metrics::cpu_ms(),
                bpf_run_ns,
                bpf_run_cnt,
            };
            queue.push(heartbeat.as_bytes());
        }
        let reconnected = output.send(&mut queue, || hello(probes.guarded()).as_bytes().to_vec());
        // Records may have been lost, task records among them.
        if reconnected || queue.dropped_bytes() != dropped {
            dropped = queue.dropped_bytes();
            probes.resync_tasks()?;
        }
    }
}
