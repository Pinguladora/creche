//! creche-sink: receives the record streams of every creche-observer on the
//! host and prints them as JSON lines, one per event, tagged with the sandbox id.

use std::io::{self, Read as _, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context as _, Result, bail};

use creche_sink::audit;
use creche_sink::k8s::CONTAINERD_BUNDLES;
use creche_sink::listen::{self, Options};
use creche_sink::otlp::{Endpoint, Protocol};
use creche_sink::stream::{Format, StreamDecoder};

const USAGE: &str = "\
usage: creche-sink [-d DIR] [-p PORT] [-b DIR | --no-pods] [-o json|raw]
                   [--otlp URL [--otlp-protocol grpc|http]]
       creche-sink -f FILE|- [-o json|raw]
       creche-sink --verify FILE|-
  -d, --dir DIR      directory of Kata sandboxes (default /run/vc/vm)
  -p, --port PORT    vsock port the observers connect to (default 7000)
  -b, --bundles DIR  containerd bundles, to name each sandbox's pod
                     (default /run/containerd/io.containerd.runtime.v2.task/k8s.io)
      --no-pods      do not look up pods
  -f, --file FILE    decode a captured stream (- for stdin) and exit
  -o, --output FMT   json: one JSON line per event, OpenTelemetry attribute names (default)
                     raw: the records unchanged, in frames naming their sandbox
      --otlp URL     also export the JSON lines as OpenTelemetry logs to a collector,
                     http://host[:port], zstd compressed (JSON output only)
      --otlp-protocol grpc (default, port 4317) or http (port 4318, path /v1/logs)
      --verify FILE  check the audit chains in saved JSON output (- for stdin) and exit,
                     with status 1 when a stream does not add up";

#[derive(Debug)]
enum Mode {
    Listen { dir: PathBuf, options: Options },
    Decode { file: PathBuf, format: Format },
    Verify { file: PathBuf },
}

fn parse_args() -> Result<Option<Mode>, lexopt::Error> {
    use lexopt::prelude::*;

    let mut dir = PathBuf::from("/run/vc/vm");
    let mut port = 7000;
    let mut bundles = Some(PathBuf::from(CONTAINERD_BUNDLES));
    let mut file = None;
    let mut verify = None;
    let mut otlp = None;
    let mut protocol = Protocol::Grpc;
    let mut format = Format::Json;
    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Short('d') | Long("dir") => dir = parser.value()?.into(),
            Short('p') | Long("port") => port = parser.value()?.parse()?,
            Short('b') | Long("bundles") => bundles = Some(parser.value()?.into()),
            Long("no-pods") => bundles = None,
            Short('f') | Long("file") => file = Some(PathBuf::from(parser.value()?)),
            Long("verify") => verify = Some(PathBuf::from(parser.value()?)),
            Long("otlp") => otlp = Some(parser.value()?.string()?),
            Long("otlp-protocol") => {
                protocol = match parser.value()?.to_str() {
                    Some("grpc") => Protocol::Grpc,
                    Some("http") => Protocol::Http,
                    _ => return Err("--otlp-protocol takes grpc or http".into()),
                }
            }
            Short('o') | Long("output") => {
                format = match parser.value()?.to_str() {
                    Some("json") => Format::Json,
                    Some("raw") => Format::Raw,
                    _ => return Err("--output takes json or raw".into()),
                }
            }
            Short('h') | Long("help") => return Ok(None),
            _ => return Err(arg.unexpected()),
        }
    }
    let otlp = match otlp {
        Some(_) if format != Format::Json => {
            return Err("--otlp exports JSON lines, it does not take -o raw".into());
        }
        Some(url) => Some(Endpoint::parse(&url, protocol)?),
        None => None,
    };
    Ok(Some(match (verify, file) {
        (Some(file), _) => Mode::Verify { file },
        (None, Some(file)) => Mode::Decode { file, format },
        (None, None) => Mode::Listen {
            dir,
            options: Options {
                port,
                format,
                bundles,
                otlp,
            },
        },
    }))
}

fn main() -> ExitCode {
    let mode = match parse_args() {
        Ok(Some(mode)) => mode,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("creche-sink: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let result = match mode {
        Mode::Decode { file, format } => decode_file(&file, format),
        Mode::Listen { dir, options } => listen(dir, options),
        Mode::Verify { file } => match verify(&file) {
            Ok(true) => Ok(()),
            Ok(false) => return ExitCode::from(1),
            Err(e) => Err(e),
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("creche-sink: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn listen(dir: PathBuf, options: Options) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .context("starting the runtime")?;
    runtime
        .block_on(listen::run(dir, options))
        .context("writing output")
}

/// The bytes of `file`, or of stdin for `-`.
fn read_input(file: &PathBuf) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    if file.as_os_str() == "-" {
        io::stdin()
            .read_to_end(&mut data)
            .context("reading stdin")?;
    } else {
        data = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    }
    Ok(data)
}

/// Prints what [`audit::verify`] found in `file`. Whether every stream is intact.
fn verify(file: &PathBuf) -> Result<bool> {
    let report = audit::verify(&read_input(file)?);
    let mut out = io::stdout().lock();
    for (stream, s) in &report.streams {
        writeln!(
            out,
            "stream {stream}: {} lines, {} verified by {} checkpoints, {}",
            s.lines,
            s.verified,
            s.checkpoints,
            if s.ended { "ended" } else { "open" }
        )?;
        for problem in &s.problems {
            writeln!(out, "  problem: {problem}")?;
        }
    }
    writeln!(
        out,
        "{} lines outside any stream, {} unreadable",
        report.outside, report.unreadable
    )?;
    Ok(report.intact())
}

fn decode_file(file: &PathBuf, format: Format) -> Result<()> {
    let data = read_input(file)?;
    let mut decoder = StreamDecoder::new(format);
    let mut lines = Vec::new();
    decoder
        .feed(&data, &"file".into(), &mut lines)
        .context("decoding")?;
    io::stdout()
        .lock()
        .write_all(&lines)
        .context("writing output")?;
    if decoder.pending() > 0 {
        bail!(
            "stream ends with an incomplete record ({} bytes)",
            decoder.pending()
        );
    }
    Ok(())
}
