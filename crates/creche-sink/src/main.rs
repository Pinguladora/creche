//! creche-sink: receives the record streams of every creche-observer on the
//! host and prints them as JSON lines, one per event, tagged with the sandbox id.

use std::io::{self, Read as _, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context as _, Result, bail};

use creche_sink::listen;
use creche_sink::stream::{Format, StreamDecoder};

const USAGE: &str = "\
usage: creche-sink [-d DIR] [-p PORT] [-o json|raw]
       creche-sink -f FILE|- [-o json|raw]
  -d, --dir DIR      directory of Kata sandboxes (default /run/vc/vm)
  -p, --port PORT    vsock port the observers connect to (default 7000)
  -f, --file FILE    decode a captured stream (- for stdin) and exit
  -o, --output FMT   json: one JSON line per event, OpenTelemetry attribute names (default)
                     raw: the records unchanged, in frames naming their sandbox";

#[derive(Debug)]
enum Mode {
    Listen {
        dir: PathBuf,
        port: u32,
        format: Format,
    },
    Decode {
        file: PathBuf,
        format: Format,
    },
}

fn parse_args() -> Result<Option<Mode>, lexopt::Error> {
    use lexopt::prelude::*;

    let mut dir = PathBuf::from("/run/vc/vm");
    let mut port = 7000;
    let mut file = None;
    let mut format = Format::Json;
    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Short('d') | Long("dir") => dir = parser.value()?.into(),
            Short('p') | Long("port") => port = parser.value()?.parse()?,
            Short('f') | Long("file") => file = Some(PathBuf::from(parser.value()?)),
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
    Ok(Some(match file {
        Some(file) => Mode::Decode { file, format },
        None => Mode::Listen { dir, port, format },
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
        Mode::Listen { dir, port, format } => listen(dir, port, format),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("creche-sink: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn listen(dir: PathBuf, port: u32, format: Format) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .context("starting the runtime")?;
    runtime
        .block_on(listen::run(dir, port, format))
        .context("writing output")
}

fn decode_file(file: &PathBuf, format: Format) -> Result<()> {
    let mut data = Vec::new();
    if file.as_os_str() == "-" {
        io::stdin()
            .read_to_end(&mut data)
            .context("reading stdin")?;
    } else {
        data = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    }
    let mut decoder = StreamDecoder::new(format);
    let mut lines = Vec::new();
    decoder
        .feed(&data, "file", &mut lines)
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
