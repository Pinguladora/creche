# creche

## Style

- Comments, docs and messages use plain ASCII sentences. No semicolons, em or en
  dashes, smart quotes or other non-ASCII characters. Split into two sentences
  instead.
- Rust follows the workspace lints in `Cargo.toml`: no `unsafe`, no `unwrap`,
  `expect` or `panic` outside tests, clippy pedantic clean.
- The BPF programs stay C with CO-RE. A wire struct change goes in both
  `crates/creche-wire/src/lib.rs` and `crates/creche-observer/bpf/wire.h`, and
  the build fails if they disagree.

## Tools

- Tools come from mise. `mise.toml` holds what local work and CI both need,
  `mise.dev.toml` the local-only lint, format and hook tooling (loaded through
  `.miserc.toml`), `mise.ci.toml` what only CI needs (`MISE_ENV=ci`). Pin new
  ones with `mise use --pin`, adding `--env dev` or `--env ci` for those layers.
- Builds go through mr-boxington. Use plain `cargo`, not a custom target dir.
- Tests: `mise run test` (nextest, the `release-assertions` profile and doc
  tests). Mutation testing: `mise run mutants`, which must report 0 missed.
  Benchmarks: `mise run bench`. Measure before and after a performance change.
- `creche-wire` is the strict core: no allocation. Its own `clippy.toml` refuses
  heap types and macros. Fixtures that need them say so with `#[expect]`.

## hk

- Ask the hk MCP server to inspect the project and plan checks before execution.
- Scope work to changed files (`--files0-from` accepts exact NUL-delimited paths)
  and use `--cd` for another project root.
- Prefer safe checks and safe fixes. Inspect command effects and ask before any
  unknown or destructive command.
- Read normalized diagnostics from structured results, then inspect the patch
  before reporting or committing a fix.
- If MCP is unavailable, run `hk run check --format jsonl --safe`. The final event
  is the authoritative summary.
