# 0000. Record architecture decisions

- Status: Accepted
- Date: 2026-11-09

## Context

creche moved fast: wire format versions, two observers, kernel variants, several
rounds of overhead work. The reasons behind the current shape lived in commit
messages, benchmark notes and conversations. A new contributor, or a reviewer of
the Kata proposal, could see what creche does but not why.

## Decision

Keep architecture decision records in `docs/adr`, one Markdown file per
decision, numbered in order, in the format of [template.md](template.md). A
change that makes a significant decision comes with its record. Records link
only to earlier records.

A decision is significant when it is hard to reverse or shapes other code: the
trust model, the wire format, the transport, kernel requirements, output
contracts, dependencies on the hot path.

## Consequences

The why survives the people who decided. Superseded records stay, so the
evolution is visible. Writing a record costs a few minutes per decision.
