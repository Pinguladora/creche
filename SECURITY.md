# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability
reporting: the "Report a vulnerability" button on the Security tab of
https://github.com/Pinguladora/creche. Please do not open a public issue.

Include what is affected (the observer in the guest, the sink on the host, or the
wire format), how to reproduce it and what an attacker gains. The guest is
untrusted by design, so anything a guest can send that crashes, stalls or
misleads the sink is in scope, as is anything that lets a guest process forge
what the observer reports.

You should get a first answer within a week. Fixes are released as soon as they
are ready, and dependency security fixes are released automatically once merged.

## Supported versions

Only the latest release receives fixes.

## Verifying a release

Each release publishes `checksums.txt`, signed keyless with cosign, and SLSA
provenance for every tarball. See the README for the commands.
