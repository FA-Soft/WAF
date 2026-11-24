# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately, not in a public issue: use **Report a vulnerability** on the repository's
Security tab (GitHub private vulnerability reporting). Include what is affected (version, platform, configuration), how
to reproduce it, and what an attacker gains.

You get an answer within a week. Once a fix is released, the advisory is published, with credit unless you prefer
otherwise.

## Supported versions

Fixes go into the latest release only. Upgrading keeps the configuration and the data
(see the installation sections of the [README](README.md)).

## What the project does about security

- [docs/security-review.md](docs/security-review.md): the review of headers, secrets, fail-closed behavior and admin
  exposure, its findings, and what is accepted and why.
- Every build runs the .NET security analyzers and a NuGet vulnerability audit. CI also scans the installer scripts and
  reports vulnerable packages, and Dependabot proposes updates.
