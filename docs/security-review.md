# Security review

Review of the gateway before its first release (step 36, November 2026): HTTP headers, secrets, fail-closed behavior,
exposure of the admin UI, plus dependencies and static analysis. Method: reading the code of each area, attacking it
in tests, scanning (below), and load tests ([performance.md](performance.md)), which found one of the issues.

**Result: no open high-severity findings.** One high and one medium finding were fixed, two low ones as well; four
low or informational points are accepted and documented.

## Findings

| ID | Severity | Area | Finding | Status |
|---|---|---|---|---|
| SR-1 | High | Admin exposure | DNS rebinding against the loopback admin listener | Fixed |
| SR-2 | Medium | Availability, logging | One application-log line per blocked request: an attack flood slowed all traffic | Fixed |
| SR-3 | Low | Headers | No HSTS for remote admin access | Fixed |
| SR-4 | Low | Headers | Admin UI without Permissions-Policy and cross-origin isolation headers | Fixed |
| SR-5 | Low | Secrets | Data protection keys are not encrypted at rest on Linux | Accepted |
| SR-6 | Low | Detection | Request bodies are inspected only up to `MaxBodyBytes`, and only when switched on | Accepted |
| SR-7 | Info | Availability | No gateway-wide connection limit | Accepted |
| SR-8 | Info | Secrets | The first-run setup token is written to the service log | Accepted |

### SR-1 DNS rebinding against the loopback admin listener (high, fixed)

The admin listener binds to `127.0.0.1` and `::1` only, but answered to any `Host` header. A web page open in a
browser **on the gateway machine** could point its own host name at 127.0.0.1 (DNS rebinding) and then use the admin
UI as its own origin. It could read the sign-in and first-run setup forms with their antiforgery tokens, and while no
admin account exists yet, create one, since requests from this machine need no setup token. The real admin's sign-in
cookie is not sent to the attacker's host name, so after setup the risk was limited to guessing passwords (throttled).

Fix: the loopback listener now answers only to `localhost`, `127.0.0.1` and `[::1]`, with any port, so SSH tunnels
keep working. Any other host gets 400 with a one-line explanation (`LoopbackHostGuardMiddleware`). Remote admin
access was not affected: it only answers to its registered host name, over HTTPS, with a matching certificate name
(SNI). Tests: `ListenerTests.Admin_listener_refuses_other_host_names` and
`Admin_listener_answers_to_loopback_host_names`.

### SR-2 WAF events flooding the application log (medium, fixed)

Each blocked or flagged request was written as a warning to the application log as well as to the request log. Under
an attack flood:

- **Every request slowed down.** The console logger blocks its callers once its queue is full, and that included
  legitimate requests. In the load test, blocked requests ran at about 7,000/s with the gateway mostly idle (3 of 20
  cores busy).
- **Very high write volume.** journald on a Raspberry Pi's SD card, or the Windows Event Log for the service, would
  have taken thousands of writes per second.

Fix: at most 60 WAF events a minute go to the application log, and the rest are summarized in one line
(`LoggingWafEventSink.MaxLinesPerMinute`, event ID 201). The summary is written when the minute ends, with the next
event, or at shutdown. The request log (`events.db`) still records every request. Blocked requests now run at about
82,000/s in the same test. Tests: `LoggingWafEventSinkTests`.

### SR-3 and SR-4 Admin UI headers (low, fixed)

- **HSTS:** remote admin access (HTTPS only) now sends `Strict-Transport-Security: max-age=31536000`, so a browser
  never tries plain HTTP for the admin host name. It doesn't cover subdomains, because other sites may run under
  them. The loopback listener is plain HTTP and doesn't send it.
- **More headers:** every admin response now also has `Permissions-Policy` (camera, microphone, geolocation, payment,
  USB, serial and Bluetooth off), `Cross-Origin-Opener-Policy: same-origin` and
  `Cross-Origin-Resource-Policy: same-origin`.
- **Headers already in place:** a strict Content-Security-Policy (no inline scripts or styles, `frame-ancestors
  'none'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and
  `Cache-Control: no-store`.
- **Tests:** `AdminUiTests.Pages_are_sent_with_strict_security_headers`, and
  `RemoteAdminTests.Before_sign_in_only_the_sign_in_page_answers_and_everything_else_is_not_found`, which also checks
  that the 404s reveal none of these headers.

### Accepted

- **SR-5 Keys at rest on Linux.** Certificate private keys, the ACME account key and the AI API key are encrypted with
  ASP.NET Core Data Protection.
  - On Windows the keys themselves are protected with DPAPI for the service account.
  - On Linux there is no equivalent, so the key ring in `/var/lib/wafgateway/keys` is protected only by file
    permissions: the folder is mode 0750 and owned by the `wafgateway` user. Only root and the service user can read
    it, and they can read the data anyway.
  - Use disk encryption if the machine can be stolen.
- **SR-6 Body inspection limits.** Attack detection inspects request bodies only when `InspectBody` is on (off by
  default, because of cost) and only the first `MaxBodyBytes` (64 KB). A payload placed after that is not inspected.
  Both settings are documented; switch inspection on for routes that take form or JSON input.
- **SR-7 Connections.** The gateway sets no limit on simultaneous connections.
  - Kestrel's defaults limit what one connection can do: 32 KB of headers, 30 MB per body, 30 s to send the headers,
    and a minimum body rate of 240 bytes/s against slow clients.
  - Rate limits apply per client.
  - On a Raspberry Pi, `install.sh --memory-max` caps the memory the gateway can take.
  - Against floods from many addresses, use the network's own protection.
- **SR-8 Setup token in the log.** Until the first admin account exists, the service log shows a one-time token for
  creating it from another machine. Whoever can read the service log (administrators; on Linux the `adm` and
  `systemd-journal` groups) can use it during that window. The token is single-use and becomes invalid once an
  account exists.

## Checked, no findings

- **Fail-closed.**
  - Public traffic gets 503 while no WAF engine is active, and when evaluating a request throws.
  - There is no fail-open setting.
  - An invalid configuration never replaces the last working one: at startup the gateway falls back to the
    last-known-good version in `config.db`.
  - ACME challenges and the admin UI keep working.
  - Tests: `FailClosedTests`, `WafMiddlewareTests`.
- **Admin exposure.**
  - The admin listener binds to loopback only, and that is not configurable.
  - Requests are classified by the connection's local address, never by the `Host` header (`ListenerTests`).
  - Remote access is off by default. When on, it is HTTPS only, needs a certificate matching the host name (SNI),
    two-factor sign-in and an optional address allowlist. Before sign-in everything except the sign-in pages is an
    empty 404, the same as an unknown address.
  - Sign-in: failed attempts are throttled, accounts lock out, sessions end after an idle timeout.
  - Cookies are `HttpOnly`, `SameSite=Strict` and `Secure` over HTTPS.
  - Every form has an antiforgery token.
- **Secrets.**
  - Authorization headers, cookie values, request bodies and query strings are not logged; the request log stores the
    path without the query.
  - Exports and backups replace header-condition values (API keys) with a placeholder unless "Include secrets" is
    chosen.
  - The AI API key never leaves the machine.
  - Certificate private keys are encrypted at rest.
  - The traffic counts (`metrics.db`) store only counts per kind, rule name and route, and the client IPs of bad
    requests: no hosts, paths, headers or bodies.
- **Traffic counts cannot be used to exhaust memory or disk.** Counts wait in memory up to a fixed limit
  (`Gateway:Metrics:MaxPendingCounts`); beyond it requests are still served but not counted (and that is counted).
  Sources are limited to 100 per minute plus "other", and in memory to a fifth of that limit, so an attack from many
  addresses cannot grow either. Counting never blocks or throws on the request path (`TrafficMetricsTests`). On disk,
  every tier is removed after its retention (at most three years by default; ten years is the hard limit), and the
  coarser tiers keep the top 100 sources plus "other" as well (`MetricsRollupTests`).
- **Proxy.**
  - `X-Forwarded-For/Proto/Host` are always overwritten, and a client's `Forwarded` header is removed.
  - The client IP comes from forwarded headers only when the request comes from a trusted proxy.
  - The `Server` header is not sent.
  - Error responses when no backend answers (502, 503, 504, and SOAP Faults) never contain backend addresses,
    ports, route or target names, or exception texts; those go to the request log only. They are not cached
    (`no-store`), and the HTML page has no scripts and a `default-src 'none'` Content Security Policy. Tests:
    `BackendErrorTests` (unit and integration, every format). The same holds in every visitor language (English,
    Dutch, French, German): only the texts change, and responses carry `Vary: Accept-Language` so a shared cache
    cannot mix languages (`VisitorLanguageTests`).
  - Only TLS 1.2 and 1.3 are accepted.
  - A host name without a certificate gets no TLS handshake, so no default certificate is ever served.
- **Service accounts.**
  - Linux: a system user without login, `CAP_NET_BIND_SERVICE` as its only capability, `NoNewPrivileges`,
    `ProtectSystem=strict` with only its data folder writable (checked by `deploy/linux/test-install.sh`).
  - Windows: a virtual service account, with the data folder restricted to SYSTEM, Administrators and the service.

## Scanning (automated)

| What | Where | Fails on |
|---|---|---|
| .NET analyzers, every security rule (`AnalysisModeSecurity=All`) | every build (`Directory.Build.props`) | any finding |
| NuGet audit of direct and transitive packages | every restore | high and critical advisories |
| Vulnerable-package report (`dotnet list package --vulnerable --include-transitive`) | CI job *Security scan* | high and critical; lower severities are annotated |
| Deprecated packages | CI job *Security scan* | report only |
| ShellCheck (`deploy/linux/*.sh`) | CI job *Security scan* | errors; warnings are listed |
| PSScriptAnalyzer (`deploy/windows/*.ps1`) | CI job *Security scan* | errors; warnings are listed |
| Dependency updates | Dependabot (`.github/dependabot.yml`), weekly | pull requests, tested by CI |

At the time of the review all of these passed locally: no package with a known vulnerability and no analyzer
findings. ShellCheck and PSScriptAnalyzer were added for CI and first ran there. GitHub's CodeQL and dependency review
need GitHub Advanced Security for a private repository. Add them when the repository becomes public or gets it.

Report vulnerabilities privately: see [SECURITY.md](../SECURITY.md).
