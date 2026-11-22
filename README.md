# WAF Gateway

A self-hosted **Web Application Firewall and reverse proxy** written in C#, managed through an easy-to-use web UI. It inspects incoming HTTP(S) traffic, blocks malicious requests, and forwards everything else to the backends you configure (any IP address and port).

Built for personal use (one administrator, a modest number of sites), but designed to production-grade standards: secure by default, fail-closed, observable and maintainable.

> **Status: in design.** This README describes the planned design and behavior. Commands, ports and file names below are the intended interface and may change while the project is built. "WAF Gateway" is a working title.

## Highlights

- **Reverse proxy** with routing by host, path and method, to any IP address and port (HTTP or HTTPS backends, WebSockets supported)
- **WAF engine** with IP allow/deny lists (CIDR, IPv4/IPv6), rate limiting, path/method/header rules, and detection of SQL injection, XSS, path traversal, command injection and bad user agents
- **Fail-closed**: if the engine or its configuration fails, traffic is blocked (HTTP 503), never passed through unchecked
- **Web UI** with plain-language forms, inline help, a sample/template library and one-click presets
- **AI configuration assistant** (optional): describe what you want in a sentence, review a generated diff, then approve it
- **User-friendly logs**: filter and search what was blocked or routed, and turn any log entry into a route or rule with one click
- **TLS** with Let's Encrypt (automatic renewal) or your own certificates, selectable per hostname
- **Runs on Windows 11, Windows Server and Ubuntu on Raspberry Pi** as a Windows service or systemd service

## How it works

```
Internet ──► :80  ─► ACME challenge / redirect to HTTPS
         ──► :443 ─► TLS (SNI → certificate)
                       │
                       ├─ admin hostname (if registered) ─► Admin UI
                       └─ any other host ─► WAF rules ─► YARP ─► your backends

127.0.0.1:8900 ─► Admin UI (always available, localhost only)
```

Request pipeline for public traffic:

1. ACME challenge responder
2. Client IP resolution (trusted proxies only)
3. Fail-closed guard
4. WAF rule engine (immutable, hot-swappable rule set)
5. HTTPS redirect / HSTS
6. [YARP](https://github.com/microsoft/reverse-proxy) reverse proxy with health checks and forwarded headers
7. Asynchronous event logging

## Supported platforms

| Target | Architecture |
|---|---|
| Windows 11 | x64 |
| Windows Server (optionally with IIS on the same machine) | x64 |
| Ubuntu Server on Raspberry Pi | linux-arm64 |

Releases are self-contained single-file builds, so no .NET runtime needs to be installed. Linux x64 and Docker are optional, lower-priority targets.

Built on **.NET 11**, ASP.NET Core 11, EF Core 11 (SQLite) and Blazor.

## Ports

| Port | Bind | Purpose |
|---|---|---|
| 80 | all interfaces | ACME challenge, HTTP→HTTPS redirect, plain HTTP routes |
| 443 | all interfaces | Public traffic, plus the admin UI on the registered admin hostname |
| 8900 (configurable) | `127.0.0.1` and `::1` only | Admin UI, always available |
| optional remote admin port | all interfaces | Only if the registered admin URL includes a port; firewall closed by default |
| 8080, 8443, … | `127.0.0.1` | Local backends, for example IIS |

The WAF owns ports 80 and 443. If IIS or another web server runs on the same machine, move its sites to other ports and add them as routes. Bind local backends to loopback so they are reachable only through the WAF.

> On Windows, IIS uses HTTP.sys, which can reserve ports on all addresses. If the WAF cannot start because 80 or 443 is taken, check the IIS site bindings.

## Admin UI access

- **Localhost:** always available on `http://127.0.0.1:8900`. It cannot be disabled and needs no hostname or certificate.
- **Remote:** off by default. The admin enables it under **Settings → Remote access** by registering an admin URL such as `https://admin.example.com`.
- **Registration requirements:** 2FA enabled, a valid certificate for that hostname, and a hostname not used by any route.
- **While remote access is on:** HTTPS only, mandatory 2FA, brute-force protection and lockout, an optional IP/CIDR allowlist, short idle timeouts, login history, and a generic 404 before login.
- **First run:** the admin account can only be created from the local machine, or with a one-time token printed to the service log.

The admin UI is exempt from user-defined WAF rules and from the fail-closed 503 state, so a bad rule can never lock you out.

## Configuration concepts

- **Routes:** match by host, path and/or method, then forward to a destination IP/hostname and port.
- **Rules:** each has a name, conditions, an action (Allow, Block or LogOnly), a priority and an enabled flag. Rules can run in detection-only mode, per rule or globally.
- **Certificates:** Let's Encrypt (HTTP-01, with a staging switch) or your own PFX/PEM, per hostname.
- **Versions and rollback:** every change is stored as a configuration version. An invalid change never replaces the last working configuration, and any version can be restored.
- **Import/export:** configuration can be exported to JSON, and the whole setup can be backed up and restored from the UI.

### Routes in `appsettings.json`

Until the web UI exists, routes are configured under `Gateway:Routes`:

```json
"Gateway": {
  "Routes": [
    {
      "Name": "api",
      "Match": { "Hosts": ["api.example.com"], "PathPrefix": "/api", "Methods": ["GET", "POST"] },
      "Destinations": [ { "Scheme": "http", "Address": "10.0.0.5", "Port": 8080 } ],
      "PreserveHost": true,
      "AllowInvalidBackendCertificate": false,
      "HealthCheck": { "Path": "/health", "IntervalSeconds": 10, "TimeoutSeconds": 5 }
    }
  ]
}
```

- **Match:** all given conditions must match; leave one out to match anything. `Hosts` accepts `*.example.com`. `PathPrefix` matches whole path segments (`/api` matches `/api` and `/api/users`, not `/apix`); the most specific route wins, and the path is forwarded unchanged. Requests that match no route get 404.
- **Destinations:** IP address or host name, port, `http` or `https`. Several destinations share the load; WebSockets are supported.
- **PreserveHost** (default `true`): the backend receives the client's original `Host` header, as IIS host bindings need.
- **AllowInvalidBackendCertificate** (default `false`): accept a self-signed certificate from an HTTPS backend you control.
- **HealthCheck:** with a `Path`, each destination is probed and taken out of rotation while it fails. Passive checks (failed requests) are always on.
- **Forwarded headers:** `X-Forwarded-For`, `-Proto` and `-Host` are always set by the gateway; values sent by clients are overwritten and a client `Forwarded` header is removed. `X-Forwarded-For` carries the resolved client IP (see below).

### Client IP and trusted proxies

By default the client IP is the address of the TCP connection, and any `X-Forwarded-For` header is ignored. If the gateway sits behind another proxy or load balancer, list it under `Gateway:Settings:TrustedProxies` (IP addresses or CIDR ranges, IPv4 and IPv6):

```json
"Gateway": { "Settings": { "TrustedProxies": [ "10.0.0.1", "192.168.10.0/24" ] } }
```

For requests from a trusted proxy, `X-Forwarded-For` is read from right to left and the first address that is not a trusted proxy is the client IP. Entries further left were written by the client and are ignored, so they cannot be spoofed. An invalid entry (e.g. `unknown`) stops at the last valid address. The resolved client IP is what rules, rate limiting, logging and backends see.

Invalid routes stop the gateway at startup with a message that names the route and the problem.

### Full configuration model and JSON schema

The complete configuration (`Settings`, `Routes`, `Rules`, `Certificates`) has one model, used by `appsettings.json` (under `Gateway`), export/import, the web UI and the AI assistant:

- [`schemas/gateway-config.schema.json`](schemas/gateway-config.schema.json): JSON schema, generated from the C# model. Add `"$schema": "./gateway-config.schema.json"` to a configuration file for completion and validation in your editor.
- [`schemas/gateway-config.example.json`](schemas/gateway-config.example.json): a complete, valid example with routes, rules (IP allowlist, required API key, detection-only rule) and certificates.

**Rules** have a name, priority (lowest first), action (`Allow`, `Block`, `LogOnly`), an enabled flag, an optional list of route names they apply to, and conditions. All conditions must match; a condition matches when any of its values matches (or none, with `Negate`). Fields: `ClientIp` (operator `InCidr`), `Method` (`Equals`), and `Host`, `Path`, `QueryString`, `UserAgent`, `Header` (`Equals`, `StartsWith`, `EndsWith`, `Contains`, `Regex`). Regular expressions use the .NET non-backtracking engine, so they cannot be abused for ReDoS (no backreferences or lookarounds).

**Detection-only:** set `DetectionOnly` on a rule, or `Settings.DetectionOnly` for all rules, to log Block decisions without enforcing them.

**Evaluation:** enabled rules run by priority (lowest first, then name). The first matching `Allow` or `Block` decides; `LogOnly` matches are recorded and evaluation continues; a `Block` in detection-only mode is recorded as "would block" and evaluation continues. If no rule decides, the request is allowed. A condition on a header that is absent never matches (so with `Negate` it always matches, e.g. "block when `X-Api-Key` is missing"). The rule set is compiled once and swapped atomically when the configuration changes.

Evaluation cost per request (`tests/Waf.Benchmarks`, run with `dotnet run -c Release --project tests/Waf.Benchmarks -- --filter *RuleEvaluation* --inProcess`), measured on a laptop: about 0.1 µs with 10 rules, 1.6 µs with 100 and 24 µs with 1000 when no rule matches (every rule evaluated), with no memory allocated for requests that match nothing.

Configuration is read strictly: misspelled setting names, invalid values (e.g. `"Action": "Deny"`) and `null` where a value is required are errors with their location, never silently ignored. After changing the model, regenerate the schema by running the tests with `WAF_UPDATE_SCHEMA=1`.

## AI configuration assistant

Optional and disabled unless you provide an API key (default provider: Anthropic Claude, behind a pluggable interface).

1. Describe what you want, for example: *"Block everything except my office IP on /admin and forward api.example.com to 10.0.0.5:8080."*
2. The assistant returns a structured proposal that is validated against a strict schema.
3. You review a human-readable diff and approve it. Nothing is ever applied automatically.
4. Undo restores the previous configuration in one click.

Only your prompt and a sanitized summary of the current configuration are sent. Request bodies, cookies, secrets and log content are never sent.

## Logging

Every request is recorded with timestamp, client IP, host, method, path, matched rule, action (blocked or forwarded), destination, status code and latency. The log viewer supports filters, free-text search, pagination and a live view. From any entry you can create a route or rule pre-filled with its details, allow a false positive, or block a source. Retention is configurable by age and database size.

## Installation (planned interface)

Windows (PowerShell, as administrator):

```powershell
.\Install.ps1                      # install the service, data folder ACLs, firewall rules for 80/443
.\Install.ps1 -OpenAdminPort       # also open the remote admin port in Windows Firewall
.\Install.ps1 -MoveIisBindings     # explicitly rebind IIS sites away from 80/443 (backs up applicationHost.config first)
```

By default the installer only detects IIS and reports which sites use ports 80/443. It never changes IIS silently.

Ubuntu / Raspberry Pi:

```bash
sudo ./install.sh                  # install the service under a dedicated non-root user
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

The systemd unit uses `CAP_NET_BIND_SERVICE` and hardening options such as `NoNewPrivileges` and `ProtectSystem`.

**Data locations**

| | Windows | Linux |
|---|---|---|
| Data | `%ProgramData%\WafGateway` | `/var/lib/wafgateway` |
| Configuration | in the data folder | `/etc/wafgateway` |

On a Raspberry Pi, store the data folder on an SSD where possible to reduce SD-card wear.

## Recovery tool

`wafctl` works locally on Windows and Linux, even when the service is down or you are locked out:

```text
wafctl rules disable-all           # disable all rules
wafctl mode detection-only         # log instead of block
wafctl config restore-last-good    # restore the last known good configuration
wafctl admin reset-password        # reset the admin password
wafctl admin reset-2fa             # reset two-factor authentication
wafctl admin allow-ip <cidr>       # add an address range to the admin allowlist
wafctl admin unregister-url        # turn remote admin access off
```

## Repository layout (planned)

```
src/Waf.Core      Domain models, interfaces, configuration schema
src/Waf.Engine    Rule evaluation, attack detectors, rate limiter
src/Waf.Proxy     YARP integration, middleware, certificates, ACME
src/Waf.Data      EF Core (config.db, events.db), migrations
src/Waf.Ai        AI provider interface and proposal schema
src/Waf.Web       Blazor UI, identity, log viewer, sample library
src/Waf.Host      Startup, Kestrel, service hosting
src/Waf.Cli       wafctl
tests/            Unit, integration and benchmark projects
deploy/windows    Install.ps1, firewall and IIS detection
deploy/linux      install.sh, systemd unit, UFW notes
```

## Building from source

Requires the [.NET 11 SDK](https://dotnet.microsoft.com/download) (pinned in `global.json`).

```bash
dotnet build WafGateway.sln
dotnet test --solution WafGateway.sln
```

Run it locally with `dotnet run --project src/Waf.Host`. In the Development environment the public listeners use `127.0.0.1:5080` (HTTP) and `127.0.0.1:5443` (HTTPS) so they don't need ports 80/443; the admin UI is at `http://127.0.0.1:8900`. Listener settings are under `Gateway:Endpoints` in `appsettings.json` (`HttpPort`, `HttpsPort`, `AdminPort`, `PublicBindAddress`). The admin listener always binds to `127.0.0.1` and `::1` only.

Shared build settings live in `Directory.Build.props` (nullable, analyzers, warnings as errors) and NuGet versions in `Directory.Packages.props` (central package management). Tests use xUnit v3 on Microsoft.Testing.Platform.

GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) builds and tests every push to `main` and every pull request on Windows and Ubuntu, then publishes self-contained single-file builds for `win-x64` and `linux-arm64` as a smoke check. Each run's summary page shows a test report per OS (passed/failed/skipped per test assembly, failure details and code coverage), and failed tests appear as annotations. Test results (TRX, Cobertura coverage) and the builds are also uploaded as workflow artifacts.

## Roadmap

| Milestone | Scope |
|---|---|
| M1 | Solution skeleton, CI on Windows and Linux, static proxy routing |
| M2 | Rule engine, middleware, fail-closed behavior |
| M3 | Persistence, hot reload, last-known-good configuration |
| M4 | Web UI for rules and routes, sample library, import/export/backup |
| M5 | Logging, log viewer, log-to-route flow, retention |
| M6 | Authentication, 2FA, audit log, local admin, `wafctl` |
| M7 | TLS (own certificates and Let's Encrypt), remote admin URL registration |
| M8 | AI configuration assistant |
| M9 | Service installers, publish profiles, Raspberry Pi tuning |
| M10 | Hardening, load tests on desktop and Pi, documentation |

## Security notes

- Fail-closed by design; there is no fail-open mode.
- Secrets, authorization headers and full request bodies are not logged by default.
- Private keys and the AI API key are stored encrypted at rest and never included in exports unless explicitly chosen.
- Forwarded client-IP headers are trusted only from addresses on the trusted-proxy list.
- Report vulnerabilities privately; see `SECURITY.md` once it exists.

## Contributing

The project is at an early stage. Issues and ideas are welcome. Please open an issue before starting larger changes.

## License

To be decided. Add a `LICENSE` file before publishing.
