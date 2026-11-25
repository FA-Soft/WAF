# Performance

Load tests of a published gateway with `waf-loadtest` ([tests/Waf.LoadTests](../tests/Waf.LoadTests)). It sends the
same request over and over on a fixed number of keep-alive connections, each sending the next request as soon as the
answer has been read. So *requests/s* is what the gateway sustains at that concurrency, and the latencies are per
request, including the hop to the backend.

## Scenarios

| Scenario | Request | Expected answer |
|---|---|---|
| GET, clean | `GET /api/items/42?sort=name&page=2&q=blue+shoes`, browser-like headers; the backend answers with 1 KB of JSON | 200, forwarded |
| POST, 2 KB JSON | `POST /api/items` with a 2 KB JSON body, inspected by attack detection | 200, forwarded |
| GET, SQL injection | `GET /api/items?id=1' OR '1'='1`; blocked by attack detection, never reaches the backend | 403 |

Each scenario also runs directly against the backend: the difference is the cost of the gateway. Any other answer
counts as an error.

**The gateway's configuration in the tests:**

- one route to the backend;
- attack detection on, including body inspection;
- the request log on, with each request written as it arrives;
- application log at `Warning`;
- the release build of the package, with its default garbage collector settings.

## Results

### Desktop: 2026-11-24, Intel Core i9-12900HK (14 cores, 20 threads), Windows 11, .NET 11.0.0

Package `WafGateway-win-x64` (self-contained). Load generator, backend and gateway share the machine. 32 connections,
20 s per scenario after 5 s warm-up:

| Scenario | Through | Requests/s | p50 ms | p95 ms | p99 ms | Max ms | Errors |
|---|---|---:|---:|---:|---:|---:|---:|
| GET, clean | backend directly | 147,778 | 0.17 | 0.33 | 0.95 | 79.7 | 0 |
| POST, 2 KB JSON | backend directly | 139,734 | 0.17 | 0.33 | 1.00 | 114.1 | 0 |
| GET, clean | gateway | 34,155 | 0.68 | 2.16 | 4.16 | 41.4 | 0 |
| POST, 2 KB JSON | gateway | 21,535 | 1.02 | 3.48 | 8.89 | 63.2 | 0 |
| GET, SQL injection (blocked) | gateway | 82,540 | 0.28 | 0.76 | 2.54 | 85.6 | 0 |

Gateway memory: 243 MB after start, peak 413 MB.

One connection, 10 s per scenario after 3 s warm-up. This shows the latency the gateway adds when it is not busy:

| Scenario | Through | Requests/s | p50 ms | p95 ms | p99 ms | Max ms | Errors |
|---|---|---:|---:|---:|---:|---:|---:|
| GET, clean | backend directly | 14,440 | 0.05 | 0.14 | 0.22 | 1.8 | 0 |
| POST, 2 KB JSON | backend directly | 13,585 | 0.06 | 0.13 | 0.23 | 5.8 | 0 |
| GET, clean | gateway | 1,794 | 0.50 | 1.15 | 1.59 | 6.1 | 0 |
| POST, 2 KB JSON | gateway | 2,332 | 0.38 | 0.75 | 1.02 | 13.5 | 0 |
| GET, SQL injection (blocked) | gateway | 5,632 | 0.16 | 0.32 | 0.45 | 5.8 | 0 |

**What these numbers say:**

- **Added latency:** about half a millisecond per forwarded request when the gateway is not busy (p50), and under
  5 ms at p99 with 32 busy connections. For a site behind it, this is well below the backend's own time.
- **Throughput:** tens of thousands of forwarded requests per second. That is far more than the sites this gateway is
  meant for will send, even with the load generator and the backend taking a share of the same CPU.
- **Blocked requests are cheap:** about 82,000/s. They get a short 403 without a trip to the backend, so an attack
  flood costs less than normal traffic.
  - Before step 36 every blocked request also wrote a line to the application log. That held blocked requests at about
    7,000/s and slowed all traffic (security review SR-2). The log is now capped at 60 such lines a minute.
- **Traffic counts (step 45) cost next to nothing:** counting a forwarded request takes about 27 ns, with no
  allocation. A blocked attack takes about 170 ns: it also reads the attack category and counts the source. At 2,000
  requests per second that is well under 0.1 ms of CPU per second. The numbers come from
  `dotnet run -c Release --project tests/Waf.Benchmarks -- --filter *TrafficCounter* --inProcess`, on the Windows
  machine above. Storing the counts happens in the background, once every 5 seconds.
- **Memory:** the Windows build uses the server garbage collector, with heaps per core. On a 20-thread machine it
  starts at about 240 MB and stays below 420 MB under load. The `linux-arm64` build uses the workstation collector,
  which needs much less (see [Raspberry Pi tuning](../README.md#raspberry-pi-tuning)).
- **CPU:** `waf-loadtest` also reports the gateway's CPU time. On a machine with many cores it mostly shows .NET's
  thread pool spinning while it waits for work: even the single-connection run showed more than 2 cores busy. So it
  is left out of the tables; compare throughput and latency instead.

### Linux (CI)

Every CI run load-tests the `linux-x64` package on the Ubuntu runner (job *Load test*, 10 s per scenario). The report
is on the run's summary page and is uploaded as the `loadtest-linux-x64` artifact. The runner's few shared cores carry
the load generator, backend and gateway together, so the numbers vary between runs and are far below a dedicated
machine. The job checks that no request fails under load.

### Raspberry Pi

Not measured yet: no Raspberry Pi was available for this step. Measure as described below and add the results here,
with the board, the storage (SD card or SSD) and the gateway's memory from `systemctl status wafgateway`.

| Board | Storage | Scenario | Connections | Requests/s | p50 ms | p99 ms | Gateway memory (peak) |
|---|---|---|---:|---:|---:|---:|---:|
| | | | | | | | |

## Running the load tests

Build the tool once (it needs the .NET SDK; the gateway under test does not):

```bash
dotnet build tests/Waf.LoadTests -c Release
```

**Everything on one machine** (`suite`). It starts the backend (port 18500) and the gateway, with a temporary data
folder and ports 18080/18900, measures each scenario directly and through the gateway, prints the report and stops
everything again:

```bash
# Windows: a package from deploy/windows/Build-Package.ps1
tests/Waf.LoadTests/bin/Release/net11.0/waf-loadtest suite --gateway "$PWD/artifacts/windows/WafGateway-win-x64/WafGateway.exe"
# Linux: a package from deploy/linux/build-package.sh
tests/Waf.LoadTests/bin/Release/net11.0/waf-loadtest suite --gateway "$PWD/artifacts/linux/wafgateway-linux-x64/WafGateway"
```

The `suite` command's options:

- `--concurrency 32`: connections;
- `--seconds 20` and `--warmup 5`: time per scenario;
- `--output report.md`: also write the report to a file;
- `--no-request-log`: request log off;
- `--no-body-inspection`: body inspection off.

The gateway path must be absolute when the tool runs with `dotnet run`.

**A gateway on a Raspberry Pi.** The gateway runs as installed (`install.sh`), and a PC on the same wired network
runs the backend and the load. On the Pi itself they would take CPU from the gateway.

1. On the PC, start the backend on all interfaces: `waf-loadtest backend --address any --port 18500`.
2. In the gateway's admin UI, add a route to `http://<PC address>:18500`. Switch on body inspection under attack
   detection, as in the desktop tests.
3. Measure each scenario from the PC. Use `--direct` with the PC's own address for the baseline:

   ```bash
   waf-loadtest run --url http://<pi address>/ --scenario clean --concurrency 32
   waf-loadtest run --url http://<pi address>/ --scenario post --concurrency 32
   waf-loadtest run --url http://<pi address>/ --scenario attack --concurrency 32
   waf-loadtest run --url http://127.0.0.1:18500/ --scenario clean --direct
   ```

   Repeat with `--concurrency 1` for the latency the gateway adds.
4. Read the gateway's peak memory with `systemctl status wafgateway`.

Add `--host <name>` when the route matches a host name. Every test request ends up in the gateway's request log,
and the attack scenario also writes WAF events to the service log (at most 60 a minute). Measure on a test
installation, or expect these entries in the history.

The micro-benchmarks of the rule engine and the attack detectors are separate: `dotnet run -c Release --project
tests/Waf.Benchmarks` (BenchmarkDotNet).
