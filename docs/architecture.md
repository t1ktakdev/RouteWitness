# Architecture

Python 3.11+, foreground local process. Dependencies are psutil (portable interface APIs), dnspython (bounded controlled DNS), Pydantic (strict versioned durable data validation), platformdirs (OS storage conventions). argparse and normal text output keep the CLI small; stdlib asyncio handles concurrent sockets and subprocesses. No LLM, HTTP framework, daemon or telemetry backend.

Modules are grouped by responsibility, not one file per function:

- `models.py`, `config.py`: strict schemas and validated TOML; UTC wall timestamps plus monotonic timing.
- `platform/`: isolated route discovery on Linux (ip JSON), Windows (PowerShell networking objects serialized to JSON), macOS (numeric C-locale route fallback). psutil supplies address/link state without MAC collection.
- `probes.py`: bounded subprocess runner, ICMP, DNS, TCP, TLS/HTTP HEAD and numeric path probes. System resolver runs in a killable child, avoiding unkillable resolver threads after cancellation.
- `engine.py`: rolling statistics, pure detector state machine, classifier. Plain model fixtures suffice to test all decisions.
- `recorder.py`: sampler scheduling, prehistory, incident lifecycle, status lock, checkpoints and path tasks. Fake clock/provider implements the same boundary.
- `reports.py`, `storage.py`: structured canonical evidence, allowlisted sanitized projection, offline HTML/Markdown/CSV and SHA256 manifest. Staging directory plus atomic rename publishes completed bundles.
- `cli.py`, `demo.py`: commands and deterministic simulated evidence.

Only configured diagnostic endpoints receive probe traffic. No shell interpolation; numeric addresses/validated hostnames only; child process cleanup on timeout/cancel. Concurrency and output sizes are bounded. Application bodies, credentials, environment contents and unrelated files are never collected.

The watcher serializes state transitions; slow probes cannot create overlapping sampling loops. Requested 1-second quiet cadence becomes 0.5 seconds during incidents; actual cadence includes probe time when a round exceeds its budget, and is recorded. Probe gaps/resume reset baseline rather than inventing outage samples. Prehistory is limited by elapsed seconds AND count. Long incidents split into linked bounded segments; periodic raw checkpoints survive process termination. Finalization marks interrupted segments honestly.

Status uses an OS-held advisory lock plus atomic heartbeat. PID creation time is additional corroboration when available; missing process metadata is explicit and does not stop collection. Lock lifetime, not an old PID file, prevents duplicate watchers. Storage is per-user. Retention is disabled by default and removes only validated completed incident directories when explicitly configured.

Target platforms are Windows 11, modern Linux and macOS. Fixture tests exercise platform parsers everywhere. Native OS CI is necessary before claiming field validation; a Linux container cannot certify Windows/macOS network behavior. No automatic privilege escalation.

## API references checked

- [Python asyncio streams](https://docs.python.org/3/library/asyncio-stream.html): bounded readers, TLS upgrade and connection shutdown. `StreamWriter.start_tls` is available from Python 3.11; the code does not use its newer 3.12-only shutdown-timeout argument.
- [dnspython asynchronous resolver](https://dnspython.readthedocs.io/en/stable/async-resolver-class.html): resolver query lifetime and async resolution boundary.
