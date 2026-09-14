# v0.1.0 validation record

Initial local validation: 2026-09-13. Public cross-platform and native Windows validation: 2026-09-14.

## Verified

- 78 deterministic/offline tests pass. Correctness tests use fake probes/clocks or mocked platform responses and block external socket connections while allowing loopback sockets required by the Windows event loop.
- Branch-aware coverage is about 91% overall. The suite covers healthy/noise behavior, local interface/link evidence, upstream-like failures, DNS failures, remote-service failures, sustained latency, repeated drops, network changes, cancellation, watcher shutdown, checkpoint recovery, restricted permissions, hostile report metadata, corrupt evidence, dual-stack partial results, long-outage segmentation, bounded buffers, and volatile route metadata.
- Ruff formatting and lint pass. Strict mypy passes.
- `python -m build` produces both sdist and wheel. The wheel installs and its `routewitness` entry point runs `--help`, `--version`, `doctor`, and the deterministic offline demo.
- GitHub Actions passes on Windows, Ubuntu, and macOS with Python 3.11, 3.12, and 3.13: 9/9 jobs green.
- Each CI job runs installation, formatting, lint, strict typing, the offline test suite, package build, wheel installation, CLI checks, native `doctor`, and the offline demo.
- Native Windows validation on Python 3.13.14 confirmed gateway/interface/resolver discovery, one-shot diagnosis, foreground `watch` without elevation, live watcher status while the OS lock is held, and clean manual Ctrl+C shutdown.
- A native Windows watch exposed false `route-change` incidents caused by volatile route-table metadata. The detector now excludes raw route rows from stable network identity while preserving route rows as evidence; a regression test verifies route churn is ignored while gateway changes still trigger a route-change event.
- A post-fix native watch session produced no spurious route-change incident before shutdown.
- The deterministic demo reproduces an upstream-like incident with the gateway still reachable, preserves pre-incident and recovery context, and marks the result as simulated.
- Incident storage uses bounded data structures, atomic file replacement, versioned structured evidence, checkpoints, and a process-held watcher lock.
- Shareable reports pseudonymize local identifiers, escape captured values, contain no JavaScript or remote assets, and are generated from structured evidence rather than serving as the canonical store.
- The generated HTML report was reviewed at desktop and narrow/mobile widths in light/dark rendering; the timeline exposes the complete failure/recovery interval without requiring remote resources.

## Remaining caveats

The release has not been exercised in a multi-hour native resource benchmark, and no physical macOS/Linux foreground session was performed outside hosted GitHub runners. Those platforms are covered by the native CI matrix and deterministic platform fixtures, not by a claim that every real network environment has been reproduced.

Wi-Fi RSSI, complete scoped macOS DNS policy, and full split-VPN enumeration are outside v0.1. No network adapter, DNS, firewall, VPN, or router settings were changed merely to manufacture a failure.

## Packaging and publication

- Project metadata and package contents are prepared for a source/wheel release.
- The project version is `0.1.0`.
- The source is ready for the `v0.1.0` tag and GitHub Release after the final release-preparation commit passes CI.
- PyPI publication is a separate step after release artifact verification.
- Package-name checks performed during development were availability checks, not reservation or trademark clearance.

Current decision: the v0.1.0 release gates required for this project are closed. The source is ready to tag and release once the final CI run succeeds.

## Validation environment notes

The initial deep local validation used Linux/Python 3.12 with psutil 7.2.2, dnspython 2.8.0, Pydantic 2.13.5, platformdirs 4.11.8, pytest 9.1.1, pytest-cov 7.1.0, Ruff 0.16.7, mypy 2.3.1, build 1.6.1, setuptools 84.0.0, and wheel 0.48.0. Compatibility ranges live in `pyproject.toml`; these versions are a record, not a dependency lock.

The native Windows validation used Python 3.13.14. GitHub Actions independently validates the declared Python 3.11–3.13 range across Windows, Ubuntu, and macOS on every push and pull request.
