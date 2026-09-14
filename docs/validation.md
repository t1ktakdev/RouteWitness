# v0.1.0 validation record

Initial local validation: 2026-09-13. Public cross-platform validation: 2026-09-14. RouteWitness is public on GitHub but has not been tagged, released, or published to PyPI.

## Verified

- 76 deterministic/offline tests pass. Correctness tests use fake probes/clocks or mocked platform responses and block external socket connections while allowing loopback sockets required by the Windows event loop.
- Branch-aware coverage is about 91% overall. The suite covers healthy/noise behavior, local interface/link evidence, upstream-like failures, DNS failures, remote-service failures, sustained latency, repeated drops, network changes, cancellation, watcher shutdown, checkpoint recovery, restricted permissions, hostile report metadata, corrupt evidence, dual-stack partial results, long-outage segmentation, and bounded buffers.
- Ruff formatting and lint pass. Strict mypy passes.
- `python -m build` produces both sdist and wheel. The wheel installs and its `routewitness` entry point runs `--help`, `--version`, `doctor`, and the deterministic offline demo.
- The public GitHub Actions matrix completed successfully on Windows, Ubuntu, and macOS with Python 3.11, 3.12, and 3.13: 9/9 jobs green.
- Each CI job runs installation, formatting, lint, strict typing, the offline test suite, package build, wheel installation, CLI checks, native `doctor`, and the offline demo.
- The deterministic demo reproduces an upstream-like incident with the gateway still reachable, preserves pre-incident and recovery context, and marks the result as simulated.
- Incident storage uses bounded data structures, atomic file replacement, versioned structured evidence, checkpoints, and a process-held watcher lock.
- Shareable reports pseudonymize local identifiers, escape captured values, contain no JavaScript or remote assets, and are generated from structured evidence rather than serving as the canonical store.
- The generated HTML report was reviewed at desktop and narrow/mobile widths in light/dark rendering; the timeline exposes the complete failure/recovery interval without requiring remote resources.

## Release gates still open

The CI matrix is intentionally deterministic and does not prove that a long-running watcher behaves correctly on every real network.

Before calling v0.1.0 production-validated, perform short native foreground sessions on the intended release platforms, with particular attention to:

- `routewitness doctor` and `routewitness diagnose` against a real host network;
- starting `routewitness watch` without elevation;
- gateway/interface discovery and normal sampling;
- `routewitness status` while the watcher owns its lock;
- Ctrl+C cancellation and cleanup;
- recovery after a real, naturally occurring connectivity incident when available;
- absence of stale status/lock files or corrupted incident bundles.

No network adapter, DNS, firewall, VPN, or router settings should be changed merely to manufacture a failure.

No multi-hour native resource benchmark has been completed. Wi-Fi RSSI, complete scoped macOS DNS policy, and full split-VPN enumeration are outside v0.1.

## Packaging and publication

- Project metadata and package contents are prepared for a source/wheel release.
- The project remains version `0.1.0`.
- No Git tag or GitHub Release has been created.
- Nothing has been published to PyPI.
- Package-name checks performed during development were availability checks, not reservation or trademark clearance.

Current decision: the source is suitable for public review and continued native validation. Tagging, GitHub Release creation, and PyPI publication remain blocked on the native foreground-watch checks above.

## Validation environment notes

The initial deep local validation used Linux/Python 3.12 with psutil 7.2.2, dnspython 2.8.0, Pydantic 2.13.5, platformdirs 4.11.8, pytest 9.1.1, pytest-cov 7.1.0, Ruff 0.16.7, mypy 2.3.1, build 1.6.1, setuptools 84.0.0, and wheel 0.48.0. Compatibility ranges live in `pyproject.toml`; these versions are a record, not a dependency lock.

GitHub Actions independently validates the declared Python 3.11–3.13 range across Windows, Ubuntu, and macOS on every push and pull request.
