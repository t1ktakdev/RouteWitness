# Contributing

Install Python 3.11+ and run `python -m pip install -e '.[dev]'` in an isolated environment.

Before a patch: `python -m ruff format --check .`, `python -m ruff check .`, `python -m mypy`, `python -m pytest --cov=routewitness --cov-branch`, `python -m build`.

Add a deterministic fixture for a new diagnosis rule. Check contradictory evidence and partial capabilities, not just the happy path. Correctness tests block outbound socket connections; use injected providers, fake clocks and mocked platform responses. Do not weaken a scenario test to match an incorrect implementation. Native OS fixtures must omit real addresses, SSIDs and account names. Label simulations clearly.

Keep dependencies small. Do not introduce automatic network configuration changes, elevation, uploads, broad scans, packet content collection, shell interpolation, unbounded process output, uncancellable resolver threads or LLM-based diagnosis. Every external operation needs a timeout. New schema fields require documentation, limits, sanitization and round-trip tests. HTML must have escaped dynamic values and no remote resources.

Bug reports should include version, OS, `doctor` output and a reviewed sanitized report. Do not attach raw incident.json by default. Security issues: see SECURITY.md.

## Release checklist

Run the entire configured native CI matrix, inspect wheel/sdist and install the wheel in a clean environment. Verify help, demo, reports, cancellation and an actual watch session on each OS. Recheck PyPI and repository name availability. Confirm license and truthful README, no credentials or local machine paths, generated example reproducibility, and clean git status. Publication is a separate maintainer action; there is no automated PyPI publish workflow.
