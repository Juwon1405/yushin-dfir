# Changelog

All notable changes to YuShin are recorded here.

## [Unreleased] — 2026-04-20

### Added
- Real implementations for `extract_mft_timeline`, `parse_prefetch`,
  `list_scheduled_tasks`, and `correlate_events`. No more scaffolds.
- `yushin-audit` CLI with `verify`, `lookup`, `trace`, `summary`
  subcommands. Enables the "3 clicks from finding to raw evidence"
  claim to be executed, not just asserted.
- `scripts/measure_accuracy.py` — deterministic accuracy measurement
  producing the numbers committed to `docs/accuracy-report.md`.
- `tests/test_mcp_bypass.py` — six adversarial bypass scenarios
  (unregistered function, ../ traversal, absolute-path escape, NUL
  truncation, surface drift, write attempt).
- `_safe_resolve` hardened against absolute-path escape, symlink
  chains, and NUL-byte truncation.
- `--max-iterations` enforcement in the agent controller with
  forced-exit closeout report.
- `examples/case-studies/case-01-ipkvm-insider/` walkthrough for
  judges.
- `.github/workflows/ci.yml` — CI across Python 3.10–3.12.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`.
- Agent audit entries now carry `finding_ids`, which is what
  `yushin-audit trace <finding_id>` relies on.

### Changed
- `docs/accuracy-report.md` rewritten to show REAL measured numbers
  (recall=1.0, FP rate=0.0, hallucination count=0 on sample case)
  instead of TBD placeholders.

## [0.1.0] — 2026-04-20

Initial MVP. See `git log` for the bootstrap commit history.
