# Pending tests

Tests in this directory exercise functions that are **not on the
current 31-tool MCP surface** but are scaffolded for Phase 2:

- `test_extended_mcp.py` — needs `parse_evtx`, `volatility_summary`,
  `duckdb_timeline_correlate`. Surface has the *successors* of these
  (`analyze_event_logs`, `correlate_timeline`) but not the originals.

- `test_sigma_matcher.py` — needs `match_sigma_rules`. Sigma matching
  is part of Phase 2 (detection-engineering work, not the hackathon
  submission).

These tests are **not** in the "17/17 passing on a clean clone" count
that the README cites. They live here so the test intent is preserved
for when the corresponding surface lands in Phase 2.

Do not move them back to `tests/` until the corresponding functions
are registered in `dart_mcp` and the `tests/_pending/test_*.py`
imports succeed cleanly.
