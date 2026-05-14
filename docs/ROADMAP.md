# Roadmap & How to Contribute

Quick reference for where Agentic-DART is headed and how to join in.

## Roadmap

| Version | Scope | Status |
|---------|-------|--------|
| **v0.3** | SANS FIND EVIL! 2026 submission | In progress (closes 2026-06-15) |
| **v0.4** | Post-hackathon hardening: CI matrix, M57 OOM fix, HTTPS transport | Planned |
| **v0.5** | Phase 2: agentic detection engineering (Sigma rule synthesis, cloud DFIR) | Planned |

### v0.3 (current milestone)

Complete the SANS FIND EVIL! submission with:
- Full typed read-only MCP surface
- Self-correction agent loop validated end-to-end
- Accuracy report with reproducible measurements
- Case study walkthrough (PTH timestomp)

### v0.4 (post-hackathon)

- CI matrix across Linux, macOS, Windows
- Fix M57 dataset out-of-memory issue
- HTTPS transport for MCP
- Expanded documentation and user guides

### v0.5 (Phase 2)

- Sigma rule synthesis from observed behavior
- Cloud DFIR support (AWS CloudTrail, Azure Activity Log)
- Multi-agent framework pattern
- Community playbook library

## How to Contribute

Read [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the full guide. The short version:

### During competition window (through 2026-06-15)

- **Accepted**: Small, focused PRs on `good-first-issue` items (CI, typos, docs fixes)
- **Deferred**: Anything labeled `post-sans`
- **Not accepted**: New MCP functions, playbook changes, agent loop modifications

### After 2026-06-15

Standard open-source contribution flow resumes.

### Quick contribution types

| What | Where | Process |
|------|-------|---------|
| New playbook YAML | `dart_playbook/` | Open a PR |
| New MCP parser | `dart_mcp/` | Open an issue first (architecture review) |
| Documentation | `docs/`, `examples/` | Open a PR |
| Bug reports | GitHub Issues | Include repro steps |
| Feature ideas | GitHub Discussions | Discuss before building |

### Before opening a PR

```bash
python3 -m pytest tests/          # All tests pass
python3 scripts/measure_accuracy.py  # Accuracy unchanged
```

## Where Things Live

- **Code & MCP surface**: `dart_mcp/`, `dart_audit/`, `dart_agent/`, `dart_corr/`, `dart_playbook/`
- **Architecture**: `dart-architecture.png` + `docs/architecture.md`
- **Sample walkthrough**: `docs/case-pth-timestomp.md`
- **Accuracy data**: `docs/accuracy-report.md`
- **Contributing guide**: `CONTRIBUTING.md`
- **Code of conduct**: `CODE_OF_CONDUCT.md`

## Contact

Author info is in the README. For security concerns, use a private security advisory rather than a public issue.
