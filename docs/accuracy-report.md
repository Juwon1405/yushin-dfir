# Accuracy Report

All numbers in this document are produced by `scripts/measure_accuracy.py`,
deterministic against the bundled sample evidence. Any reviewer can reproduce:

```bash
export PYTHONPATH="$PWD/yushin_audit/src:$PWD/yushin_mcp/src:$PWD/yushin_agent/src"
python3 scripts/measure_accuracy.py
```

## MCP surface (all 12 functions implemented end-to-end)

| Category | Function | Purpose |
|---|---|---|
| Execution | `get_amcache` | Amcache.hve execution records |
| Execution | `parse_prefetch` | Prefetch + run history |
| Execution | `parse_shimcache` | AppCompatCache (survives binary deletion) |
| Execution | `get_process_tree` | Parent-child chains + LOTL flags |
| User activity | `analyze_usb_history` | setupapi + SYSTEM hive |
| User activity | `parse_shellbags` | Folder navigation history |
| User activity | `extract_mft_timeline` | MFT (MFTECmd CSV) |
| System state | `list_scheduled_tasks` | Tasks/ enumeration |
| System state | `detect_persistence` | Run keys + Services + Tasks |
| System state | `analyze_event_logs` | EVTX rule pack (5 rules) |
| Cross-artifact | `correlate_events` | Proximity join (legacy) |
| Cross-artifact | `correlate_timeline` | **DuckDB scale-capable engine** |

## Measured results

### Case 01 — IP-KVM remote-hands insider

| Metric | Value |
|---|---|
| Recall | **1.000** |
| False positive rate | **0.000** |
| Hallucination count | **0** |
| Evidence integrity preserved | **true** (25 files, SHA-256 pre/post match) |
| Self-correction observed | **true** |
| Iterations to closeout | 5 |
| Audit chain length | 3 entries, SHA-256-linked |

### Case 02 — LOTL PowerShell attack (new)

| MCP call | Result | Finding count |
|---|---|---|
| `get_process_tree` | 10 processes, 3 LOTL flags | 3 (powershell→cmd×2, cmd→many×1) |
| `analyze_event_logs` | 5 events examined, 4 alerts | 1 critical (LSASS) + 1 high (PS-dl-exec) + 2 medium |
| `detect_persistence` | 6 mechanisms, 3 HIGH severity | 3 (Run key + Temp-path service + task) |
| `correlate_timeline` (DuckDB) | 4 events joined | 1 kvm→logon + 3 cross-source |

## Bypass test results

| # | Attack | Result |
|---|--------|--------|
| 1 | Call `execute_shell` | ✅ `KeyError: ToolNotFound` |
| 2 | `hive_path="../../../etc/passwd"` | ✅ `PathTraversalAttempt` |
| 3 | `hive_path="/etc/passwd"` | ✅ `PathTraversalAttempt` |
| 4 | `hive_path="legit\x00/etc/passwd"` | ✅ `PathTraversalAttempt` |
| 5 | Surface drift | ✅ exact 12-function positive set enforced |
| 6 | Handler writes outside evidence | ✅ zero writes observed |

## Honest limitations

1. **MFTECmd, PECmd, AppCompatCacheParser wrappers.** YuShin consumes the
   CSV/JSON output of these tools via sidecar files. True binary parsers
   for `$MFT`, `.pf`, and SYSTEM hives require .NET runtime (for Eric
   Zimmerman's toolset) or native C parsers. Sidecar approach is
   intentional — it lets YuShin run in any Python environment while
   preserving the forensic quality of the upstream parsers.

2. **Memory forensics (Volatility) is out of MVP scope.** Noted in
   Gemini's external review. This is a deliberate boundary — Volatility
   integration is 2–3 months of work. See the Roadmap section.

3. **macOS artifacts are out of MVP scope.** UnifiedLogs, KnowledgeC,
   FSEvents, Spotlight metadata. Planned post-hackathon.

4. **Event log rule pack is deliberately small (5 rules).** Designed to
   demonstrate the detection surface; not a replacement for Sigma/hayabusa.
   The rule schema is extensible — PRs welcome.

## Roadmap — addressing Gemini's review points

Gemini's external assessment flagged these as "scaffolded":

| Capability | Status | Target |
|---|---|---|
| MFT / Prefetch / Amcache real parsing | ✅ **Implemented** via sidecar-CSV approach | — |
| AppCompat / ShimCache parsing | ✅ **Implemented** (`parse_shimcache`) | — |
| ShellBags parsing | ✅ **Implemented** (`parse_shellbags`) | — |
| Process tree + LOTL detection | ✅ **Implemented** (`get_process_tree`) | — |
| Persistence (Run keys + Services + Tasks) | ✅ **Implemented** (`detect_persistence`) | — |
| Event log analysis with rule pack | ✅ **Implemented** (`analyze_event_logs`) | — |
| DuckDB correlation at scale | ✅ **Implemented** (`correlate_timeline`) | — |
| Volatility memory forensics | 📋 Planned | Post-hackathon |
| macOS UnifiedLog / KnowledgeC | 📋 Planned | Post-hackathon |
| Live MCP mode (Claude Code stdio) | 📋 Planned | W5 (mid-May) |

**7 of 9 roadmap items are now real implementations, not scaffolds.**
