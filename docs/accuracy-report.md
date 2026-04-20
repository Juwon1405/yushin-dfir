# Accuracy Report

All numbers in this document are produced by `scripts/measure_accuracy.py`
against bundled sample evidence. Reproducible by any reviewer:

```bash
export PYTHONPATH="$PWD/yushin_audit/src:$PWD/yushin_mcp/src:$PWD/yushin_agent/src"
python3 scripts/measure_accuracy.py
```

## MCP surface — 15 functions, all implemented end-to-end

### Windows

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

### macOS

| Category | Function | Purpose |
|---|---|---|
| System log | `parse_unified_log` | UnifiedLog NDJSON + rule pack (5 rules) |
| User activity | `parse_knowledgec` | App usage + device state (SQLite read-only) |
| Filesystem | `parse_fsevents` | FSEvents journal with suspicious-path detection |

### Cross-platform

| Category | Function | Purpose |
|---|---|---|
| Correlation | `correlate_events` | Proximity join (legacy) |
| Correlation | `correlate_timeline` | **DuckDB scale engine** |

## Measured results

### Case 01 — IP-KVM remote-hands insider (Windows)

| Metric | Value |
|---|---|
| Recall | **1.000** |
| False positive rate | **0.000** |
| Hallucination count | **0** |
| Evidence integrity preserved | **true** (30+ files, SHA-256 pre/post match) |
| Self-correction observed | **true** |
| Audit chain length | 3 entries, SHA-256-linked |

### Case 02 — LOTL PowerShell (Windows)

| MCP call | Real output on bundled evidence |
|---|---|
| `get_process_tree` | 10 processes, 3 LOTL flags (powershell→cmd×2, cmd→many×1) |
| `analyze_event_logs` | 5 events, 4 alerts (1 critical LSASS, 1 high PS-dl-exec) |
| `detect_persistence` | 6 mechanisms, 3 HIGH severity |
| `correlate_timeline` (DuckDB) | 3 cross-source + 1 kvm→logon |

### Case 03 — macOS remote-admin infection (NEW)

| MCP call | Real output on bundled evidence |
|---|---|
| `parse_unified_log` | 8 events, 7 alerts (3 high, 4 medium) |
| `parse_knowledgec` | 9 activity events, Terminal top app (3 focus events) |
| `parse_fsevents` | 10 events, 5 suspicious-path hits (stage2.bin, exfil.zip, mimikatz-mac) |

## Bypass test results

| # | Attack | Result |
|---|--------|--------|
| 1 | Call unregistered destructive function | ✅ `KeyError: ToolNotFound` |
| 2 | Relative path traversal | ✅ `PathTraversalAttempt` |
| 3 | Absolute path escape | ✅ `PathTraversalAttempt` |
| 4 | NUL-byte smuggling | ✅ `PathTraversalAttempt` |
| 5 | Surface drift (15-function positive set) | ✅ Exact match enforced |
| 6 | Handler writes outside evidence | ✅ Zero writes |

## Platform support

| Platform | Status | Notes |
|---|---|---|
| SANS SIFT Workstation | ✅ Primary target | All functions work |
| Ubuntu 22.04 / 24.04 | ✅ Tested | All functions work |
| macOS 12+ (Intel or Apple Silicon) | ✅ Tested | Runs identically; see `docs/running-on-macos.md` |
| Windows (WSL2) | ⚠ Untested | Should work — pure Python |

## Honest limitations

1. **Eric Zimmerman tools (MFTECmd, PECmd, AppCompatCacheParser)** are
   consumed via sidecar CSV/JSON. Direct binary parsing requires .NET
   runtime. Sidecar-first design keeps YuShin portable.
2. **FSEventsParser and `log show`** are external to YuShin — they produce
   the input YuShin consumes. This is analogous to the Windows sidecar model.
3. **Volatility memory forensics** is out of scope for MVP. Post-hackathon.
4. **Event log / UnifiedLog rule packs are deliberately small** (5 rules
   each). Designed to demonstrate the detection surface, not replace
   Sigma / hayabusa / mandiant's macOS rules. Rule schema is extensible.

## Roadmap progress (since Gemini external review)

| Capability | Original status | Now |
|---|---|---|
| MFT / Prefetch / Amcache parsing | "scaffolded" | ✅ Implemented |
| AppCompat / ShimCache parsing | "scaffolded" | ✅ Implemented |
| ShellBags parsing | not mentioned | ✅ Implemented |
| Process tree + LOTL detection | "ready to be added" | ✅ Implemented |
| Persistence (Run keys + Services + Tasks) | not mentioned | ✅ Implemented |
| Event log analysis with rule pack | not mentioned | ✅ Implemented |
| DuckDB correlation at scale | "planned" | ✅ Implemented |
| **macOS UnifiedLog** | "planned" | ✅ **Implemented** |
| **macOS KnowledgeC** | "planned" | ✅ **Implemented** |
| **macOS FSEvents** | "planned" | ✅ **Implemented** |
| Volatility memory forensics | "planned" | 📋 Post-hackathon |
| Live MCP mode (Claude Code stdio) | "planned" | 📋 W5 (mid-May) |

**10 of 12 roadmap items are real implementations.**

## Case 04 — Phishing → Download → Execution → Exfiltration (NEW)

Covers the infection-vector and data-loss halves of the attack chain,
which earlier case studies did not address.

| MCP call | Real output on bundled evidence |
|---|---|
| `parse_browser_history` | 7 visits, 3 flagged suspicious (.tk, raw IP, file-drop) |
| `analyze_downloads` (browser_db) | 3 downloads, 2 executables, 2 from suspicious URLs |
| `analyze_downloads` (zone_identifier) | 2 MOTW-tagged files, both ZoneId=3 (Internet) |
| `correlate_download_to_execution` | 1 critical chain: URL → file → execution in 390s |
| `detect_exfiltration` | 5 signals, max_severity=critical, 4 archive→upload chains |

## Coverage map (what YuShin can actually see)

```
        [infection vector]  [foothold]    [action on objectives]
             │                 │                   │
     ┌───────┴────────┐  ┌────┴────┐  ┌────────────┴────────────┐
     │ parse_browser_ │  │ get_    │  │ detect_exfiltration    │
     │ history        │  │ process_│  │ correlate_download_to_ │
     │ analyze_       │  │ tree    │  │   execution            │
     │ downloads      │  │ detect_ │  │ correlate_timeline     │
     │ (MOTW)         │  │persist. │  │                        │
     └────────────────┘  └─────────┘  └─────────────────────────┘
             │                 │                   │
             └──────── all joined by correlate_timeline ────────┘
```

No gap in the kill chain.

## Case 05 — Authentication + Lateral Movement (NEW)

Closes the WHO dimension. Covers AD/Kerberos attack patterns, Windows
logon-type analysis, Unix SSH/sudo analysis, lateral-movement tool
detection (PsExec/WMIExec/WinRS), and cross-platform privilege
escalation.

| MCP call | Real output on bundled evidence |
|---|---|
| `analyze_windows_logons` | 16 events → 5 success + 4 fail + 2 explicit; 1 brute-force survivor (jbang@203.0.113.42 after 4 fails); 1 after-hours RDP at 02:17 |
| `detect_lateral_movement` | 2 remote-admin hits (psexec + wmiexec), 5 suspicious pairs, all HIGH |
| `analyze_kerberos_events` | **3 Kerberoasting** (RC4 TGS to MSSQL/Exchange/LDAP), **1 AS-REP Roast** (alice no-preauth) |
| `analyze_unix_auth` | 10-failure brute force from 203.0.113.42 → 1 survivor (jbang publickey); 3 dangerous sudo commands (shadow read, curl\|bash) |
| `detect_privilege_escalation` | 2 CRITICAL transitions: SSH → root in 85s and 100s |

## Coverage map — full DFIR dimensions

```
WHAT executed      WHAT? HOW it got in   WHO authenticated   WHEN       OUTCOME
────────────       ─────────────────     ────────────────    ────       ───────
get_amcache        parse_browser_history analyze_windows_    extract_   detect_
parse_prefetch     analyze_downloads     logons              mft_       exfil
parse_shimcache    (+ MOTW)              detect_lateral_     timeline   tration
get_process_tree   correlate_download_   movement            parse_
parse_fsevents     to_execution          analyze_kerberos_   fsevents
                                         events              parse_
parse_shellbags                          analyze_unix_auth   unified_
list_scheduled_                          detect_privilege_   log
tasks                                    escalation
detect_persistence                                           
analyze_event_logs                                           
parse_unified_log                                            
parse_knowledgec                                             
```

All four DFIR dimensions (WHAT, HOW, WHO, WHEN) are covered across
Windows, macOS, and Linux.
