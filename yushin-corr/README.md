# yushin-corr

Cross-artifact correlation engine. Python + DuckDB.

## Purpose

Perform timeline joins across independent evidence sources. When two sources contradict, flag the contradiction as **UNRESOLVED** rather than smoothing over it.

## Sources correlated

| Source | Typical artifacts |
|---|---|
| Disk | MFT, Amcache, Prefetch, USB setupapi, registry hives |
| Memory | Process tree, network sockets, in-RAM registry |
| Network | PCAP flows, DNS, authentication telemetry |

## Contradiction handling

When `correlate_events(hypothesis_id)` finds two sources that disagree (e.g., USB insert time precedes authenticated logon by more than the tolerance window), the engine does **not** pick a winner. It emits an `UNRESOLVED` record into `progress.jsonl` with both sides preserved. The agent is architecturally required to address the contradiction before writing to the final report.

## DuckDB choice

In-process, zero-config, columnar. Timeline joins over millions of MFT rows finish in single-digit seconds on SIFT Workstation defaults. No external DB, no credentials, no network.

## Status

Scaffolding. First correlation pass targets mid-May 2026.
