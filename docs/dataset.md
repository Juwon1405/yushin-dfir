# Evidence Dataset Documentation

## Primary dataset

**SANS FIND EVIL! starter evidence dataset** — distributed via the Protocol SIFT Slack server at hackathon launch (April 15, 2026).

- Source: Protocol SIFT Slack, `#starter-data` channel
- License: Per SANS hackathon terms (research / evaluation use)
- Format: E01 disk image + raw memory capture + supporting network PCAP
- Integrity: SHA-256 hashes recorded in `audit.jsonl` at agent startup

## Secondary datasets (publicly redistributable)

To validate breadth against a range of case classes beyond the starter data, we exercise YuShin against the following:

### 1. NIST CFReDS — Hacking Case

- **Source:** https://cfreds.nist.gov/all/NIST/HackingCase
- **Why:** Canonical intrusion-analysis scenario with published ground truth
- **Ground truth:** bundled with the dataset by NIST

### 2. Digital Corpora — M57-Patents

- **Source:** https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario/
- **Why:** Multi-host, multi-day scenario with insider-threat elements; matches YuShin's target case class
- **Ground truth:** published scenario narrative and artifact list

### 3. Ali Hadi — DFIR Challenges

- **Source:** https://github.com/ashemery/DFIR_Challenges
- **Why:** Community-vetted challenges with documented answer keys; useful for regression

## Case classes exercised

| Class | Artifacts | Ground-truth source |
|---|---|---|
| Insider-threat / unauthorized access | USB history, Amcache, Prefetch, Security event logs | Starter + M57-Patents |
| Remote-hands / IP-KVM pattern | USB setupapi, authentication telemetry, process tree | Starter (primary target) |
| Living-off-the-land | Scheduled tasks, PowerShell history, WMI persistence | CFReDS Hacking Case |

## Per-dataset expected findings

Populated as each dataset is run end-to-end. Entries follow this schema:

```yaml
dataset: <name>
run_id: <uuid>
expected_findings:
  - id: F-001
    description: "..."
    audit_ids: ["a1b2c3", "d4e5f6"]
    mcp_calls: ["get_amcache", "parse_prefetch"]
    status: confirmed | missed | false_positive
```

Final tables will be committed here no later than 72 hours before the submission deadline.

## Integrity and reproducibility

- All dataset files are mounted read-only (`mount -o ro,noload`) before the agent is invoked
- SHA-256 of every input is recorded in `audit.jsonl` at startup and at finalization
- No dataset file is ever modified; extraction writes only to the output directory
- Chain-of-custody for each run is preserved in `audit.jsonl` with `run_id`

## Status

Active development. Starter-dataset results will be the basis of the demo video and accuracy report. Secondary-dataset results will be appended before deadline.
