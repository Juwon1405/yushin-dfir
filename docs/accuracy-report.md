# Accuracy Report

All numbers in this document are produced by `scripts/measure_accuracy.py`,
which is deterministic against the bundled sample evidence. Any reviewer
can reproduce them:

```bash
export PYTHONPATH="$PWD/yushin_audit/src:$PWD/yushin_mcp/src:$PWD/yushin_agent/src"
python3 scripts/measure_accuracy.py
```

## Methodology

Four metrics, applied to the bundled `examples/sample-evidence/` case
whose ground truth is committed to this repo:

| Metric | Definition |
|---|---|
| Recall | true_positives / ground_truth_count |
| False positive rate | false_positives / reported_count |
| Hallucination rate | findings whose `audit_ids` do not resolve in `audit.jsonl` |
| Evidence integrity | SHA-256 map of `sample-evidence/` before vs after the run |

Ground truth for this case:

| Finding ID | Description |
|---|---|
| F-001 | Unusual binary first-executed shortly after reported login |
| F-013 | IP-KVM device inserted ~3 min before operator logon (remote-hands pattern, ATEN VID 0557 / PID 2419) |

## Measured results (sample-evidence, find-evil-ref-01)

| Metric | Value |
|---|---|
| Ground-truth count | 2 |
| Reported count | 2 |
| True positives | F-001, F-013 |
| False positives | (none) |
| False negatives | (none) |
| **Recall** | **1.000** |
| **False positive rate** | **0.000** |
| **Hallucination count** | **0** |
| **Evidence integrity preserved** | **true** (8 files, all hashes match pre/post) |
| Self-correction observed in progress.jsonl | **true** |
| Iterations to closeout | 5 |
| Audit chain length | 3 entries, SHA-256-linked |

### Important honesty note

These numbers are **measured against a single curated reference case**
(the IP-KVM remote-hands pattern bundled in this repo). They are **not**
generalization claims. Before the deadline we will extend measurement
to:

- NIST CFReDS Hacking Case
- Digital Corpora M57-Patents
- Ali Hadi Challenge #1 (Web Server Case)

The `measure_accuracy.py` script is designed to accept any case for
which a `GROUND_TRUTH` set is defined; adding a new case is a 5-line
change plus a dataset mount.

## Baseline comparison (planned)

`measure_accuracy.py` will be extended in W5 to also drive the
unmodified Protocol SIFT agent against the same evidence, producing a
side-by-side table. The expected directional outcomes:

- Hallucination rate: **significantly lower for YuShin** — `execute_shell`
  is not exposed, which removes the primary surface for fabricated
  command output
- Evidence integrity: **100% for YuShin by architectural construction**;
  the baseline depends on prompt adherence, which is not a guarantee
- Recall: expected comparable; YuShin's differentiator is precision and
  integrity, not coverage

## Evidence-integrity bypass test results

All three bypass tests below are automated and live in
`tests/test_mcp_bypass.py`. Every run asserts them.

| # | Attack | Expected | Actual |
|---|--------|----------|--------|
| 1 | Call `execute_shell` (destructive function not registered) | `KeyError: ToolNotFound` | ✅ Pass |
| 2 | Request `hive_path="../../../etc/passwd"` (relative traversal) | `PathTraversalAttempt` | ✅ Pass |
| 3 | Request `hive_path="/etc/passwd"` (absolute escape) | `PathTraversalAttempt` | ✅ Pass |
| 4 | Smuggle `\x00` into path (NUL truncation) | `PathTraversalAttempt` | ✅ Pass |
| 5 | Surface drift — exposed set ≠ declared set | Assertion failure | ✅ Pass |
| 6 | Handler writes any file outside evidence | Assertion failure | ✅ Pass |

## Documented failure modes (honest disclosure)

1. **Correlation engine is Python, not DuckDB, for the MVP.** Above a few
   million timeline rows, `correlate_events` will need to be rewritten.
   Tracked for W4. Current implementation is correct and auditable but
   not yet benchmarked at scale.
2. **Hypothesis tracker can over-anchor on the first iteration.** When
   the first artifact examined strongly suggests a hypothesis, the
   tracker occasionally anchors too tightly. Mitigation: the
   `self_challenge.trigger_on_events` block in
   `yushin_playbook/senior-analyst-v1.yaml` forces a contrary-evidence
   check every 2 iterations. Status: implemented, under validation.
3. **macOS artifacts are out of scope for this submission.** UnifiedLogs,
   KnowledgeC, FSEvents are not covered. Listed under "What's next" on
   the public project page.

## Auditability from finding to raw evidence

Every finding in the final report carries an `audit_id`. From a finding,
the three-click path to raw evidence is:

```
finding (report.json)
  → audit_id                        # in findings[].audit_ids
  → audit.jsonl entry               # resolved with: yushin-audit lookup
  → tool_name + inputs + output_digest   # same entry
```

Demonstrated on the bundled case:

```bash
$ python3 -m yushin_audit trace examples/out/find-evil-ref-01/audit.jsonl F-013
{ "finding_id": "F-013", "entry_count": 2, "entries": [ ... ] }
```

This is the property that makes a practitioner comfortable standing
behind YuShin's output in a courtroom-grade report.
