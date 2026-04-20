# yushin-playbook

Senior-analyst sequencing rules, expressed as YAML so other responders can contribute without touching Python.

## Philosophy

What makes a senior analyst effective is not the tools — it is the **sequence** and the **self-challenge**. This directory captures that sequence as data.

A playbook is a YAML file that tells `yushin-agent`:

1. In what order to examine artifacts (volatile-first, then timeline, then anomaly, then hypothesis, then validate)
2. What "normal" looks like for each artifact class
3. What contradiction patterns must trigger a self-correction iteration
4. When to declare a finding confirmed, inferred, or unresolvable

## Current playbook

- [`senior-analyst-v1.yaml`](./senior-analyst-v1.yaml) — general-purpose incident triage, biased toward insider-threat and DPRK IT-worker-style case classes

## Contributing a playbook

PRs welcome. Each playbook must:

- Declare a `target_case_class`
- List the MCP functions it depends on
- Include at least one `contradiction_pattern` with a documented self-correction branch
- Be linted against the schema in `docs/architecture.md`

## Status

v1 is the reference playbook for the FIND EVIL! submission. Additional playbooks (ransomware, supply-chain, macOS-focused) are on the post-submission roadmap.
