# yushin-audit

Structured JSONL logger. Side-tapped from every MCP call.

## Every entry

```json
{
  "ts": "2026-06-01T14:23:17.412Z",
  "run_id": "<uuid>",
  "iteration": 2,
  "tool_name": "extract_mft_timeline",
  "inputs": {"start": "...", "end": "..."},
  "output_digest": "sha256:...",
  "audit_id": "a7f3e9",
  "token_count_in": 412,
  "token_count_out": 1847,
  "finding_ids": ["F-013", "F-014"]
}
```

## Guarantees

- **Append-only.** The logger does not expose a delete or truncate function.
- **Immutable per run.** Each run is sealed with a final SHA-256 of the full JSONL at finalization.
- **Traceability.** Every finding in the final report carries an `audit_id` that resolves, in ≤3 clicks, to the exact MCP call, the exact underlying SIFT tool command, and the raw tool output.

## Status

Specification finalized. Implementation follows `yushin-mcp` alpha.
