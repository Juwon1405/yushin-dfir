"""End-to-end test: agent runs, self-corrects on USB contradiction."""
import json
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for p in ["agentic_dart_audit/src", "agentic_dart_mcp/src", "agentic_dart_agent/src"]:
    sys.path.insert(0, str(REPO / p))


def test_full_run_produces_self_correction():
    os.environ["AGENTIC_DART_EVIDENCE_ROOT"] = str(REPO / "examples" / "sample-evidence")
    # Re-import with new env var
    if "agentic_dart_mcp" in sys.modules:
        del sys.modules["agentic_dart_mcp"]
    from agentic_dart_agent import main
    with tempfile.TemporaryDirectory() as td:
        rc = main(["--case", "ci-test", "--out", td, "--mode", "deterministic"])
        assert rc == 0, "agent exited non-zero"

        progress_lines = (Path(td) / "progress.jsonl").read_text().splitlines()
        joined = " ".join(progress_lines).lower()
        assert "contradiction" in joined or "self-correction" in joined, \
            "self-correction trace missing from progress.jsonl"

        report = json.loads((Path(td) / "report.json").read_text())
        finding_ids = [f["finding_id"] for f in report["findings"]]
        assert "F-013" in finding_ids, f"IP-KVM finding missing: {finding_ids}"


if __name__ == "__main__":
    test_full_run_produces_self_correction()
    print("test_full_run_produces_self_correction OK")
