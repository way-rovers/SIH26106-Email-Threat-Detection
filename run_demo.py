"""
run_demo.py — Smoke-test script for the full pipeline.

Run from the repo root:
    python run_demo.py

If this script exits with no errors, the entire plumbing works — even with
all-stub data. That's the bar for Phase 0 / day one.
"""

import json
import sys

from dashboard.pipeline import run_pipeline

EML_PATH = "contracts/fixtures/sample_phish_1.eml"


def main():
    print(f"Running pipeline on: {EML_PATH}\n{'=' * 60}")
    try:
        result = run_pipeline(EML_PATH)
    except Exception as exc:
        print(f"[FAIL] Pipeline raised an unexpected exception: {exc}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result, indent=2, default=str))
    print(f"\n{'=' * 60}")
    print(
        f"✅  Smoke test passed.\n"
        f"    Verdict: {result.get('verdict', 'unknown').upper()}  "
        f"| Fraud score: {result.get('fraud_score', '?')}"
    )


if __name__ == "__main__":
    main()
