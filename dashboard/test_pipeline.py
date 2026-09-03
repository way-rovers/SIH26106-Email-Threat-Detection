"""dashboard/test_pipeline.py — shape-check tests for run_pipeline()."""

import pytest
from dashboard.pipeline import run_pipeline

EML_PATH = "contracts/fixtures/sample_phish_1.eml"

REQUIRED_KEYS = {
    "email_id",
    "parsed",
    "typosquat",
    "geo_hops",
    "classification",
    "correlation",
    "fraud_score",
    "verdict",
}

VALID_VERDICTS = {"malicious", "suspicious", "safe"}


def test_run_pipeline_returns_dict():
    result = run_pipeline(EML_PATH)
    assert isinstance(result, dict), "run_pipeline() must return a dict"


def test_run_pipeline_has_required_keys():
    result = run_pipeline(EML_PATH)
    missing = REQUIRED_KEYS - result.keys()
    assert not missing, f"run_pipeline() is missing keys: {missing}"


def test_run_pipeline_verdict_is_valid():
    result = run_pipeline(EML_PATH)
    assert result["verdict"] in VALID_VERDICTS, \
        f"verdict must be one of {VALID_VERDICTS}, got {result['verdict']!r}"


def test_run_pipeline_fraud_score_in_range():
    result = run_pipeline(EML_PATH)
    assert 0.0 <= result["fraud_score"] <= 100.0, \
        "fraud_score must be in [0.0, 100.0]"


def test_run_pipeline_geo_hops_is_list():
    result = run_pipeline(EML_PATH)
    assert isinstance(result["geo_hops"], list), "geo_hops must be a list"
