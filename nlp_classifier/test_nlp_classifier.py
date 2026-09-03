"""nlp_classifier/test_nlp_classifier.py — shape-check tests for classify_text()."""

import pytest
from nlp_classifier.main import classify_text

REQUIRED_KEYS = {"label", "confidence", "top_words"}
VALID_LABELS = {"phishing", "legitimate"}


def test_classify_text_returns_dict():
    result = classify_text("Verify your account immediately or it will be suspended.")
    assert isinstance(result, dict), "classify_text() must return a dict"


def test_classify_text_has_required_keys():
    result = classify_text("Hello, your invoice is attached.")
    missing = REQUIRED_KEYS - result.keys()
    assert not missing, f"classify_text() is missing keys: {missing}"


def test_classify_text_label_is_valid():
    result = classify_text("Click here to claim your prize!")
    assert result["label"] in VALID_LABELS, \
        f"label must be one of {VALID_LABELS}, got {result['label']!r}"


def test_classify_text_confidence_in_range():
    result = classify_text("Your account needs attention.")
    assert 0.0 <= result["confidence"] <= 1.0, \
        "confidence must be in [0.0, 1.0]"


def test_classify_text_top_words_is_list():
    result = classify_text("Urgent: verify now.")
    assert isinstance(result["top_words"], list), "top_words must be a list"
