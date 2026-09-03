"""
nlp_classifier/main.py — Person 2: NLP phishing text classifier.

Public contract:
    classify_text(body_text: str) -> dict

Return shape:
{
    "label":      "phishing" | "legitimate",
    "confidence": float,    # 0.0 – 1.0
    "top_words":  [str],    # tokens most responsible for the score
}

Rules:
- Never raise an exception.
- Text classification is deliberately the *least-trusted* signal in the
  fraud score — header/typosquat signals outweigh it because an attacker
  can craft legitimate-looking body text, but cannot fake a DKIM signature.
"""


def classify_text(body_text: str) -> dict:
    """Classify *body_text* as phishing or legitimate.

    STUB — currently returns hardcoded example data. Replace with a real
    TF-IDF + LogisticRegression model (trained in train.py and saved with
    joblib) in Phase 1.

    Args:
        body_text: The plain-text body of the email.

    Returns:
        A dict with keys: label, confidence, top_words.
    """
    # HARDCODED STUB — replace with: model.predict() + explain() in Phase 1.
    return {
        "label": "phishing",
        "confidence": 0.91,
        "top_words": ["verify", "account", "limited", "click", "immediately"],
    }
