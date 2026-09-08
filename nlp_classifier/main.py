"""
nlp_classifier/main.py — NLP phishing text classifier.

Public contract:
    classify_text(body_text: str) -> dict

Return shape:
{
    "label":      "phishing" | "legitimate",
    "confidence": float,    # 0.0 – 1.0
    "top_words":  [str],    # tokens most responsible for the score
}

Never raises — always returns the safe-default dict on any failure.
"""

import os
import re
import json
import joblib

# ── Paths ──────────────────────────────────────────────────────────
_DIR = os.path.dirname(__file__)
MODEL_PATH          = os.path.join(_DIR, "model", "classifier.pkl")
THRESHOLD_META_PATH = os.path.join(_DIR, "model", "threshold_meta.json")

# ── Load threshold from metadata at import time (fallback: 0.65) ──
def _load_threshold() -> float:
    """Read the trained threshold from threshold_meta.json.

    Falls back to 0.65 (the original hardcoded value) if the file is
    missing or malformed, so the module is always importable even before
    the new model artefacts exist.
    """
    try:
        with open(THRESHOLD_META_PATH, encoding="utf-8") as fh:
            return float(json.load(fh)["threshold"])
    except Exception:
        return 0.65


PHISHING_THRESHOLD: float = _load_threshold()

# ── Lazy model cache ───────────────────────────────────────────────
_VECTORIZER = None
_CLF        = None


def _load_model():
    global _VECTORIZER, _CLF
    if _VECTORIZER is None or _CLF is None:
        _VECTORIZER, _CLF = joblib.load(MODEL_PATH)
    return _VECTORIZER, _CLF


# ── Text pre-processing (unchanged) ────────────────────────────────
def _clean_text(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"http\S+|www\.\S+", " URL ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip().lower()


# ── Top-word extraction ─────────────────────────────────────────────
def _extract_top_words(vectorizer, clf, vec_row, n: int = 5) -> list[str]:
    """Return the *n* tokens with the largest |contribution| to the score.

    Handles both plain TfidfVectorizer and FeatureUnion(word+char).

    With FeatureUnion, sklearn prefixes feature names with the sub-pipeline
    name: ``word__account``, ``char__ ac``.  We surface only the *word-level*
    features (``word__`` prefix) so the result is always human-readable, and
    strip the prefix before returning.  If the vectorizer is a plain
    TfidfVectorizer (old-style model), no prefix stripping is needed.
    """
    try:
        feature_names = vectorizer.get_feature_names_out()   # works for both types
        coefs         = clf.coef_[0]
        row           = vec_row.tocoo()

        contributions = [
            (feature_names[col], float(vec_row[0, col] * coefs[col]))
            for col in row.col
        ]

        # Filter to word-level features when FeatureUnion is in use
        is_feature_union = hasattr(vectorizer, "transformer_list")
        if is_feature_union:
            contributions = [
                (name.removeprefix("word__"), score)
                for name, score in contributions
                if name.startswith("word__")
            ]

        contributions.sort(key=lambda x: abs(x[1]), reverse=True)
        return [w for w, _ in contributions[:n]]

    except Exception:
        return []


# ── Public API ─────────────────────────────────────────────────────
def classify_text(body_text: str) -> dict:
    """Classify *body_text* as phishing or legitimate.

    Contract: never raises; always returns
    ``{"label": str, "confidence": float, "top_words": list[str]}``.
    """
    try:
        if not body_text or not body_text.strip():
            return {"label": "legitimate", "confidence": 0.0, "top_words": []}

        vectorizer, clf = _load_model()
        cleaned         = _clean_text(body_text)
        vec             = vectorizer.transform([cleaned])

        proba         = clf.predict_proba(vec)[0]
        phishing_prob = proba[1]
        pred_class    = 1 if phishing_prob >= PHISHING_THRESHOLD else 0
        label         = "phishing" if pred_class == 1 else "legitimate"
        confidence    = float(proba[pred_class])

        top_words = _extract_top_words(vectorizer, clf, vec)

        return {"label": label, "confidence": confidence, "top_words": top_words}

    except Exception:
        return {"label": "legitimate", "confidence": 0.0, "top_words": []}