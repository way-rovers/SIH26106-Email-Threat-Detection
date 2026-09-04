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
"""

import os
import re
import joblib

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model", "classifier.pkl")
PHISHING_THRESHOLD = 0.65

_VECTORIZER = None
_CLF = None


def _load_model():
    global _VECTORIZER, _CLF
    if _VECTORIZER is None or _CLF is None:
        _VECTORIZER, _CLF = joblib.load(MODEL_PATH)
    return _VECTORIZER, _CLF


def _clean_text(text):
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"http\S+|www\.\S+", " URL ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip().lower()


def classify_text(body_text: str) -> dict:
    try:
        if not body_text or not body_text.strip():
            return {"label": "legitimate", "confidence": 0.0, "top_words": []}

        vectorizer, clf = _load_model()
        cleaned = _clean_text(body_text)
        vec = vectorizer.transform([cleaned])

        proba = clf.predict_proba(vec)[0]
        phishing_prob = proba[1]
        pred_class = 1 if phishing_prob >= PHISHING_THRESHOLD else 0
        label = "phishing" if pred_class == 1 else "legitimate"
        confidence = float(proba[pred_class])

        feature_names = vectorizer.get_feature_names_out()
        coefs = clf.coef_[0]
        row = vec.tocoo()
        contributions = [
            (feature_names[col], vec[0, col] * coefs[col])
            for col in row.col
        ]
        contributions.sort(key=lambda x: abs(x[1]), reverse=True)
        top_words = [w for w, _ in contributions[:5]]

        return {"label": label, "confidence": confidence, "top_words": top_words}

    except Exception:
        return {"label": "legitimate", "confidence": 0.0, "top_words": []}