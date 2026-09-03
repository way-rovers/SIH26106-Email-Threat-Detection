"""
nlp_classifier/train.py — Person 2: train and persist the phishing classifier.

Intended pipeline (implement in Phase 1):
    1. Load a labelled dataset (e.g. Enron spam corpus, TREC spam, or a custom
       phishing corpus). Each sample is a raw email body string + a label
       ("phishing" | "legitimate").
    2. Pre-process: lowercase, strip HTML, remove URLs/tokens we don't want to
       leak into the model.
    3. Vectorise with sklearn TfidfVectorizer (unigrams + bigrams, max 20k
       features, sublinear_tf=True).
    4. Train a LogisticRegression classifier (C=1.0, max_iter=1000,
       class_weight="balanced" if the corpus is skewed).
    5. Evaluate: print classification_report on a held-out test split.
       Aim for F1 ≥ 0.90 on the "phishing" class.
    6. Save both the vectoriser and the model together with joblib:
           joblib.dump((vectorizer, clf), "nlp_classifier/model/classifier.pkl")
       The load path must match wherever main.py loads it from.

Usage:
    python -m nlp_classifier.train
"""

# TODO: train and save a model here


def main():
    raise NotImplementedError(
        "train.py is not implemented yet. See the docstring above for the "
        "intended pipeline."
    )


if __name__ == "__main__":
    main()
