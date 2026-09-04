"""
nlp_classifier/train.py — train and persist the phishing classifier.
Usage: python nlp_classifier/train.py
"""

import pandas as pd
import joblib
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

DATA_PATH = "nlp_classifier/data/cleaned.csv"
MODEL_PATH = "nlp_classifier/model/classifier.pkl"


def main():
    df = pd.read_csv(DATA_PATH)
    X = df["body_text"]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2), max_features=20000, sublinear_tf=True
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    clf = LogisticRegression(C=1.0, max_iter=1000, class_weight="balanced")
    clf.fit(X_train_vec, y_train)

    preds = clf.predict(X_test_vec)
    print(classification_report(y_test, preds, target_names=["legitimate", "phishing"]))

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump((vectorizer, clf), MODEL_PATH)
    print("Saved model to", MODEL_PATH)


if __name__ == "__main__":
    main()