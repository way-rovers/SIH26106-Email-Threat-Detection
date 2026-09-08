"""
nlp_classifier/train.py — train and persist the phishing classifier.

Addresses four issues:
  1. Proper threshold selection (PR curve on val set, FPR ≤ 5% strategy)
  2. Near-duplicate leakage investigation + 5-fold stratified CV
  3. Char n-gram FeatureUnion experiment (word+char vs word-only)
  4. Calibration check (Brier score + calibration curve)

Usage:  python -m nlp_classifier.train
   or:  python nlp_classifier/train.py
"""

import os
import json
import time
import warnings
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import (
    train_test_split,
    StratifiedKFold,
    StratifiedGroupKFold,
)
from sklearn.metrics import (
    classification_report,
    precision_recall_curve,
    f1_score,
    brier_score_loss,
    precision_score,
    recall_score,
    confusion_matrix,
)
from sklearn.pipeline import FeatureUnion
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.frozen import FrozenEstimator

warnings.filterwarnings("ignore", category=UserWarning)

# ── Paths ─────────────────────────────────────────────────────────
DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "cleaned.csv")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "model")
MODEL_PATH = os.path.join(MODEL_DIR, "classifier.pkl")
THRESHOLD_META_PATH = os.path.join(MODEL_DIR, "threshold_meta.json")


# ═══════════════════════════════════════════════════════════════════
#  ISSUE 2 — Near-duplicate detection via SimHash + LSH
#  (no external deps: uses numpy/scipy only)
# ═══════════════════════════════════════════════════════════════════

def _find_near_duplicate_groups(texts, hamming_threshold=10, num_bits=64):
    """
    Detect near-duplicate clusters using SimHash with LSH banding.

    Pipeline:
      1. Lightweight word-unigram TF-IDF (max_features=5 000)
      2. Random hyperplane projection → 64-bit binary signature per doc
      3. LSH banding: 8 bands × 8 bits → candidate pairs
      4. Verify candidates via Hamming distance ≤ threshold → union-find

    Returns
    -------
    groups : np.ndarray[int]  — group id per document (0 … num_groups-1)
    stats  : dict             — counts for the report
    """
    n = len(texts)

    # Step 1 — lightweight TF-IDF for similarity signal
    dup_vec = TfidfVectorizer(
        analyzer="word", max_features=5000, sublinear_tf=True
    )
    tfidf = dup_vec.fit_transform(texts)

    # Step 2 — SimHash via random hyperplane projection
    rng = np.random.RandomState(42)
    hyperplanes = rng.randn(tfidf.shape[1], num_bits).astype(np.float32)
    projections = tfidf.dot(hyperplanes)          # sparse @ dense → dense (n, 64)
    sigs = (np.asarray(projections) > 0).astype(np.uint8)   # (n, 64)

    # Step 3 — LSH banding: 8 bands × 8 bits → bucket key per (doc, band)
    band_size = 8
    num_bands = num_bits // band_size

    # Pack each band into a uint32 for fast hashing
    band_ints = np.zeros((n, num_bands), dtype=np.uint32)
    for b in range(num_bands):
        start = b * band_size
        for bit in range(band_size):
            band_ints[:, b] |= sigs[:, start + bit].astype(np.uint32) << bit

    # Build buckets: (band_index, band_value) → [doc indices]
    from collections import defaultdict
    buckets = defaultdict(list)
    for b in range(num_bands):
        col = band_ints[:, b]
        for i in range(n):
            buckets[(b, int(col[i]))].append(i)

    # Step 4 — Union-Find on candidate pairs
    parent = np.arange(n, dtype=np.int64)

    def find(x):
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:          # path compression
            parent[x], x = root, parent[x]
        return root

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    pairs_checked = 0
    pairs_merged = 0
    for bucket_indices in buckets.values():
        k = len(bucket_indices)
        if k <= 1 or k > 500:             # skip singletons & degenerate buckets
            continue
        for i_pos in range(k):
            for j_pos in range(i_pos + 1, k):
                a, b_idx = bucket_indices[i_pos], bucket_indices[j_pos]
                if find(a) == find(b_idx):
                    continue
                hamming = int(np.sum(sigs[a] != sigs[b_idx]))
                pairs_checked += 1
                if hamming <= hamming_threshold:
                    union(a, b_idx)
                    pairs_merged += 1

    # Relabel groups to contiguous 0 … num_groups-1
    groups_raw = np.array([find(i) for i in range(n)])
    _, groups = np.unique(groups_raw, return_inverse=True)

    group_sizes = np.bincount(groups)
    non_singleton = int(np.sum(group_sizes > 1))
    largest = int(group_sizes.max())

    stats = {
        "pairs_checked": pairs_checked,
        "pairs_merged": pairs_merged,
        "total_groups": len(group_sizes),
        "non_singleton_clusters": non_singleton,
        "largest_cluster": largest,
    }
    return groups, stats


def _check_leakage(groups, idx_a, idx_b):
    """Count groups that span two index sets (= potential leakage)."""
    groups_a = set(groups[idx_a])
    groups_b = set(groups[idx_b])
    overlapping = groups_a & groups_b
    docs_a = sum(1 for i in idx_a if groups[i] in overlapping)
    docs_b = sum(1 for i in idx_b if groups[i] in overlapping)
    return len(overlapping), docs_a, docs_b


# ═══════════════════════════════════════════════════════════════════
#  ISSUE 3 — Synthetic obfuscation for char-n-gram evaluation
# ═══════════════════════════════════════════════════════════════════

_OBFUSC_MAP = {"a": "@", "o": "0", "i": "1", "e": "3", "s": "$", "l": "1"}


def _obfuscate_text(text, rng):
    """Apply basic leet-speak / phishing-style obfuscation to *text*."""
    out = []
    for ch in text:
        if ch.lower() in _OBFUSC_MAP and rng.random() < 0.4:
            out.append(_OBFUSC_MAP[ch.lower()])
        else:
            out.append(ch)
    return "".join(out)


def _generate_obfuscated_set(phishing_texts, n_samples=200, seed=42):
    """Create *n_samples* obfuscated copies of real phishing emails."""
    rng = np.random.RandomState(seed)
    idx = rng.choice(len(phishing_texts), min(n_samples, len(phishing_texts)), replace=False)
    return [_obfuscate_text(phishing_texts.iloc[i], np.random.RandomState(seed + i)) for i in idx]


# ═══════════════════════════════════════════════════════════════════
#  ISSUE 1 — Threshold selection via precision-recall curve
# ═══════════════════════════════════════════════════════════════════

def _select_threshold(y_true, proba_pos, target_fpr=0.05):
    """
    Pick the classification threshold from a precision-recall curve.

    Strategy (security-context rationale):
        False negatives (missing real phishing) are MORE dangerous
        than false positives (flagging legitimate mail).  We therefore
        tolerate up to *target_fpr* false-positive rate and, subject
        to that constraint, maximise recall.

        Concretely: choose the **lowest** threshold whose FPR ≤ target_fpr.
        If nothing qualifies, fall back to the F1-optimal threshold.

    Returns  (threshold, strategy_name, metrics_at_threshold)
    """
    _, _, thresholds = precision_recall_curve(y_true, proba_pos)

    # Evaluate every candidate threshold
    candidates = []
    for t in thresholds:
        preds = (proba_pos >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, preds, labels=[0, 1]).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        candidates.append({
            "threshold": float(t),
            "fpr":       float(fpr),
            "precision": float(precision_score(y_true, preds, zero_division=0)),
            "recall":    float(recall_score(y_true, preds, zero_division=0)),
            "f1":        float(f1_score(y_true, preds)),
        })

    # Primary: lowest threshold with FPR ≤ target
    fpr_valid = [c for c in candidates if c["fpr"] <= target_fpr]

    if fpr_valid:
        # Highest recall among the valid set = lowest threshold
        fpr_valid.sort(key=lambda c: c["recall"], reverse=True)
        best = fpr_valid[0]
        strategy = f"lowest_threshold_fpr_le_{int(target_fpr * 100)}pct"
    else:
        # Fallback: F1-optimal
        candidates.sort(key=lambda c: c["f1"], reverse=True)
        best = candidates[0]
        strategy = "f1_optimal_fallback"

    return best["threshold"], strategy, best


# ═══════════════════════════════════════════════════════════════════
#  Vectorizer factories (keeps the main() body DRY)
# ═══════════════════════════════════════════════════════════════════

def _make_word_vectorizer():
    return TfidfVectorizer(
        analyzer="word", ngram_range=(1, 2),
        max_features=20_000, sublinear_tf=True,
    )


def _make_combined_vectorizer():
    return FeatureUnion([
        ("word", TfidfVectorizer(
            analyzer="word", ngram_range=(1, 2),
            max_features=20_000, sublinear_tf=True,
        )),
        ("char", TfidfVectorizer(
            analyzer="char_wb", ngram_range=(3, 5),
            max_features=30_000, sublinear_tf=True,
        )),
    ])


def _make_classifier():
    return LogisticRegression(C=1.0, max_iter=1000, class_weight="balanced")


# ═══════════════════════════════════════════════════════════════════
#  Main pipeline
# ═══════════════════════════════════════════════════════════════════

def main():
    wall_start = time.time()
    sep = "=" * 64

    print(f"\n{sep}")
    print("  NLP Classifier — Full Training Pipeline")
    print(sep)

    # ── 1. Load data ──────────────────────────────────────────────
    print(f"\n[1/8] Loading data from {DATA_PATH} …")
    t0 = time.time()
    df = pd.read_csv(DATA_PATH)
    X_all = df["body_text"].fillna("").astype(str)
    y_all = df["label"].values
    print(f"  {len(df):,} rows loaded in {time.time()-t0:.1f}s")
    print(f"  Label counts: 0 (legit)={int((y_all==0).sum()):,}  "
          f"1 (phish)={int((y_all==1).sum()):,}")

    # ── 2. Three-way split: train 60 / val 20 / test 20 ──────────
    print(f"\n[2/8] Splitting data …")
    X_trainval, X_test, y_trainval, y_test = train_test_split(
        X_all, y_all, test_size=0.20, random_state=42, stratify=y_all,
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_trainval, y_trainval, test_size=0.25,      # 0.25 × 0.80 = 0.20
        random_state=42, stratify=y_trainval,
    )
    print(f"  Train: {len(X_train):,}   Val: {len(X_val):,}   Test: {len(X_test):,}")

    # ── 3. Near-duplicate detection (Issue 2) ─────────────────────
    print(f"\n[3/8] Near-duplicate detection (SimHash LSH) …")
    t0 = time.time()
    groups_tv, dup_stats = _find_near_duplicate_groups(
        X_trainval.values, hamming_threshold=10, num_bits=64,
    )
    dup_time = time.time() - t0
    print(f"  Completed in {dup_time:.1f}s")
    for k, v in dup_stats.items():
        print(f"    {k}: {v:,}")

    # Simulate old-style random split and check leakage
    naive_tr = np.arange(len(X_train))
    naive_val = np.arange(len(X_train), len(X_trainval))
    overlap_groups, overlap_tr, overlap_val = _check_leakage(
        groups_tv, naive_tr, naive_val,
    )
    has_clusters = dup_stats["non_singleton_clusters"] > 0
    print(f"\n  Leakage check (simulated 75/25 split within trainval):")
    print(f"    Overlapping groups: {overlap_groups:,}")
    print(f"    Leaked docs in train-side: {overlap_tr:,}/{len(naive_tr):,}")
    print(f"    Leaked docs in val-side:   {overlap_val:,}/{len(naive_val):,}")
    if has_clusters:
        print("  -> Near-duplicate clusters found; will use StratifiedGroupKFold.")
    else:
        print("  -> No clusters; will use standard StratifiedKFold.")

    # ── 4. 5-fold cross-validation: word-only vs word+char (Issues 2+3) ─
    print(f"\n[4/8] 5-fold stratified cross-validation …")

    if has_clusters:
        try:
            cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
            cv_splits = list(cv.split(X_trainval, y_trainval, groups=groups_tv))
            cv_name = "StratifiedGroupKFold"
        except ValueError as exc:
            print(f"  StratifiedGroupKFold failed ({exc}); falling back to StratifiedKFold.")
            cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
            cv_splits = list(cv.split(X_trainval, y_trainval))
            cv_name = "StratifiedKFold (fallback)"
    else:
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_splits = list(cv.split(X_trainval, y_trainval))
        cv_name = "StratifiedKFold"

    print(f"  CV strategy: {cv_name}")

    # 4a — word-only CV
    word_f1s = []
    for fold, (tr, te) in enumerate(cv_splits):
        vec = _make_word_vectorizer()
        clf = _make_classifier()
        clf.fit(vec.fit_transform(X_trainval.iloc[tr]), y_trainval[tr])
        preds = clf.predict(vec.transform(X_trainval.iloc[te]))
        f = f1_score(y_trainval[te], preds)
        word_f1s.append(f)
        print(f"    [word]  fold {fold+1}: F1 = {f:.4f}")
    print(f"    [word]  mean = {np.mean(word_f1s):.4f} ± {np.std(word_f1s):.4f}")

    # 4b — word+char CV
    comb_f1s = []
    for fold, (tr, te) in enumerate(cv_splits):
        vec = _make_combined_vectorizer()
        clf = _make_classifier()
        clf.fit(vec.fit_transform(X_trainval.iloc[tr]), y_trainval[tr])
        preds = clf.predict(vec.transform(X_trainval.iloc[te]))
        f = f1_score(y_trainval[te], preds)
        comb_f1s.append(f)
        print(f"    [w+ch]  fold {fold+1}: F1 = {f:.4f}")
    print(f"    [w+ch]  mean = {np.mean(comb_f1s):.4f} ± {np.std(comb_f1s):.4f}")

    # 4c — obfuscation test (Issue 3)
    print(f"\n  Obfuscation test (200 synthetic samples) …")
    phish_tv = X_trainval[y_trainval == 1]
    obf_texts = _generate_obfuscated_set(phish_tv, n_samples=200)

    # Fit both on full trainval for this comparison
    vec_w = _make_word_vectorizer()
    clf_w = _make_classifier()
    clf_w.fit(vec_w.fit_transform(X_trainval), y_trainval)
    obf_recall_word = float(np.mean(clf_w.predict(vec_w.transform(obf_texts)) == 1))

    vec_c = _make_combined_vectorizer()
    clf_c = _make_classifier()
    clf_c.fit(vec_c.fit_transform(X_trainval), y_trainval)
    obf_recall_comb = float(np.mean(clf_c.predict(vec_c.transform(obf_texts)) == 1))

    print(f"    Word-only  obfuscated-phishing recall: {obf_recall_word:.4f}")
    print(f"    Word+Char  obfuscated-phishing recall: {obf_recall_comb:.4f}")

    # Decision
    cv_delta  = np.mean(comb_f1s) - np.mean(word_f1s)
    obf_delta = obf_recall_comb - obf_recall_word
    keep_char = (cv_delta >= 0.002) or (obf_delta >= 0.05)

    char_rationale = (
        f"CV F1 delta: {cv_delta:+.4f} (need ≥+0.002). "
        f"Obfuscation recall delta: {obf_delta:+.4f} (need ≥+0.05). "
        + ("KEPT — meets threshold." if keep_char else "DROPPED — below thresholds.")
    )
    print(f"\n  Decision: {'KEEP' if keep_char else 'DROP'} char n-grams")
    print(f"  {char_rationale}")

    # ── 5. Train final model on train split ───────────────────────
    print(f"\n[5/8] Training final model on train split ({len(X_train):,} rows) …")
    if keep_char:
        final_vec = _make_combined_vectorizer()
        print("  Vectorizer: FeatureUnion(word + char)")
    else:
        final_vec = _make_word_vectorizer()
        print("  Vectorizer: word-only TF-IDF")

    X_train_vec = final_vec.fit_transform(X_train)
    final_clf = _make_classifier()
    final_clf.fit(X_train_vec, y_train)
    print(f"  Feature dimension: {X_train_vec.shape[1]:,}")

    # ── 6. Threshold selection on val set (Issue 1) ───────────────
    print(f"\n[6/8] Threshold selection (PR curve on val set) …")
    X_val_vec = final_vec.transform(X_val)
    val_proba = final_clf.predict_proba(X_val_vec)[:, 1]

    threshold, strategy, thr_metrics = _select_threshold(y_val, val_proba, target_fpr=0.05)
    print(f"  Strategy:  {strategy}")
    print(f"  Threshold: {threshold:.4f}  (was 0.65)")
    print(f"    Precision: {thr_metrics['precision']:.4f}")
    print(f"    Recall:    {thr_metrics['recall']:.4f}")
    print(f"    F1:        {thr_metrics['f1']:.4f}")
    print(f"    FPR:       {thr_metrics['fpr']:.4f}")

    # ── 7. Calibration check (Issue 4) ────────────────────────────
    print(f"\n[7/8] Calibration check …")
    brier = brier_score_loss(y_val, val_proba)
    frac_pos, mean_pred = calibration_curve(y_val, val_proba, n_bins=10, strategy="uniform")
    max_cal_err = float(np.max(np.abs(frac_pos - mean_pred)))

    print(f"  Brier score:           {brier:.4f}  (< 0.05 is well-calibrated)")
    print(f"  Max calibration error: {max_cal_err:.4f}")
    print(f"  {'Predicted':>12}  {'Actual':>12}  {'|Err|':>8}")
    for p, a in zip(mean_pred, frac_pos):
        print(f"  {p:12.3f}  {a:12.3f}  {abs(p-a):8.3f}")

    calibrated = False
    cal_rationale = ""

    if brier > 0.05:
        print(f"\n  Brier {brier:.4f} > 0.05 — trying CalibratedClassifierCV …")
        cal_clf = CalibratedClassifierCV(FrozenEstimator(final_clf), method="isotonic")
        cal_clf.fit(X_val_vec, y_val)

        # Latency comparison
        _probe = final_vec.transform(["test email for timing"])
        n_iter = 500
        t0 = time.perf_counter()
        for _ in range(n_iter):
            final_clf.predict_proba(_probe)
        uncal_ms = (time.perf_counter() - t0) / n_iter * 1000

        t0 = time.perf_counter()
        for _ in range(n_iter):
            cal_clf.predict_proba(_probe)
        cal_ms = (time.perf_counter() - t0) / n_iter * 1000

        cal_proba = cal_clf.predict_proba(X_val_vec)[:, 1]
        cal_brier = brier_score_loss(y_val, cal_proba)
        print(f"  Uncalibrated latency: {uncal_ms:.2f} ms")
        print(f"  Calibrated latency:   {cal_ms:.2f} ms")
        print(f"  Calibrated Brier:     {cal_brier:.4f}")

        if cal_ms <= 22.0 and cal_brier < brier:
            calibrated = True
            final_clf = cal_clf
            brier = cal_brier
            val_proba = cal_proba
            # Re-select threshold with calibrated probabilities
            threshold, strategy, thr_metrics = _select_threshold(y_val, val_proba, target_fpr=0.05)
            cal_rationale = (
                f"Applied isotonic calibration. "
                f"Brier: {brier:.4f} (improved). Latency: {cal_ms:.2f} ms (within 22 ms budget). "
                f"Re-selected threshold: {threshold:.4f}."
            )
            print(f"  ✓ Calibration APPLIED. New threshold: {threshold:.4f}")
        else:
            reason = "latency exceeded 22 ms" if cal_ms > 22.0 else "no Brier improvement"
            cal_rationale = (
                f"NOT applied ({reason}). "
                f"Brier: {brier:.4f} → {cal_brier:.4f}. Latency: {cal_ms:.2f} ms."
            )
            print(f"  ✗ Calibration NOT applied ({reason})")
    else:
        cal_rationale = f"Brier {brier:.4f} ≤ 0.05 — already well-calibrated, no wrapper needed."
        print(f"  ✓ Already well-calibrated.")

    # ── 8. Final evaluation on held-out test set ──────────────────
    print(f"\n[8/8] Held-out test evaluation …")
    X_test_vec = final_vec.transform(X_test)
    test_proba = final_clf.predict_proba(X_test_vec)[:, 1]
    test_preds = (test_proba >= threshold).astype(int)
    test_f1 = f1_score(y_test, test_preds)

    print(f"\n  Threshold: {threshold:.4f}")
    print(classification_report(y_test, test_preds, target_names=["legitimate", "phishing"]))

    # Also report the "optimistic" single-split number (old-style, default 0.5 cutoff)
    opt_preds = final_clf.predict(X_test_vec)      # uses default 0.5 boundary
    opt_f1 = f1_score(y_test, opt_preds)
    print(f"  'Optimistic' single-split F1 (@0.5 cutoff): {opt_f1:.4f}")
    print(f"  Cross-validated F1 (word):     {np.mean(word_f1s):.4f} ± {np.std(word_f1s):.4f}")
    print(f"  Cross-validated F1 (word+ch):  {np.mean(comb_f1s):.4f} ± {np.std(comb_f1s):.4f}")

    # Inference latency (full pipeline: vectorize + predict)
    _sample = "Dear customer, please verify your account by clicking the link below."
    n_lat = 1000
    t0 = time.perf_counter()
    for _ in range(n_lat):
        _v = final_vec.transform([_sample])
        final_clf.predict_proba(_v)
    full_ms = (time.perf_counter() - t0) / n_lat * 1000
    print(f"\n  Inference latency (vec + predict): {full_ms:.2f} ms")

    # ── Save artefacts ────────────────────────────────────────────
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump((final_vec, final_clf), MODEL_PATH)
    print(f"\n  Saved model  → {MODEL_PATH}")

    meta = {
        "threshold": float(threshold),
        "strategy": strategy,
        "val_metrics": {
            "precision": thr_metrics["precision"],
            "recall":    thr_metrics["recall"],
            "f1":        thr_metrics["f1"],
            "fpr":       thr_metrics["fpr"],
            "brier_score": float(brier),
        },
        "cv_metrics": {
            "word_only_mean_f1": float(np.mean(word_f1s)),
            "word_only_std_f1":  float(np.std(word_f1s)),
            "combined_mean_f1":  float(np.mean(comb_f1s)),
            "combined_std_f1":   float(np.std(comb_f1s)),
            "folds":             5,
            "cv_type":           cv_name,
        },
        "test_f1":               float(test_f1),
        "optimistic_f1":         float(opt_f1),
        "char_ngrams_kept":      keep_char,
        "char_ngrams_rationale": char_rationale,
        "obfuscation_recall_word": float(obf_recall_word),
        "obfuscation_recall_combined": float(obf_recall_comb),
        "calibrated":            calibrated,
        "calibration_rationale": cal_rationale,
        "inference_latency_ms":  float(full_ms),
        "leakage_detected":      overlap_groups > 0,
        "near_dup_stats":        dup_stats,
        "trained_at":            datetime.now(timezone.utc).isoformat(),
    }
    with open(THRESHOLD_META_PATH, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"  Saved metadata → {THRESHOLD_META_PATH}")

    # ── Summary ───────────────────────────────────────────────────
    print(f"\n{sep}")
    print("  SUMMARY")
    print(sep)
    print(f"  Threshold:         {threshold:.4f}  (was 0.65, strategy: {strategy})")
    print(f"  CV F1 (word):      {np.mean(word_f1s):.4f} ± {np.std(word_f1s):.4f}")
    print(f"  CV F1 (word+char): {np.mean(comb_f1s):.4f} ± {np.std(comb_f1s):.4f}")
    print(f"  Test F1:           {test_f1:.4f}  (optimistic @0.5: {opt_f1:.4f})")
    print(f"  Brier score:       {brier:.4f}")
    print(f"  Calibrated:        {calibrated}")
    print(f"  Char n-grams:      {'KEPT' if keep_char else 'DROPPED'}")
    print(f"  Leakage:           {'YES' if overlap_groups > 0 else 'NO'} "
          f"({overlap_groups} overlapping groups)")
    print(f"  Inference:         {full_ms:.2f} ms / call")
    print(f"  Wall time:         {time.time()-wall_start:.0f}s")
    print(sep)


if __name__ == "__main__":
    main()