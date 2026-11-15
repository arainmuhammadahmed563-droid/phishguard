"""Train the phishing URL classifier, compare models, save best model + metrics.

python train.py                      # Random Forest (default)
python train.py --compare            # RF vs GradientBoosting vs LogisticRegression (5-fold CV), keeps the best F1
"""
import argparse
import json
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, roc_auc_score)
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from features import FEATURE_NAMES, features_vector


def load(path):
    df = pd.read_csv(path)
    if not {"url", "label"}.issubset(df.columns):
        raise SystemExit("CSV must have columns: url,label (1=phishing, 0=legit)")
    df = df.dropna(subset=["url", "label"]).drop_duplicates(subset=["url"])
    # Accept text labels too (e.g. 'bad'/'good', 'phishing'/'benign')
    if df["label"].dtype == object:
        bad = {"bad", "phishing", "malicious", "1"}
        df["label"] = df["label"].astype(str).str.lower().isin(bad).astype(int)
    return df["url"].astype(str).tolist(), df["label"].astype(int).to_numpy()


def candidates():
    return {
        "random_forest": RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=42,
                                                class_weight="balanced"),
        "gradient_boosting": GradientBoostingClassifier(random_state=42),
        "logistic_regression": make_pipeline(StandardScaler(),
                                             LogisticRegression(max_iter=2000, class_weight="balanced")),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/urls.csv")
    ap.add_argument("--model", default="models/model.joblib")
    ap.add_argument("--compare", action="store_true", help="compare 3 models with 5-fold CV")
    a = ap.parse_args()

    urls, y = load(a.data)
    print(f"Loaded {len(urls)} URLs | phishing={int(y.sum())} legit={int((y == 0).sum())}")
    X = np.array([features_vector(u) for u in urls], dtype=float)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    models, cv_scores = candidates(), {}
    name = "random_forest"
    if a.compare:
        print("\nModel comparison (5-fold CV, F1):")
        for n, m in models.items():
            cv_scores[n] = float(cross_val_score(m, Xtr, ytr, cv=5, scoring="f1", n_jobs=-1).mean())
            print(f"  {n:20} {cv_scores[n]:.4f}")
        name = max(cv_scores, key=cv_scores.get)
        print(f"Best: {name}")
    clf = models[name]
    clf.fit(Xtr, ytr)
    pred = clf.predict(Xte)
    proba = clf.predict_proba(Xte)[:, 1]

    acc, f1, auc = accuracy_score(yte, pred), f1_score(yte, pred), roc_auc_score(yte, proba)
    print(f"\nAccuracy: {acc:.4f} | F1: {f1:.4f} | ROC-AUC: {auc:.4f}\n")
    print(classification_report(yte, pred, target_names=["legit", "phishing"], digits=4))
    cm = confusion_matrix(yte, pred)
    print("Confusion matrix [[TN FP] [FN TP]]:\n", cm)

    os.makedirs(os.path.dirname(a.model) or ".", exist_ok=True)
    joblib.dump({"model": clf, "features": FEATURE_NAMES, "name": name}, a.model)

    top = []
    final = clf[-1] if hasattr(clf, "steps") else clf
    if hasattr(final, "feature_importances_"):
        imp = sorted(zip(FEATURE_NAMES, final.feature_importances_), key=lambda t: -t[1])
        top = [(n, round(float(v), 4)) for n, v in imp[:10]]
        print("\nTop features:", ", ".join(f"{n}({v:.3f})" for n, v in top[:5]))
    with open(os.path.join(os.path.dirname(a.model) or ".", "metrics.json"), "w") as f:
        json.dump({"model": name, "accuracy": acc, "f1": f1, "roc_auc": auc,
                   "confusion_matrix": cm.tolist(), "cv_f1": cv_scores, "top_features": top}, f, indent=2)
    print(f"Model saved to {a.model}")


if __name__ == "__main__":
    main()
