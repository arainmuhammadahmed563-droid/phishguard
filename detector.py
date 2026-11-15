"""Shared prediction logic (CLI + web app): ML model blended with rule-based heuristics."""
import os
from functools import lru_cache

import joblib

from features import TRUSTED_DOMAINS, extract_features, features_vector, get_host, registered_domain

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "model.joblib")
ML_WEIGHT = 0.7            # final = 0.7*ML + 0.3*rules
DEFAULT_THRESHOLD = 0.5
_bundle = None

# (feature-test, weight, human-readable reason)
RULES = [
    (lambda f: f["has_ip"], 0.35, "Host is a raw IP address"),
    (lambda f: f["has_at"], 0.30, "Contains '@' (can hide the real destination)"),
    (lambda f: f["brand_mismatch"], 0.35, "Mentions a well-known brand but is NOT the brand's real domain"),
    (lambda f: f["risky_tld"], 0.15, "Uses a TLD commonly abused for phishing"),
    (lambda f: not f["has_https"], 0.10, "Not using HTTPS"),
    (lambda f: f["num_suspicious_words"] >= 2, 0.15, "Several suspicious keywords (login/verify/secure...)"),
    (lambda f: f["num_subdomains"] >= 3, 0.10, "Too many subdomains"),
    (lambda f: f["has_port"], 0.10, "Non-standard port"),
    (lambda f: f["is_shortener"], 0.10, "URL shortener hides the destination"),
    (lambda f: f["punycode"], 0.20, "Punycode (possible look-alike characters)"),
    (lambda f: f["url_length"] > 90, 0.05, "Very long URL"),
    (lambda f: f["num_hyphens"] >= 3, 0.10, "Many hyphens in URL"),
    (lambda f: f["suspicious_ext"], 0.10, "Path ends in a risky file type (.php/.exe/...)"),
    (lambda f: f["hex_encoded_chars"] >= 3, 0.05, "Heavily URL-encoded characters"),
]


def _load():
    global _bundle
    if _bundle is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError("Model not found. Run: python train.py")
        _bundle = joblib.load(MODEL_PATH)
    return _bundle


def _rules(f: dict):
    hits = [(w, msg) for test, w, msg in RULES if test(f)]
    return min(sum(w for w, _ in hits), 1.0), [m for _, m in hits]


def risk_level(p: float) -> str:
    return "LOW" if p < 0.30 else "MEDIUM" if p < 0.60 else "HIGH"


@lru_cache(maxsize=2048)
def _predict_cached(url: str, threshold: float) -> dict:
    b = _load()
    ml = float(b["model"].predict_proba([features_vector(url)])[0][1])
    f = extract_features(url)
    rule_score, reasons = _rules(f)
    prob = ML_WEIGHT * ml + (1 - ML_WEIGHT) * rule_score

    trusted = (registered_domain(get_host(url)) in TRUSTED_DOMAINS
               and not f["has_ip"] and not f["has_at"] and not f["punycode"])
    if trusted:
        prob = min(prob, 0.05)
        reasons = ["Domain is on the trusted list"]

    return {
        "url": url,
        "label": "PHISHING" if prob >= threshold else "LEGITIMATE",
        "phishing_probability": round(prob, 4),
        "risk_level": risk_level(prob),
        "ml_probability": round(ml, 4),
        "rule_score": round(rule_score, 4),
        "trusted_domain": trusted,
        "reasons": reasons,
    }


def predict(url: str, threshold: float = DEFAULT_THRESHOLD) -> dict:
    return dict(_predict_cached((url or "").strip(), float(threshold)))


def predict_many(urls, threshold: float = DEFAULT_THRESHOLD) -> list:
    return [predict(u, threshold) for u in urls]
