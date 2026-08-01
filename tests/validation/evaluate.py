"""Accuracy evaluation harness over the labeled validation corpus.

Computes precision, recall, F1, accuracy, and a confusion matrix treating
High/Critical as the positive (malicious) class.
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from dataclasses import asdict
from typing import Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from header_analysis import analyze_headers
from scoring import score_message
from url_analysis import analyze_urls

from tests.validation.corpus import ValidationCase, build_validation_corpus

POSITIVE = {"High", "Critical"}


def _predict(case: ValidationCase) -> dict[str, Any]:
    hv = analyze_headers(case.parsed)
    uv = analyze_urls(case.parsed)
    verdict = score_message(
        case.parsed, case.auth, case.routing,
        header_verdict=hv, url_verdict=uv,
    )
    predicted_positive = verdict.risk_level in POSITIVE
    actual_positive = case.label == "malicious"

    if predicted_positive and actual_positive:
        outcome = "TP"
    elif predicted_positive and not actual_positive:
        outcome = "FP"
    elif not predicted_positive and actual_positive:
        outcome = "FN"
    else:
        outcome = "TN"

    return {
        "id": case.id,
        "label": case.label,
        "category": case.category,
        "risk_level": verdict.risk_level,
        "display_score": verdict.display_score,
        "raw_score": verdict.total_score,
        "trusted_sender": verdict.trusted_sender,
        "classification_reason": verdict.classification_reason,
        "strong_signal_count": verdict.strong_signal_count,
        "weak_signal_count": verdict.weak_signal_count,
        "top_signals": [
            {
                "indicator": s.indicator,
                "weight": s.weight,
                "strength": s.strength,
                "contribution_pct": s.contribution_pct,
                "family": s.family,
            }
            for s in sorted(verdict.signals, key=lambda x: -x.weight)[:8]
            if s.weight > 0
        ],
        "outcome": outcome,
    }


def evaluate(corpus: list[ValidationCase] | None = None) -> dict[str, Any]:
    cases = corpus or build_validation_corpus()
    rows = [_predict(c) for c in cases]
    counts = Counter(r["outcome"] for r in rows)
    tp, fp, tn, fn = counts["TP"], counts["FP"], counts["TN"], counts["FN"]

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    accuracy = (tp + tn) / len(rows) if rows else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "metrics": {
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "accuracy": round(accuracy, 4),
            "f1": round(f1, 4),
            "n_benign": sum(1 for c in cases if c.label == "benign"),
            "n_malicious": sum(1 for c in cases if c.label == "malicious"),
            "n_total": len(cases),
        },
        "confusion_matrix": {
            "labels": ["actual_malicious", "actual_benign"],
            "predicted_malicious": [tp, fp],
            "predicted_benign": [fn, tn],
        },
        "cases": rows,
    }


def main() -> None:
    report = evaluate()
    print(json.dumps(report["metrics"], indent=2))
    print("\nConfusion matrix (rows=actual malicious/benign, cols=pred malicious/benign):")
    cm = report["confusion_matrix"]
    print(f"  TP={cm['predicted_malicious'][0]}  FN={cm['predicted_benign'][0]}")
    print(f"  FP={cm['predicted_malicious'][1]}  TN={cm['predicted_benign'][1]}")
    print("\nPer-case outcomes:")
    for row in report["cases"]:
        print(
            f"  {row['outcome']:>2} | {row['risk_level']:8} {row['display_score']:3} | "
            f"{row['id']} ({row['category']})"
        )


if __name__ == "__main__":
    main()
