
"""Evaluate FPTK case-level results against independent labels."""

import csv
import json
from pathlib import Path

DATASET = Path("test_cases.csv")
SCAN_REPORT = Path("reports/case-scan-results.json")
REPORT_DIR = Path("reports")


def load_dataset():
    with DATASET.open(newline="", encoding="utf-8-sig") as file:
        rows = list(csv.DictReader(file))

    if not rows:
        raise ValueError("test_cases.csv is empty.")

    labels = {}
    for row in rows:
        case_id = row["case_id"].strip()

        if case_id in labels:
            raise ValueError(f"Duplicate case ID: {case_id}")

        value = row["expected_vulnerable"].strip().lower()
        if value not in {"true", "false"}:
            raise ValueError(f"Invalid expected label for {case_id}")

        row["expected"] = value == "true"
        row["case_id"] = case_id
        labels[case_id] = row

    return labels


def load_predictions():
    with SCAN_REPORT.open(encoding="utf-8") as file:
        report = json.load(file)

    predictions = {}
    for finding in report["findings"]:
        case_id = finding["case_id"]
        if case_id in predictions:
            raise ValueError(f"Duplicate scanner result: {case_id}")
        predictions[case_id] = finding

    return report, predictions


def ratio(numerator, denominator):
    return round(numerator / denominator, 4) if denominator else None


def metrics(rows, prediction_key):
    expected = [row["expected"] for row in rows]
    predicted = [row[prediction_key] for row in rows]

    tp = sum(e and p for e, p in zip(expected, predicted))
    tn = sum(not e and not p for e, p in zip(expected, predicted))
    fp = sum(not e and p for e, p in zip(expected, predicted))
    fn = sum(e and not p for e, p in zip(expected, predicted))

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)

    if precision is not None and recall is not None:
        f1 = (
            round(2 * precision * recall / (precision + recall), 4)
            if precision + recall else 0.0
        )
    else:
        f1 = None

    return {
        "cases": len(rows),
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "precision": precision,
        "recall": recall,
        "specificity": ratio(tn, tn + fp),
        "false_positive_rate": ratio(fp, fp + tn),
        "accuracy": ratio(tp + tn, len(rows)),
        "f1": f1,
    }


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    labels = load_dataset()
    scan_report, predictions = load_predictions()

    missing = sorted(set(labels) - set(predictions))
    extra = sorted(set(predictions) - set(labels))
    if missing or extra:
        raise ValueError(
            f"Dataset/report mismatch. Missing={missing}; extra={extra}"
        )

    rows = []
    for case_id, label in labels.items():
        finding = predictions[case_id]
        rows.append({
            **label,
            "baseline_prediction": finding["baseline_vulnerable"],
            "improved_prediction": finding["improved_vulnerable"],
            "baseline_evidence": finding["baseline_evidence"],
            "improved_evidence": finding["improved_evidence"],
        })

    report = {
        "scanner_version": scan_report.get("scanner_version"),
        "dataset": str(DATASET),
        "case_count": len(rows),
        "warning": (
            "Interpret holdout results as held-out input performance on "
            "this lab, not independent validation on unrelated applications."
        ),
        "baseline": {},
        "improved": {},
    }

    for split_name in ("all", "development", "holdout"):
        subset = (
            rows if split_name == "all"
            else [row for row in rows if row["split"] == split_name]
        )

        report["baseline"][split_name] = metrics(
            subset, "baseline_prediction"
        )
        report["improved"][split_name] = metrics(
            subset, "improved_prediction"
        )

    details_path = REPORT_DIR / "case-evaluation-details.csv"
    fields = [
        "case_id", "route", "category", "probe_type", "split",
        "expected_vulnerable", "baseline_prediction", "improved_prediction",
        "baseline_correct", "improved_correct", "label_rationale",
        "baseline_evidence", "improved_evidence",
    ]

    with details_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        for row in rows:
            expected = row["expected"]
            writer.writerow({
                "case_id": row["case_id"],
                "route": row["route"],
                "category": row["category"],
                "probe_type": row["probe_type"],
                "split": row["split"],
                "expected_vulnerable": expected,
                "baseline_prediction": row["baseline_prediction"],
                "improved_prediction": row["improved_prediction"],
                "baseline_correct": (
                    row["baseline_prediction"] == expected
                ),
                "improved_correct": (
                    row["improved_prediction"] == expected
                ),
                "label_rationale": row["label_rationale"],
                "baseline_evidence": row["baseline_evidence"],
                "improved_evidence": row["improved_evidence"],
            })

    summary_path = REPORT_DIR / "case-evaluation-summary.json"
    summary_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(report, indent=2))
    print(f"\nDetailed results: {details_path}")
    print(f"Summary: {summary_path}")


if __name__ == "__main__":
    main()
