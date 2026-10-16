
import argparse
import csv
import json
from pathlib import Path
from urllib.parse import urlparse


VERSION = "0.5.6"

DEFAULT_XSS_REPORT = "reports/xss-analysis-v0.5.4.json"
DEFAULT_SQLI_REPORT = "reports/sqli-analysis-v0.5.5.json"
DEFAULT_JSON_OUT = "reports/evaluation-v0.5.6.json"
DEFAULT_CSV_OUT = "reports/evaluation-details-v0.5.6.csv"


# Reference labels come from the deliberately constructed local lab.
# Do not treat these as independently validated real-world labels.
XSS_REFERENCE_LABELS = {
    "/lab/xss/vulnerable": "vulnerable",
    "/lab/xss/secure": "secure",
    "/lab/xss/vulnerable-attribute": "vulnerable",
    "/lab/xss/secure-attribute": "secure",
    "/lab/xss/no-reflection": "secure",
}

POSITIVE_XSS_CLASSIFICATIONS = {
    "potential_html_injection",
    "raw_reflection_in_attribute",
    "raw_reflection_in_text_context",
    "raw_reflection_context_unknown",
}


def safe_ratio(numerator, denominator):
    if denominator == 0:
        return None
    return numerator / denominator


def calculate_metrics(records):
    tp = fp = tn = fn = 0

    for record in records:
        expected = record["expected"]
        predicted = record["predicted"]

        if expected == "vulnerable" and predicted == "vulnerable":
            tp += 1
        elif expected == "secure" and predicted == "vulnerable":
            fp += 1
        elif expected == "secure" and predicted == "secure":
            tn += 1
        elif expected == "vulnerable" and predicted == "secure":
            fn += 1

    total = tp + fp + tn + fn
    precision = safe_ratio(tp, tp + fp)
    recall = safe_ratio(tp, tp + fn)
    specificity = safe_ratio(tn, tn + fp)
    fpr = safe_ratio(fp, fp + tn)
    accuracy = safe_ratio(tp + tn, total)

    if precision is None or recall is None:
        f1 = None
    elif precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)

    return {
        "total": total,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "false_positive_rate": fpr,
        "accuracy": accuracy,
        "f1_score": f1,
    }


def load_json(path):
    with open(path, "r", encoding="utf-8") as source:
        return json.load(source)


def classify_xss_report(report):
    records = []

    for result in report.get("results", []):
        url = result.get("url", "")
        path = urlparse(url).path
        expected = XSS_REFERENCE_LABELS.get(path)

        if expected is None:
            # Never silently guess an expected label.
            continue

        analysis = result.get("analysis", {})
        classification = analysis.get("classification", "")

        predicted = (
            "vulnerable"
            if classification in POSITIVE_XSS_CLASSIFICATIONS
            else "secure"
        )

        records.append({
            "category": "XSS",
            "url": url,
            "expected": expected,
            "predicted": predicted,
            "classification": classification,
            "correct": expected == predicted,
        })

    return records


def classify_sqli_report(report):
    records = []

    for result in report.get("results", []):
        url = result.get("url", "")
        expected = result.get("expected_lab_label")

        if expected not in {"vulnerable", "secure"}:
            # Do not infer a reference label from the detector output.
            continue

        classification = result.get("classification", "")

        predicted = (
            "vulnerable"
            if classification == "potential_sql_injection"
            else "secure"
        )

        records.append({
            "category": "SQLi",
            "url": url,
            "expected": expected,
            "predicted": predicted,
            "classification": classification,
            "correct": expected == predicted,
        })

    return records


def category_summary(records):
    summary = {}

    for category in ("XSS", "SQLi"):
        subset = [
            record for record in records
            if record["category"] == category
        ]
        summary[category] = calculate_metrics(subset)

    return summary


def main():
    parser = argparse.ArgumentParser(
        description="FPTK v0.5.6 unified detector evaluation"
    )
    parser.add_argument("--xss", default=DEFAULT_XSS_REPORT)
    parser.add_argument("--sqli", default=DEFAULT_SQLI_REPORT)
    parser.add_argument("--out", default=DEFAULT_JSON_OUT)
    parser.add_argument("--csv-out", default=DEFAULT_CSV_OUT)
    args = parser.parse_args()

    try:
        xss_report = load_json(args.xss)
        sqli_report = load_json(args.sqli)
    except (OSError, json.JSONDecodeError) as exc:
        parser.error(f"Could not load input report: {exc}")

    records = (
        classify_xss_report(xss_report)
        + classify_sqli_report(sqli_report)
    )

    if not records:
        parser.error(
            "No labelled results found. Check the report paths and formats."
        )

    overall = calculate_metrics(records)
    by_category = category_summary(records)

    output = {
        "evaluation_version": VERSION,
        "input_reports": {
            "xss": args.xss,
            "sqli": args.sqli,
        },
        "reference_label_source": (
            "Known labels for the project's constructed local training lab"
        ),
        "overall_metrics": overall,
        "category_metrics": by_category,
        "test_details": records,
        "limitations": [
            "This is a small, hand-built local lab evaluation.",
            "Reference labels are not independent real-world validation.",
            "Unknown XSS routes are excluded rather than assigned guessed labels.",
            "A detector classification is a heuristic, not proof of exploitability.",
            "These results are not directly comparable to v0.4 unless the "
            "same cases, labels, and evaluation rules are used.",
        ],
    }

    try:
        json_path = Path(args.out)
        csv_path = Path(args.csv_out)

        json_path.parent.mkdir(parents=True, exist_ok=True)
        csv_path.parent.mkdir(parents=True, exist_ok=True)

        with json_path.open("w", encoding="utf-8") as output_file:
            json.dump(output, output_file, indent=2)

        with csv_path.open(
            "w", newline="", encoding="utf-8-sig"
        ) as output_file:
            columns = [
                "category",
                "url",
                "expected",
                "predicted",
                "classification",
                "correct",
            ]
            writer = csv.DictWriter(
                output_file, fieldnames=columns
            )
            writer.writeheader()
            writer.writerows(records)

    except OSError as exc:
        parser.error(f"Could not save evaluation output: {exc}")

    print(f"Evaluation version: {VERSION}")
    print(f"Labelled tests evaluated: {len(records)}")
    print(f"Saved JSON: {json_path}")
    print(f"Saved CSV: {csv_path}")
    print()

    for name, metrics in [
        ("OVERALL", overall),
        ("XSS", by_category["XSS"]),
        ("SQLi", by_category["SQLi"]),
    ]:
        print(f"[{name}]")
        print(
            f"TP={metrics['true_positives']} "
            f"FP={metrics['false_positives']} "
            f"TN={metrics['true_negatives']} "
            f"FN={metrics['false_negatives']}"
        )

        for metric_name in (
            "precision",
            "recall",
            "specificity",
            "false_positive_rate",
            "accuracy",
            "f1_score",
        ):
            value = metrics[metric_name]
            formatted = (
                "N/A" if value is None else f"{value:.2%}"
            )
            print(f"{metric_name}: {formatted}")

        print()


if __name__ == "__main__":
    main()
