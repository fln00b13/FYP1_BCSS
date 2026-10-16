
"""FPTK v0.4: dataset-driven scanner for the local research lab."""

import argparse
import csv
import html
import ipaddress
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

SQL_ERROR_SIGNATURES = (
    "sqlite error",
    "sqlite3.",
    "unrecognized token",
    "unterminated string",
    "syntax error",
)


def validate_local_target(target):
    parsed = urlparse(target)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError("Use an HTTP loopback URL such as http://127.0.0.1:5000")

    host = parsed.hostname.lower()
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False

    if not loopback:
        raise ValueError("Safety restriction: loopback targets only.")

    return target.rstrip("/")


def load_cases(path):
    with path.open(newline="", encoding="utf-8-sig") as file:
        cases = list(csv.DictReader(file))

    required = {
        "case_id", "route", "category", "probe_type", "probe_value",
        "marker", "expected_vulnerable", "label_rationale", "split",
    }
    if not cases:
        raise ValueError("The test-case dataset is empty.")

    missing = required - set(cases[0])
    if missing:
        raise ValueError(f"Dataset is missing columns: {sorted(missing)}")

    ids = [case["case_id"].strip() for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("case_id values must be unique.")

    for case in cases:
        case["case_id"] = case["case_id"].strip()
        case["route"] = case["route"].strip()
        if not case["route"].startswith("/lab/"):
            raise ValueError(
                f"Case {case['case_id']} has an unexpected route."
            )
        if case["probe_type"] not in {
            "sql_boolean", "html_tag", "attribute", "no_reflection"
        }:
            raise ValueError(
                f"Unsupported probe_type in {case['case_id']}."
            )

    return cases


def fetch(session, url, params):
    started = time.perf_counter()
    response = session.get(
        url,
        params=params,
        timeout=4,
        allow_redirects=False,
    )
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    return response, elapsed_ms


def parse_json(response):
    try:
        value = response.json()
        return value if isinstance(value, dict) else None
    except (ValueError, requests.exceptions.JSONDecodeError):
        return None


def scan_case(session, base_url, case):
    route = case["route"]
    probe_type = case["probe_type"]
    probe = case["probe_value"]
    marker = case["marker"]
    url = base_url + route

    if probe_type == "sql_boolean":
        normal, t1 = fetch(session, url, {"term": "alice"})
        tested, t2 = fetch(session, url, {"term": probe})

        # Baseline: intentionally broad keyword rule.
        keywords = ("database", "sql", "error")
        baseline = any(
            word in (normal.text + " " + tested.text).lower()
            for word in keywords
        )

        normal_json = parse_json(normal)
        tested_json = parse_json(tested)
        normal_matches = (
            normal_json.get("matches")
            if normal_json and isinstance(normal_json.get("matches"), list)
            else None
        )
        tested_matches = (
            tested_json.get("matches")
            if tested_json and isinstance(tested_json.get("matches"), list)
            else None
        )

        behaviour_change = (
            normal_matches is not None
            and tested_matches is not None
            and set(normal_matches).issubset(set(tested_matches))
            and len(tested_matches) > len(normal_matches)
        )
        database_error = any(
            signature in tested.text.lower()
            for signature in SQL_ERROR_SIGNATURES
        )
        improved = behaviour_change or database_error

        baseline_evidence = (
            "Broad SQL/database/error keyword found"
            if baseline else "No broad keyword found"
        )
        improved_evidence = (
            f"match_set_expanded={behaviour_change}; "
            f"database_error_signature={database_error}"
        )
        elapsed_ms = round(t1 + t2, 2)

    else:
        response, elapsed_ms = fetch(session, url, {"term": probe})
        body = response.text
        body_lower = body.lower()
        baseline = bool(marker) and marker.lower() in body_lower

        if probe_type == "html_tag":
            escaped_probe = html.escape(probe, quote=True)
            raw_present = probe in body
            escaped_present = escaped_probe.lower() in body_lower
            improved = raw_present and not escaped_present
            improved_evidence = (
                f"raw_input_present={raw_present}; "
                f"escaped_input_present={escaped_present}"
            )

        elif probe_type == "attribute":
            active_attribute = 'data-fptk="probe"' in body
            improved = active_attribute
            improved_evidence = (
                f"active_injected_attribute={active_attribute}"
            )

        else:  # no_reflection
            improved = False
            improved_evidence = (
                f"marker_reflected={marker.lower() in body_lower}"
            )

        baseline_evidence = (
            "Input marker appears in response"
            if baseline else "Input marker not found in response"
        )

    return {
        "case_id": case["case_id"],
        "route": route,
        "category": case["category"],
        "probe_type": probe_type,
        "split": case["split"],
        "baseline_vulnerable": bool(baseline),
        "improved_vulnerable": bool(improved),
        "baseline_evidence": baseline_evidence,
        "improved_evidence": improved_evidence,
        "response_time_ms": elapsed_ms,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Run FPTK test cases against the local lab only."
    )
    parser.add_argument(
        "--target", default="http://127.0.0.1:5000"
    )
    parser.add_argument(
        "--dataset", default="test_cases.csv"
    )
    parser.add_argument(
        "--out", default="reports/case-scan-results.json"
    )
    args = parser.parse_args()

    try:
        base_url = validate_local_target(args.target)
        cases = load_cases(Path(args.dataset))
        findings = []

        with requests.Session() as session:
            session.headers.update({"User-Agent": "FPTK-Research/0.4"})
            for case in cases:
                findings.append(scan_case(session, base_url, case))

    except (ValueError, OSError, requests.RequestException) as exc:
        parser.error(str(exc))

    output = {
        "scanner_version": "0.4",
        "target": base_url,
        "dataset": args.dataset,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case_count": len(findings),
        "findings": findings,
        "limitations": [
            "Research prototype for the local training lab.",
            "Heuristic detections do not prove general exploitability.",
            "Holdout cases share the same application and route implementations.",
        ],
    }

    output_path = Path(args.out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")

    print(f"Scanner version: {output['scanner_version']}")
    print(f"Cases scanned: {output['case_count']}")
    print(f"Saved: {output_path}")
    for finding in findings:
        print(
            f"{finding['case_id']} {finding['route']}: "
            f"baseline={finding['baseline_vulnerable']}, "
            f"improved={finding['improved_vulnerable']}"
        )


if __name__ == "__main__":
    main()
