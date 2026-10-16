
import argparse
import ipaddress
import json
from urllib.parse import urlparse

import requests


VERSION = "0.5.5"
BASE_URL = "http://127.0.0.1:5000"

# Fixed, local training-lab routes only.
ROUTES = [
    {
        "path": "/lab/sqli/vulnerable",
        "type": "equality",
        "expected_label": "vulnerable",
    },
    {
        "path": "/lab/sqli/secure",
        "type": "equality",
        "expected_label": "secure",
    },
    {
        "path": "/lab/sqli/vulnerable-prefix",
        "type": "prefix",
        "expected_label": "vulnerable",
    },
    {
        "path": "/lab/sqli/secure-prefix",
        "type": "prefix",
        "expected_label": "secure",
    },
]

NO_MATCH_TERM = "fptk_no_match_7c91"


def is_loopback_url(url):
    parsed = urlparse(url)

    if parsed.scheme != "http" or not parsed.hostname:
        return False
    if parsed.username or parsed.password:
        return False
    if parsed.hostname.lower() == "localhost":
        return True

    try:
        return ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        return False


def request_json(session, url, term):
    if not is_loopback_url(url):
        raise ValueError(f"Out-of-scope URL rejected: {url}")

    response = session.get(
        url,
        params={"term": term},
        timeout=5,
        allow_redirects=False,
    )

    if 300 <= response.status_code < 400:
        raise ValueError("Redirect detected; not followed.")

    try:
        data = response.json()
    except ValueError:
        data = {"non_json_response": True}

    return {
        "status_code": response.status_code,
        "data": data,
        "elapsed_ms": round(response.elapsed.total_seconds() * 1000, 2),
    }


def match_count(result):
    matches = result["data"].get("matches")

    if isinstance(matches, list):
        return len(matches)

    return None


def has_sql_error(result):
    data = result["data"]

    if result["status_code"] >= 500:
        return True

    error = data.get("error", "")
    if not isinstance(error, str):
        return False

    indicators = (
        "sqlite",
        "sql syntax",
        "unterminated string",
        "no such column",
        "near ",
        "operationalerror",
    )

    return any(item in error.lower() for item in indicators)


def test_route(session, route):
    url = BASE_URL + route["path"]
    route_type = route["type"]

    baseline = request_json(session, url, NO_MATCH_TERM)

    # A quote is used to observe whether input causes a SQL error.
    quote_test = request_json(session, url, "'")

    # Controlled Boolean condition, for the local lab only.
    if route_type == "equality":
        boolean_term = "' OR '1'='1' -- "
    else:
        boolean_term = "%' OR '1'='1' -- "

    boolean_test = request_json(session, url, boolean_term)

    baseline_count = match_count(baseline)
    boolean_count = match_count(boolean_test)

    quote_error = has_sql_error(quote_test)
    boolean_difference = (
        baseline_count is not None
        and boolean_count is not None
        and boolean_count > baseline_count
    )

    signals = []

    if quote_error:
        signals.append("sql_error_after_quote_input")

    if boolean_difference:
        signals.append("unexpected_match_count_increase")

    # These are heuristic observations, not definitive proof.
    if quote_error or boolean_difference:
        classification = "potential_sql_injection"
    else:
        classification = "no_sql_injection_signal_observed"

    return {
        "url": url,
        "route_type": route_type,
        "expected_lab_label": route["expected_label"],
        "baseline": {
            "status_code": baseline["status_code"],
            "match_count": baseline_count,
        },
        "quote_test": {
            "status_code": quote_test["status_code"],
            "sql_error_signal": quote_error,
        },
        "boolean_test": {
            "status_code": boolean_test["status_code"],
            "match_count": boolean_count,
        },
        "signals": signals,
        "boolean_response_difference": boolean_difference,
        "classification": classification,
        "confirmed_vulnerability": False,
        "note": (
            "Heuristic result only. Response differences and SQL "
            "errors can have other causes; review against the known "
            "lab implementation and labelled test cases."
        ),
    }


def main():
    parser = argparse.ArgumentParser(
        description="FPTK local SQLite SQL injection detector"
    )
    parser.add_argument(
        "--out",
        default="reports/sqli-analysis-v0.5.5.json",
    )
    args = parser.parse_args()

    if not is_loopback_url(BASE_URL):
        parser.error("Configured target is not a loopback URL.")

    session = requests.Session()
    session.trust_env = False

    results = []
    errors = []

    try:
        for route in ROUTES:
            try:
                results.append(test_route(session, route))
            except (ValueError, requests.RequestException) as exc:
                errors.append({
                    "path": route["path"],
                    "error": str(exc),
                })
    finally:
        session.close()

    report = {
        "scanner_version": VERSION,
        "target": BASE_URL,
        "tests_run": len(results),
        "errors": errors,
        "results": results,
        "limitations": [
            "Only fixed loopback training-lab routes are tested.",
            "The detector uses heuristic response comparisons.",
            "A missing signal does not prove a route is secure.",
            "Expected lab labels are not independent ground truth.",
            "No JavaScript or external targets are involved.",
        ],
    }

    try:
        with open(args.out, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2)
    except OSError as exc:
        parser.error(f"Could not save report: {exc}")

    print(f"Scanner version: {VERSION}")
    print(f"Routes tested: {len(results)}")
    print(f"Errors: {len(errors)}")
    print(f"Saved report: {args.out}")

    for result in results:
        print(
            f"{result['url']} | "
            f"{result['classification']} | "
            f"signals={result['signals']}"
        )

    for error in errors:
        print(f"ERROR: {error['path']} | {error['error']}")


if __name__ == "__main__":
    main()
