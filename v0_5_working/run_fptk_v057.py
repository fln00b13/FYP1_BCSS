
import argparse
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse


VERSION = "0.5.7"
BASE_URL = "http://127.0.0.1:5000"

PROJECT_DIR = Path(__file__).resolve().parent
REPORT_DIR = PROJECT_DIR / "reports"

DISCOVERY_SCRIPT = PROJECT_DIR / "discovery.py"
XSS_SCRIPT = PROJECT_DIR / "probe.py"
SQLI_SCRIPT = PROJECT_DIR / "sqli_detector.py"
EVALUATION_SCRIPT = PROJECT_DIR / "evaluate_v056.py"

DISCOVERY_OUT = REPORT_DIR / "discovery-report-v0.5.7.json"
XSS_OUT = REPORT_DIR / "xss-analysis-v0.5.7.json"
SQLI_OUT = REPORT_DIR / "sqli-analysis-v0.5.7.json"
EVALUATION_OUT = REPORT_DIR / "evaluation-v0.5.7.json"
EVALUATION_CSV = REPORT_DIR / "evaluation-details-v0.5.7.csv"
FINAL_OUT = REPORT_DIR / "fptk-report-v0.5.7.json"

# Seed known local lab routes so discovery can find routes that
# are not linked from the landing page.
SEED_PATHS = [
    "/lab/xss/vulnerable?term=hello",
    "/lab/xss/secure?term=hello",
    "/lab/xss/vulnerable-attribute?term=hello",
    "/lab/xss/secure-attribute?term=hello",
    "/lab/xss/no-reflection?term=hello",
    "/lab/sqli/vulnerable?term=alice",
    "/lab/sqli/secure?term=alice",
    "/lab/sqli/vulnerable-prefix?term=alice",
    "/lab/sqli/secure-prefix?term=alice",
]

XSS_POSITIVE_CLASSIFICATIONS = {
    "potential_html_injection",
    "raw_reflection_in_attribute",
    "raw_reflection_in_text_context",
    "raw_reflection_context_unknown",
}


def load_json(path):
    with path.open("r", encoding="utf-8") as source:
        return json.load(source)


def run_stage(name, command):
    print(f"\n{'=' * 60}")
    print(f"STAGE: {name}")
    print(f"{'=' * 60}")

    result = subprocess.run(
        command,
        cwd=PROJECT_DIR,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"{name} failed with exit code {result.returncode}. "
            "Fix the error above before rerunning."
        )


def validate_configuration(start_url):
    parsed = urlparse(start_url)

    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or parsed.username
        or parsed.password
    ):
        raise ValueError(
            "This prototype only accepts a local HTTP URL."
        )

    # The existing SQLi detector uses a fixed target. Require
    # the same origin so the integrated report isn't misleading.
    origin = f"{parsed.scheme}://{parsed.netloc}".lower()

    if origin != BASE_URL:
        raise ValueError(
            f"The existing SQLi detector targets {BASE_URL}. "
            f"Use a start URL on that exact origin for this version."
        )


def build_findings(xss_report, sqli_report):
    findings = []

    for result in xss_report.get("results", []):
        analysis = result.get("analysis", {})
        classification = analysis.get("classification", "")

        if classification in XSS_POSITIVE_CLASSIFICATIONS:
            findings.append({
                "category": "XSS",
                "url": result.get("url"),
                "parameter": result.get("parameter"),
                "classification": classification,
                "status": "potential_finding",
                "confirmed_vulnerability": False,
                "evidence": analysis,
                "note": (
                    "HTML reflection/context signal only; "
                    "JavaScript execution was not tested."
                ),
            })

    for result in sqli_report.get("results", []):
        classification = result.get("classification", "")

        if classification == "potential_sql_injection":
            findings.append({
                "category": "SQLi",
                "url": result.get("url"),
                "classification": classification,
                "status": "potential_finding",
                "confirmed_vulnerability": False,
                "evidence": {
                    "signals": result.get("signals", []),
                    "baseline": result.get("baseline", {}),
                    "quote_test": result.get("quote_test", {}),
                    "boolean_test": result.get("boolean_test", {}),
                },
                "note": (
                    "Heuristic SQL error/response-difference signal; "
                    "review the evidence before drawing conclusions."
                ),
            })

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="FPTK v0.5.7 integrated local prototype"
    )
    parser.add_argument(
        "--url",
        default=f"{BASE_URL}/",
        help="Starting URL for the local training lab",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=30,
        help="Maximum number of URLs for discovery",
    )
    args = parser.parse_args()

    if args.max_pages < 1:
        parser.error("--max-pages must be at least 1")

    try:
        validate_configuration(args.url)
    except ValueError as exc:
        parser.error(str(exc))

    required_scripts = [
        DISCOVERY_SCRIPT,
        XSS_SCRIPT,
        SQLI_SCRIPT,
        EVALUATION_SCRIPT,
    ]

    missing = [str(path) for path in required_scripts if not path.is_file()]
    if missing:
        parser.error(
            "Required script(s) missing:\n" + "\n".join(missing)
        )

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    try:
        # 1. Discover local routes and query parameters.
        run_stage(
            "Endpoint discovery",
            [
                sys.executable,
                str(DISCOVERY_SCRIPT),
                "--url", args.url,
                "--paths", *SEED_PATHS,
                "--max-pages", str(args.max_pages),
                "--out", str(DISCOVERY_OUT),
            ],
        )

        # 2. Analyze discovered XSS query parameters.
        run_stage(
            "XSS reflection analysis",
            [
                sys.executable,
                str(XSS_SCRIPT),
                "--report", str(DISCOVERY_OUT),
                "--out", str(XSS_OUT),
            ],
        )

        # 3. Run the existing fixed-route SQLi lab detector.
        run_stage(
            "SQL injection analysis",
            [
                sys.executable,
                str(SQLI_SCRIPT),
                "--out", str(SQLI_OUT),
            ],
        )

        # 4. Evaluate predictions against the lab's reference labels.
        run_stage(
            "Labelled evaluation",
            [
                sys.executable,
                str(EVALUATION_SCRIPT),
                "--xss", str(XSS_OUT),
                "--sqli", str(SQLI_OUT),
                "--out", str(EVALUATION_OUT),
                "--csv-out", str(EVALUATION_CSV),
            ],
        )

        discovery = load_json(DISCOVERY_OUT)
        xss = load_json(XSS_OUT)
        sqli = load_json(SQLI_OUT)
        evaluation = load_json(EVALUATION_OUT)

        findings = build_findings(xss, sqli)

        final_report = {
            "tool": "FPTK",
            "version": VERSION,
            "start_url": args.url,
            "scope": {
                "type": "local training lab",
                "allowed_origin": BASE_URL,
                "external_targets_scanned": False,
            },
            "summary": {
                "discovered_pages": discovery.get("page_count", 0),
                "discovered_forms": discovery.get("form_count", 0),
                "xss_tests_run": xss.get("tests_run", 0),
                "sqli_tests_run": sqli.get("tests_run", 0),
                "potential_findings": len(findings),
                "confirmed_vulnerabilities": 0,
                "discovery_errors": len(discovery.get("errors", [])),
                "xss_errors": len(xss.get("errors", [])),
                "sqli_errors": len(sqli.get("errors", [])),
            },
            "findings": findings,
            "evaluation": evaluation,
            "stage_reports": {
                "discovery": DISCOVERY_OUT.name,
                "xss": XSS_OUT.name,
                "sqli": SQLI_OUT.name,
                "evaluation_json": EVALUATION_OUT.name,
                "evaluation_csv": EVALUATION_CSV.name,
            },
            "stage_results": {
                "discovery": discovery,
                "xss": xss,
                "sqli": sqli,
            },
            "limitations": [
                "This prototype is designed for the project's local lab.",
                "SQLi checks use fixed lab routes rather than discovered arbitrary endpoints.",
                "XSS checks use a harmless custom HTML tag and do not execute JavaScript.",
                "Potential findings are heuristic signals, not confirmed vulnerabilities.",
                "Evaluation labels describe the constructed lab and are not independent real-world validation.",
                "GET requests can still have side effects on poorly designed applications.",
                "A completed stage with request errors does not mean every route was tested.",
            ],
        }

        with FINAL_OUT.open("w", encoding="utf-8") as output:
            json.dump(final_report, output, indent=2)

    except (OSError, json.JSONDecodeError, RuntimeError) as exc:
        parser.error(str(exc))

    summary = final_report["summary"]

    print(f"\n{'=' * 60}")
    print(f"FPTK INTEGRATED PROTOTYPE v{VERSION}")
    print(f"{'=' * 60}")
    print(f"Discovered pages: {summary['discovered_pages']}")
    print(f"XSS tests: {summary['xss_tests_run']}")
    print(f"SQLi tests: {summary['sqli_tests_run']}")
    print(f"Potential findings: {summary['potential_findings']}")
    print(f"Confirmed vulnerabilities: 0")
    print(
        "Request/stage errors: "
        f"{summary['discovery_errors'] + summary['xss_errors'] + summary['sqli_errors']}"
    )
    print(f"Unified report: {FINAL_OUT}")
    print(f"Evaluation JSON: {EVALUATION_OUT}")
    print(f"Evaluation CSV: {EVALUATION_CSV}")
    print("\nIntegration run completed.")


if __name__ == "__main__":
    main()
