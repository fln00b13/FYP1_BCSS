
import argparse
import html
import ipaddress
import json
import time
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup


VERSION = "0.5.4"
MARKER = "<FPTK_XSS_A91>"
TAG_NAME = "fptk_xss_a91"


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


def set_query_parameter(url, parameter, value):
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    updated = []
    replaced = False

    for name, old_value in pairs:
        if name == parameter and not replaced:
            updated.append((name, value))
            replaced = True
        else:
            updated.append((name, old_value))

    if not replaced:
        updated.append((parameter, value))

    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        urlencode(updated),
        "",
    ))


def fetch(session, url):
    if not is_loopback_url(url):
        raise ValueError(f"Out-of-scope URL rejected: {url}")

    started = time.perf_counter()
    response = session.get(
        url,
        timeout=5,
        allow_redirects=False,
        headers={"User-Agent": f"FPTK-XSS/{VERSION}"},
    )
    elapsed_ms = round(
        (time.perf_counter() - started) * 1000, 2
    )

    if 300 <= response.status_code < 400:
        raise ValueError("Redirect detected; not followed.")

    return {
        "status_code": response.status_code,
        "content_type": response.headers.get("Content-Type", ""),
        "body": response.text,
        "body_length": len(response.text),
        "elapsed_ms": elapsed_ms,
    }


def analyze_reflection(body, marker=MARKER):
    escaped_marker = html.escape(marker, quote=True)

    raw_reflected = marker in body
    escaped_reflected = escaped_marker in body

    soup = BeautifulSoup(body, "html.parser")

    parsed_as_tag = (
        raw_reflected and soup.find(TAG_NAME) is not None
    )

    attribute_contexts = []
    for element in soup.find_all(True):
        for attribute, value in element.attrs.items():
            values = value if isinstance(value, list) else [value]

            if any(
                isinstance(item, str) and marker in item
                for item in values
            ):
                attribute_contexts.append({
                    "element": element.name,
                    "attribute": attribute,
                })

    text_contexts = []
    for text_node in soup.find_all(string=True):
        if marker in str(text_node):
            parent = text_node.parent
            text_contexts.append({
                "parent_element": (
                    parent.name if parent else None
                )
            })

    if parsed_as_tag:
        classification = "potential_html_injection"
        explanation = (
            "The marker was parsed as an HTML element. "
            "This suggests raw HTML interpretation, but does "
            "not establish executable XSS."
        )
    elif raw_reflected and attribute_contexts:
        classification = "raw_reflection_in_attribute"
        explanation = (
            "The raw marker occurs in one or more HTML attribute "
            "values. Risk depends on the attribute and its context."
        )
    elif raw_reflected and text_contexts:
        classification = "raw_reflection_in_text_context"
        explanation = (
            "The marker occurs in parsed text content. Inspect "
            "the original response and browser parsing context."
        )
    elif raw_reflected:
        classification = "raw_reflection_context_unknown"
        explanation = (
            "The marker is present verbatim, but the analyzer "
            "could not confidently identify its DOM context."
        )
    elif escaped_reflected:
        classification = "escaped_reflection"
        explanation = (
            "The escaped marker appears in the response, "
            "consistent with HTML output encoding."
        )
    else:
        classification = "not_reflected"
        explanation = (
            "Neither the raw marker nor its escaped form "
            "was found in the response."
        )

    return {
        "raw_reflected": raw_reflected,
        "escaped_reflected": escaped_reflected,
        "parsed_as_html_tag": parsed_as_tag,
        "attribute_contexts": attribute_contexts,
        "text_contexts": text_contexts,
        "classification": classification,
        "explanation": explanation,
        "confirmed_vulnerability": False,
    }


def test_parameter(session, url, parameter):
    baseline = fetch(session, url)
    test_url = set_query_parameter(url, parameter, MARKER)
    tested = fetch(session, test_url)

    return {
        "url": url,
        "parameter": parameter,
        "baseline": {
            "status_code": baseline["status_code"],
            "content_type": baseline["content_type"],
            "body_length": baseline["body_length"],
            "elapsed_ms": baseline["elapsed_ms"],
        },
        "test": {
            "status_code": tested["status_code"],
            "content_type": tested["content_type"],
            "body_length": tested["body_length"],
            "elapsed_ms": tested["elapsed_ms"],
        },
        "analysis": analyze_reflection(tested["body"]),
        "evidence": {
            "status_changed": (
                baseline["status_code"] != tested["status_code"]
            ),
            "body_length_changed": (
                baseline["body_length"] != tested["body_length"]
            ),
        },
        "note": (
            "Reflection analysis only. JavaScript execution and "
            "browser-level exploitability are not tested."
        ),
    }


def main():
    parser = argparse.ArgumentParser(
        description="FPTK local XSS context analysis"
    )
    parser.add_argument(
        "--report",
        default="reports/discovery-report.json",
    )
    parser.add_argument(
        "--out",
        default="reports/xss-analysis-v0.5.4.json",
    )
    args = parser.parse_args()

    try:
        with open(args.report, encoding="utf-8") as source:
            discovery = json.load(source)
    except (OSError, json.JSONDecodeError) as exc:
        parser.error(f"Cannot read discovery report: {exc}")

    results = []
    errors = []
    seen = set()

    session = requests.Session()
    session.trust_env = False

    try:
        for page in discovery.get("pages", []):
            url = page.get("url", "")
            path = urlparse(url).path

            if not path.startswith("/lab/xss/"):
                continue
            if not is_loopback_url(url):
                errors.append({
                    "url": url,
                    "error": "Target is not loopback",
                })
                continue

            parameters = page.get("query_parameters", [])
            names = list(dict.fromkeys(
                item["name"]
                for item in parameters
                if item.get("name")
            ))

            for parameter in names:
                key = (url, parameter)
                if key in seen:
                    continue
                seen.add(key)

                try:
                    results.append(
                        test_parameter(session, url, parameter)
                    )
                except (ValueError, requests.RequestException) as exc:
                    errors.append({
                        "url": url,
                        "parameter": parameter,
                        "error": str(exc),
                    })
    finally:
        session.close()

    report = {
        "scanner_version": VERSION,
        "start_url": discovery.get("start_url"),
        "tests_run": len(results),
        "errors": errors,
        "results": results,
        "limitations": [
            "Only discovered query parameters on /lab/xss/ routes are tested.",
            "The marker is a harmless custom HTML tag.",
            "Reflection classifications are not confirmed vulnerabilities.",
            "JavaScript execution and browser behavior are not tested.",
            "Only loopback HTTP targets are allowed.",
        ],
    }

    try:
        with open(args.out, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2)
    except OSError as exc:
        parser.error(f"Cannot save report: {exc}")

    print(f"Scanner version: {VERSION}")
    print(f"Tests run: {len(results)}")
    print(f"Errors: {len(errors)}")
    print(f"Saved report: {args.out}")

    for result in results:
        analysis = result["analysis"]
        print(
            f"{result['url']} | {result['parameter']} | "
            f"{analysis['classification']} | "
            f"attributes={len(analysis['attribute_contexts'])} | "
            f"text_nodes={len(analysis['text_contexts'])}"
        )


if __name__ == "__main__":
    main()
