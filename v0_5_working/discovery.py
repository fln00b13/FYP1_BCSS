import argparse
import ipaddress
import json
from collections import deque
from urllib.parse import (
    urljoin,
    urlparse,
    urlunparse,
    parse_qsl,
)

import requests
from bs4 import BeautifulSoup


VERSION = "0.5.1"


def is_loopback_url(url):
    """Allow HTTP URLs on localhost or a loopback IP."""
    parsed = urlparse(url)

    if parsed.scheme != "http" or not parsed.hostname:
        return False

    if parsed.username or parsed.password:
        return False

    host = parsed.hostname.lower()

    if host == "localhost":
        return True

    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalize_url(url):
    """Remove fragments and normalize a URL for crawling."""
    parsed = urlparse(url)

    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        "",
    ))


def get_origin(url):
    parsed = urlparse(url)
    return parsed.scheme, parsed.netloc.lower()


def get_query_parameters(url):
    return [
        {"name": name, "value": value}
        for name, value in parse_qsl(
            urlparse(url).query,
            keep_blank_values=True,
        )
    ]


def discover(start_url, seed_paths=None, max_pages=30):
    if not is_loopback_url(start_url):
        raise ValueError(
            "Use a local HTTP URL, such as "
            "http://127.0.0.1:5000/"
        )

    start_url = normalize_url(start_url)
    allowed_origin = get_origin(start_url)

    queue = deque([start_url])
    seed_paths = seed_paths or []

    for path in seed_paths:
        seeded_url = urljoin(start_url, path)

        if (
            is_loopback_url(seeded_url)
            and get_origin(seeded_url) == allowed_origin
        ):
            queue.append(normalize_url(seeded_url))
        else:
            print(f"Skipping out-of-scope seed: {path}")

    visited = set()
    pages = []
    discovered_forms = []
    discovered_links = []
    errors = []

    session = requests.Session()
    session.trust_env = False

    try:
        while queue and len(visited) < max_pages:
            url = queue.popleft()

            if url in visited:
                continue

            parsed_url = urlparse(url)

            # Stay on the exact starting origin.
            if (
                not is_loopback_url(url)
                or get_origin(url) != allowed_origin
            ):
                continue

            visited.add(url)

            try:
                response = session.get(
                    url,
                    timeout=5,
                    allow_redirects=False,
                    headers={"User-Agent": "FPTK-Discovery/0.5.1"},
                )

                if 300 <= response.status_code < 400:
                    errors.append({
                        "url": url,
                        "error": "Redirect not followed",
                    })
                    continue

                response.raise_for_status()

            except requests.RequestException as exc:
                errors.append({
                    "url": url,
                    "error": str(exc),
                })
                continue

            content_type = response.headers.get(
                "Content-Type", ""
            ).lower()

            page_record = {
                "url": url,
                "status_code": response.status_code,
                "content_type": content_type,
                "query_parameters": get_query_parameters(url),
            }

            if "application/json" in content_type:
                try:
                    body = response.json()
                except ValueError:
                    body = None

                page_record["kind"] = "json_endpoint"
                page_record["json_keys"] = (
                    list(body.keys())
                    if isinstance(body, dict)
                    else []
                )
                pages.append(page_record)
                continue

            if "text/html" not in content_type:
                page_record["kind"] = "other"
                pages.append(page_record)
                continue

            page_record["kind"] = "html_page"
            pages.append(page_record)

            soup = BeautifulSoup(response.text, "html.parser")

            # Discover links, but only queue same-origin local URLs.
            for anchor in soup.find_all("a", href=True):
                link_url = normalize_url(
                    urljoin(url, anchor["href"])
                )

                if (
                    is_loopback_url(link_url)
                    and get_origin(link_url) == allowed_origin
                ):
                    discovered_links.append({
                        "source": url,
                        "url": link_url,
                    })

                    if link_url not in visited:
                        queue.append(link_url)

            # Record forms without submitting them.
            for index, form in enumerate(
                soup.find_all("form"), start=1
            ):
                action = normalize_url(
                    urljoin(url, form.get("action") or url)
                )

                if (
                    not is_loopback_url(action)
                    or get_origin(action) != allowed_origin
                ):
                    continue

                method = form.get("method", "get").upper()

                if method not in {"GET", "POST"}:
                    method = "GET"

                fields = []

                for element in form.find_all(
                    ["input", "textarea", "select"]
                ):
                    name = element.get("name")

                    if not name:
                        continue

                    if element.name == "input":
                        field_type = element.get(
                            "type", "text"
                        ).lower()
                    else:
                        field_type = element.name

                    fields.append({
                        "name": name,
                        "type": field_type,
                    })

                discovered_forms.append({
                    "form_id": f"{url}#form-{index}",
                    "page_url": url,
                    "method": method,
                    "action": action,
                    "fields": fields,
                })

    finally:
        session.close()

    return {
        "scanner_version": VERSION,
        "start_url": start_url,
        "pages_visited": len(visited),
        "page_count": len(pages),
        "form_count": len(discovered_forms),
        "link_count": len(discovered_links),
        "pages": pages,
        "forms": discovered_forms,
        "links": discovered_links,
        "errors": errors,
        "limitations": [
            "Only pages reachable through HTML links are crawled automatically.",
            "Unlinked endpoints must be supplied as route seeds.",
            "Forms are recorded but never submitted.",
            "Only GET requests are sent.",
            "Redirects are not followed.",
            "Discovery does not confirm vulnerabilities.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="FPTK v0.5.1 local endpoint discovery"
    )

    parser.add_argument(
        "--url",
        required=True,
        help="Starting local URL",
    )

    parser.add_argument(
        "--paths",
        nargs="*",
        default=[],
        help="Optional known local route paths to inspect",
    )

    parser.add_argument(
        "--max-pages",
        type=int,
        default=30,
        help="Maximum number of unique URLs to visit",
    )

    parser.add_argument(
        "--out",
        default="reports/discovery-report.json",
        help="Output JSON report",
    )

    args = parser.parse_args()

    if args.max_pages < 1:
        parser.error("--max-pages must be at least 1")

    try:
        report = discover(
            args.url,
            seed_paths=args.paths,
            max_pages=args.max_pages,
        )

        with open(args.out, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2)

        print(f"Scanner version: {VERSION}")
        print(f"Pages visited: {report['pages_visited']}")
        print(f"Pages recorded: {report['page_count']}")
        print(f"Forms found: {report['form_count']}")
        print(f"Links found: {report['link_count']}")
        print(f"Errors: {len(report['errors'])}")
        print(f"Saved report: {args.out}")

        for page in report["pages"]:
            print(
                f"- {page['kind']}: {page['url']} "
                f"(HTTP {page['status_code']})"
            )

    except (ValueError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
