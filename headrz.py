#!/usr/bin/env python3

import argparse
import csv
import urllib3
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import requests


DEFAULT_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",   # legacy
    "Feature-Policy",     # legacy
]


def candidate_urls(target):
    """Return URLs to try for a target."""
    target = target.strip()

    if target.startswith(("http://", "https://")):
        return [target]

    try:
        parsed = urlsplit(f"//{target}")
        port = parsed.port
    except ValueError:
        return []

    # Known HTTPS ports
    if port in (443, 8443):
        return [f"https://{target}"]

    # Known HTTP ports
    if port in (80, 8080):
        return [f"http://{target}"]

    # Prefer HTTPS for everything else
    return [
        f"https://{target}",
        f"http://{target}",
    ]


def check_target(target, headers, timeout, verify):
    urls = candidate_urls(target)

    if not urls:
        return {
            "Target": target,
            "URL": "",
            "Status": "",
            "Error": "Invalid target",
            **{header: "" for header in headers},
        }

    errors = []

    for url in urls:
        try:
            response = requests.get(
                url,
                timeout=timeout,
                verify=verify,
                allow_redirects=True,
                headers={"User-Agent": "headrz/2.0"},
            )

            result = {
                "Target": target,
                "URL": response.url,
                "Status": response.status_code,
                "Error": "",
            }

            for header in headers:
                value = response.headers.get(header)
                result[header] = (
                    f"Present | {value}" if value is not None else "Missing"
                )

            return result

        except requests.RequestException as exc:
            errors.append(f"{url}: {exc}")

    return {
        "Target": target,
        "URL": "",
        "Status": "",
        "Error": " | ".join(errors),
        **{header: "" for header in headers},
    }


def load_targets(filename):
    with open(filename, encoding="utf-8") as file:
        return [
            line.strip()
            for line in file
            if line.strip() and not line.lstrip().startswith("#")
        ]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Check HTTP security response headers."
    )

    parser.add_argument(
        "-i", "--input",
        default="targets.txt",
        help="Input target file (default: targets.txt)",
    )

    parser.add_argument(
        "-o", "--output",
        default="security_headers_results.csv",
        help="Output CSV file",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=5,
        help="Request timeout in seconds (default: 5)",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=10,
        help="Concurrent workers (default: 10)",
    )

    parser.add_argument(
        "-k", "--insecure",
        action="store_true",
        help="Disable TLS certificate verification",
    )

    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help="Additional response header to check; may be repeated",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    headers = list(dict.fromkeys(DEFAULT_HEADERS + args.header))

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        targets = load_targets(args.input)
    except OSError as exc:
        raise SystemExit(f"Unable to read {args.input}: {exc}")

    if not targets:
        raise SystemExit("No targets found.")

    print(f"Headrz: scanning {len(targets)} target(s)...")

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        results = executor.map(
            lambda target: check_target(
                target,
                headers,
                args.timeout,
                not args.insecure,
            ),
            targets,
        )

        fieldnames = ["Target", "URL", "Status", "Error"] + headers

        try:
            with open(
                args.output,
                "w",
                newline="",
                encoding="utf-8",
            ) as file:
                writer = csv.DictWriter(file, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)

        except OSError as exc:
            raise SystemExit(f"Unable to write {args.output}: {exc}")

    print(f"Scan complete: {args.output}")


if __name__ == "__main__":
    main()
