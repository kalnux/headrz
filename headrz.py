#!/usr/bin/env python3

import argparse
import csv
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import requests
import urllib3


DEFAULT_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

USER_AGENT = "headrz/3.0"


def candidate_urls(target):
    """
    Generate candidate URLs for a target.

    Targets may be provided as:
      - hostname
      - IP address
      - hostname:port
      - IP:port
      - full HTTP/HTTPS URL
    """
    target = target.strip()

    if not target:
        return []

    if target.startswith(("http://", "https://")):
        return [target]

    try:
        parsed = urlsplit(f"//{target}")
        port = parsed.port
    except ValueError:
        return []

    if port in (443, 8443):
        return [f"https://{target}"]

    if port in (80, 8080):
        return [f"http://{target}"]

    return [
        f"https://{target}",
        f"http://{target}",
    ]


def perform_request(url, timeout, verify):
    """
    Perform an HTTP request without following redirects.
    """
    return requests.get(
        url,
        timeout=timeout,
        verify=verify,
        allow_redirects=False,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
        },
    )


def build_result(
    target,
    requested_url,
    response,
    headers,
    tls_validation="",
    error="",
):
    """
    Build a result dictionary from an HTTP response.
    """
    result = {
        "Target": target,
        "Requested URL": requested_url,
        "Response URL": response.url if response is not None else "",
        "Status": response.status_code if response is not None else "",
        "TLS Validation": tls_validation,
        "Redirect Location": (
            response.headers.get("Location", "")
            if response is not None
            else ""
        ),
        "Error": error,
    }

    for header in headers:
        if response is None:
            result[header] = ""
            continue

        value = response.headers.get(header)

        if value is None:
            result[header] = "Missing"
        else:
            result[header] = f"Present | {value}"

    return result


def check_target(
    target,
    headers,
    timeout,
    verify,
    retry_insecure_on_tls_error,
):
    """
    Check a single target.

    HTTPS is attempted before HTTP when no scheme or explicit port
    determines the protocol.

    Redirects are not followed.

    When enabled, an HTTPS request that fails certificate validation is
    retried with certificate verification disabled so that the HTTP
    response can still be inspected. The validation failure is retained
    in the result.
    """
    urls = candidate_urls(target)

    if not urls:
        result = {
            "Target": target,
            "Requested URL": "",
            "Response URL": "",
            "Status": "",
            "TLS Validation": "",
            "Redirect Location": "",
            "Error": "Invalid target",
        }

        result.update({header: "" for header in headers})
        return result

    errors = []

    for url in urls:
        is_https = url.lower().startswith("https://")

        try:
            response = perform_request(
                url=url,
                timeout=timeout,
                verify=verify,
            )

            if is_https:
                tls_validation = (
                    "Verified"
                    if verify
                    else "Verification disabled"
                )
            else:
                tls_validation = "N/A"

            return build_result(
                target=target,
                requested_url=url,
                response=response,
                headers=headers,
                tls_validation=tls_validation,
            )

        except requests.exceptions.SSLError as exc:
            if (
                is_https
                and verify
                and retry_insecure_on_tls_error
            ):
                tls_error = str(exc)

                try:
                    response = perform_request(
                        url=url,
                        timeout=timeout,
                        verify=False,
                    )

                    return build_result(
                        target=target,
                        requested_url=url,
                        response=response,
                        headers=headers,
                        tls_validation=(
                            "Failed; response retrieved without "
                            "certificate verification"
                        ),
                        error=f"TLS validation failed: {tls_error}",
                    )

                except requests.RequestException as retry_exc:
                    errors.append(
                        f"{url}: TLS validation failed ({tls_error}); "
                        f"insecure retry failed ({retry_exc})"
                    )
                    continue

            errors.append(
                f"{url}: TLS validation failed ({exc})"
            )
            continue

        except requests.exceptions.Timeout as exc:
            errors.append(
                f"{url}: request timed out ({exc})"
            )
            continue

        except requests.exceptions.ConnectionError as exc:
            errors.append(
                f"{url}: connection failed ({exc})"
            )
            continue

        except requests.RequestException as exc:
            errors.append(
                f"{url}: request failed ({exc})"
            )
            continue

    result = {
        "Target": target,
        "Requested URL": "",
        "Response URL": "",
        "Status": "",
        "TLS Validation": "",
        "Redirect Location": "",
        "Error": " | ".join(errors),
    }

    result.update({header: "" for header in headers})
    return result


def load_targets(filename):
    """
    Load targets from a text file.

    Empty lines and lines beginning with '#' are ignored.
    """
    with open(filename, encoding="utf-8") as file:
        return [
            line.strip()
            for line in file
            if line.strip()
            and not line.lstrip().startswith("#")
        ]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Check HTTP response headers for multiple targets."
    )

    parser.add_argument(
        "-i",
        "--input",
        default="targets.txt",
        help="Input target file (default: targets.txt)",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="security_headers_results.csv",
        help="Output CSV file",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=10,
        help="Number of concurrent workers (default: 10)",
    )

    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification for all HTTPS requests",
    )

    parser.add_argument(
        "--no-tls-retry",
        action="store_true",
        help=(
            "Do not retry HTTPS requests without certificate verification "
            "when TLS validation fails"
        ),
    )

    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help=(
            "Additional response header to check. "
            "May be specified multiple times."
        ),
    )

    return parser.parse_args()


def main():
    args = parse_args()

    urllib3.disable_warnings(
        urllib3.exceptions.InsecureRequestWarning
    )

    headers = list(
        dict.fromkeys(DEFAULT_HEADERS + args.header)
    )

    try:
        targets = load_targets(args.input)
    except OSError as exc:
        raise SystemExit(
            f"Unable to read {args.input}: {exc}"
        )

    if not targets:
        raise SystemExit("No targets found.")

    print(
        f"Headrz: scanning {len(targets)} target(s)..."
    )

    with ThreadPoolExecutor(
        max_workers=max(1, args.workers)
    ) as executor:
        results = executor.map(
            lambda target: check_target(
                target=target,
                headers=headers,
                timeout=args.timeout,
                verify=not args.insecure,
                retry_insecure_on_tls_error=(
                    not args.no_tls_retry
                ),
            ),
            targets,
        )

        fieldnames = [
            "Target",
            "Requested URL",
            "Response URL",
            "Status",
            "TLS Validation",
            "Redirect Location",
            "Error",
        ] + headers

        try:
            with open(
                args.output,
                "w",
                newline="",
                encoding="utf-8",
            ) as file:
                writer = csv.DictWriter(
                    file,
                    fieldnames=fieldnames,
                )
                writer.writeheader()
                writer.writerows(results)

        except OSError as exc:
            raise SystemExit(
                f"Unable to write {args.output}: {exc}"
            )

    print(f"Scan complete: {args.output}")


if __name__ == "__main__":
    main()
