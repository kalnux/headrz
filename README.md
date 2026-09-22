# Headrz

Headrz is a small Python tool for checking HTTP response headers across multiple hosts.

It reads targets from a file and exports the results to CSV.

## Headers checked

By default, Headrz checks the following response headers:

* `Strict-Transport-Security`
* `Content-Security-Policy`
* `X-Frame-Options`
* `X-Content-Type-Options`
* `Referrer-Policy`
* `Permissions-Policy`

Additional headers can be supplied with `--header`.

## Install

```
git clone https://github.com/kalnux/headrz.git
cd headrz
pip install requests urllib3
```

## Usage

Create `targets.txt`:

```
example.com
example.org:8443
192.168.1.10
http://192.168.1.20:8080

# comments are ignored
https://internal.example.com
```

Run:

```
python3 headrz.py
```

Results are saved by default to:

```text
security_headers_results.csv
```

### Options

```text
-i, --input FILE       Input file (default: targets.txt)
-o, --output FILE      Output CSV file
--timeout SECONDS      Request timeout (default: 10)
--workers NUMBER       Concurrent requests (default: 10)
-k, --insecure         Disable TLS certificate verification
--no-tls-retry         Do not retry HTTPS requests without certificate
                       verification when TLS validation fails
--header HEADER        Check an additional response header
```

Examples:

```
python3 headrz.py -i hosts.txt -o results.csv

python3 headrz.py --timeout 15 --workers 20

python3 headrz.py -k

python3 headrz.py --no-tls-retry

python3 headrz.py --header Cross-Origin-Opener-Policy
```

## Target handling

Headrz accepts:

* Hostnames
* IP addresses
* Hostnames or IP addresses with explicit ports
* Full HTTP or HTTPS URLs

When no scheme or explicit protocol-specific port is provided, Headrz attempts HTTPS first and falls back to HTTP if the HTTPS request cannot be completed.

Explicit `http://` and `https://` targets are used as provided.

## Redirects

Headrz does not follow HTTP redirects.

Redirect responses are recorded as returned by the target, and the value of the `Location` header is written to the `Redirect Location` column in the CSV.

This makes it possible to inspect the response headers returned directly by each target without replacing them with headers from a redirect destination.

## TLS

TLS certificate verification is enabled by default.

If an HTTPS request fails certificate validation, Headrz can retry the request with certificate verification disabled. This allows the HTTP response to be inspected while preserving the certificate validation failure in the CSV output.

The `TLS Validation` column indicates whether certificate validation:

* succeeded,
* was disabled,
* or failed before the response was retrieved using an unverified retry.

The original TLS validation error is retained in the `Error` column.

To prevent automatic retry after a TLS validation failure:

```
python3 headrz.py --no-tls-retry
```

To disable certificate verification for all HTTPS requests:

```
python3 headrz.py -k
```

Disabling certificate verification should only be used when appropriate for the environment being tested.

## CSV output

The output includes:

```
Target
Requested URL
Response URL
Status
TLS Validation
Redirect Location
Error
```

followed by one column for each response header being checked.

Header values are reported as:

```
Present | <header value>
```

or:

```
Missing
```

Failed requests are also written to the CSV so that targets are not silently omitted.

## Requirements

* Python 3
* requests
* urllib3

## Disclaimer

Use Headrz only against systems you own or are authorized to test.
