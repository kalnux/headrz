# Headrz

Headrz is a small Python tool for checking HTTP security response headers across multiple hosts.

It reads targets from a file and exports the results to CSV.

## Headers checked

* `Strict-Transport-Security`
* `Content-Security-Policy`
* `X-Frame-Options`
* `X-Content-Type-Options`
* `Referrer-Policy`
* `Permissions-Policy`
* `X-XSS-Protection` *(legacy)*
* `Feature-Policy` *(legacy)*

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

Results are saved to:

```
security_headers_results.csv
```

### Options

```
-i, --input FILE       Input file (default: targets.txt)
-o, --output FILE      Output CSV
--timeout SECONDS      Request timeout (default: 5)
--workers NUMBER       Concurrent requests (default: 10)
-k, --insecure         Disable TLS certificate verification
--header HEADER        Check an additional header
```

Examples:

```
python3 headrz.py -i hosts.txt -o results.csv

python3 headrz.py --timeout 10 --workers 20

python3 headrz.py -k

python3 headrz.py --header Cross-Origin-Opener-Policy
```

Headrz prefers HTTPS and falls back to HTTP where appropriate. Explicit `http://` or `https://` targets are used as provided.

Failed requests are also recorded in the CSV so that unreachable targets are not silently lost.

## TLS

Certificate verification is enabled by default.

For authorized testing of systems using self-signed or otherwise untrusted certificates:

```
python3 headrz.py -k
```

## Requirements

* Python 3
* requests
* urllib3

## Disclaimer

Use Headrz only against systems you own or are authorized to test.
