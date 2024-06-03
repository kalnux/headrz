import csv
import requests
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

security_headers = [
    'Strict-Transport-Security',
    'X-Frame-Options',
    'X-XSS-Protection',
    'X-Content-Type-Options',
    'Content-Security-Policy',
    'Referrer-Policy',
    'Feature-Policy'
]

# Function to check the URL and return the results
def check_url(url, security_headers, timeout=5):
    try:
        response = requests.get(url, verify=False, timeout=timeout)
        results = [url]
        for header in security_headers:
            value = response.headers.get(header)
            if value is not None:
                results.append(f'Present | {value}')
            else:
                results.append('Missing')
        return results
    except (requests.exceptions.RequestException, ValueError) as e:
        return f'Error checking {url}: {e}'

banner()

# Read targets from file
with open('targets.txt') as f:
    targets = [line.strip() for line in f]

# Write results to CSV
with open('security_headers_results.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    headers_row = ['URL'] + security_headers
    writer.writerow(headers_row)

    for target in targets:
        # Determine the protocol and URL format
        if ':' in target:
            ip, port = target.split(':')
            port = int(port)
            if port in [443, 8443]:
                url_https = f'https://{ip}:{port}'
                results = check_url(url_https, security_headers)
            elif port in [80, 8080]:
                url_http = f'http://{ip}:{port}'
                results = check_url(url_http, security_headers)
            else:
                # Try both protocols for non-standard ports
                url_http = f'http://{ip}:{port}'
                url_https = f'https://{ip}:{port}'
                results = check_url(url_http, security_headers)
                if 'Error' in results:
                    results = check_url(url_https, security_headers)
        else:
            url_http = f'http://{target}'
            url_https = f'https://{target}'
            results = check_url(url_http, security_headers)
            if 'Error' in results:
                results = check_url(url_https, security_headers)

        # If results is still a string, it indicates an error; otherwise, it's the header checks
        if isinstance(results, str):
            print(results)  # Print the error
        else:
            writer.writerow(results)  # Write the successful checks to the CSV

print("Scan complete. Results saved to 'security_headers_results.csv'.")
