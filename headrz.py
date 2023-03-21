import csv
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def banner():
    print("")
    print("======================================================")
    print(" Houssam - MALLEUM - .................................")
    print("------------------------------------------------------")
    print(" A script for checking HTTP Security Response Headers ")
    print("======================================================")
    print("")

security_headers = [
    'Strict-Transport-Security',
    'X-Frame-Options',
    'X-XSS-Protection',
    'X-Content-Type-Options',
    'Content-Security-Policy',
    'Referrer-Policy',
    'Feature-Policy'
]

banner()

with open('targets.txt') as f:
    targets = [line.strip() for line in f]

with open('security_headers_results.csv', mode='a', newline='') as f:
    writer = csv.writer(f)

    if f.tell() == 0:
        headers_row = ['URL'] + security_headers
        writer.writerow(headers_row)

    for target in targets:
        if not target.startswith('http'):
            target = f'https://{target}'

        try:
            response = requests.get(target, verify=False)

            results = [target]
            for header in security_headers:
                value = response.headers.get(header)
                if value is not None:
                    results.append(f'Present | {value}')
                else:
                    results.append('Missing')

            writer.writerow(results)

        except (requests.exceptions.RequestException, ValueError) as e:
            print(f'Error checking {target}: {e}')
            continue
