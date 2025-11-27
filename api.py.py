#!/usr/bin/env python3
"""
Advanced HackerHunt-Lab for API Pentesting Practice
- Dynamic endpoints from config
- Supports Auth headers
- Tests multiple HTTP methods and vulnerabilities
- Generates detailed JSON output report
"""

import sys
import json
import argparse
import requests
from urllib.parse import urljoin
from typing import List, Dict, Any

USER_AGENT = "AdvancedHackerHuntLab/2.0"
DEFAULT_TIMEOUT = 7

def load_endpoints_config(filename: str) -> List[Dict[str, Any]]:
    """Load API endpoints and test details from JSON config file"""
    with open(filename, 'r') as f:
        data = json.load(f)
    return data.get("endpoints", [])

def make_request(url: str, method: str, headers: dict, params=None, data=None):
    try:
        resp = requests.request(method, url, headers=headers, params=params, data=data, timeout=DEFAULT_TIMEOUT)
        return resp.status_code, resp.text
    except Exception as e:
        print(f"[!] Request failed for {url} with {method}: {e}")
        return None, None

def test_reflected_xss(url: str, method: str, headers: dict, param_name: str):
    payload = "<script>alert('XSS')</script>"
    if method.upper() == "GET":
        params = {param_name: payload}
        status, content = make_request(url, "GET", headers, params=params)
    else:
        data = {param_name: payload}
        status, content = make_request(url, method.upper(), headers, data=data)
    if content and payload in content:
        return True
    return False

def test_sql_injection(url: str, method: str, headers: dict, param_name: str):
    payload = "'"
    if method.upper() == "GET":
        params = {param_name: payload}
        status, content = make_request(url, "GET", headers, params=params)
    else:
        data = {param_name: payload}
        status, content = make_request(url, method.upper(), headers, data=data)
    if content:
        errors = [
            "sql syntax", "mysql", "syntax error", "unclosed quotation",
            "sqlite error", "pg_query", "sqlstate", "mysql_fetch",
            "mysql_num_rows", "sql error"
        ]
        content_lower = content.lower()
        if any(e in content_lower for e in errors):
            return True
    return False

def run_tests(endpoint: Dict[str, Any], auth_headers: dict):
    results = {
        "url": endpoint.get("url"),
        "method": endpoint.get("method", "GET"),
        "vulnerabilities": {}
    }
    param_names = endpoint.get("params", [])
    for param in param_names:
        if test_reflected_xss(endpoint["url"], results["method"], auth_headers, param):
            results["vulnerabilities"].setdefault("reflected_xss", []).append(param)
        if test_sql_injection(endpoint["url"], results["method"], auth_headers, param):
            results["vulnerabilities"].setdefault("sql_injection", []).append(param)
    return results

def main():
    parser = argparse.ArgumentParser(description="Advanced HackerHunt Lab for API Pentesting")
    parser.add_argument("--config", required=True, help="JSON config file with API endpoints to test")
    parser.add_argument("--auth", help="Authorization header value, e.g. 'Bearer <token>' or 'APIKey <key>'")
    parser.add_argument("--output", help="Output JSON report file")
    args = parser.parse_args()

    auth_headers = {"User-Agent": USER_AGENT}
    if args.auth:
        auth_headers["Authorization"] = args.auth

    endpoints = load_endpoints_config(args.config)
    report = []

    for endpoint in endpoints:
        print(f"[*] Testing endpoint {endpoint.get('url')} with method {endpoint.get('method', 'GET')}")
        result = run_tests(endpoint, auth_headers)
        report.append(result)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
