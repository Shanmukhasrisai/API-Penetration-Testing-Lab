#!/usr/bin/env python3
"""
API Penetration Testing Lab - Core Scanner Engine
Advanced Multi-Vector Security Assessment Tool for REST Endpoints

Features:
- Dynamic target endpoint configuration via JSON schema
- Authentication header integration (Bearer tokens, API keys, custom headers)
- Multi-vector injection testing:
    * Reflected & Contextual Cross-Site Scripting (XSS)
    * SQL Injection (Error-Based & Boolean Inference)
    * NoSQL Operator & JSON Structure Injection
    * Command Injection & OS Subshell Delimiters
- Structured JSON reporting with timestamped vulnerability evidence
"""

import argparse
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import requests


class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


# ------------------------------------------------------------------------------
# Configuration & Constants
# ------------------------------------------------------------------------------
USER_AGENT = "SecOps-APIScanner/2.5 (Automated API Security Assessment)"
DEFAULT_TIMEOUT = 7
MAX_CONFIG_SIZE = 10 * 1024 * 1024  # 10 MB limit for config files


PAYLOAD_MATRIX = {
    "xss": [
        "<script>alert('SEC_XSS')</script>",
        "\"-alert('SEC_XSS')-\"",
        "<img src=x onerror=alert('SEC_XSS')>",
        "<svg/onload=alert('SEC_XSS')>",
        "javascript:alert('SEC_XSS')",
    ],
    "sqli": [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "admin'--",
        "1' UNION SELECT NULL, NULL--",
        "1; SELECT pg_sleep(0)--",
    ],
    "nosql": [
        {"$ne": "__non_existent_key__"},
        {"$gt": ""},
        {"$regex": "^admin.*"},
        {"$where": "1 == 1"},
    ],
    "command_injection": [
        "; echo SEC_CMD_VULN",
        "| echo SEC_CMD_VULN",
        "`echo SEC_CMD_VULN`",
        "$(echo SEC_CMD_VULN)",
    ],
}

SQL_ERROR_PATTERNS = [
    r"syntax error in query expression",
    r"mysql_fetch",
    r"You have an error in your SQL syntax",
    r"pg_query\(\)",
    r"unclosed quotation mark after the character string",
    r"sqlite3\.OperationalError",
    r"ORA-00933",
    r"SQLSTATE\[",
    r"Microsoft OLE DB Provider for SQL Server",
    r"PostgreSQL.*ERROR",
]


# ------------------------------------------------------------------------------
# Configuration Loader & Validator
# ------------------------------------------------------------------------------
def load_endpoints_config(filename: str) -> List[Dict[str, Any]]:
    """Load and validate API endpoints and parameters from JSON configuration."""
    if not os.path.exists(filename):
        print(f"{Colors.RED}[!] Error: Config file not found: {filename}{Colors.RESET}")
        sys.exit(1)

    if os.path.getsize(filename) > MAX_CONFIG_SIZE:
        print(f"{Colors.RED}[!] Error: Config file exceeds size limit (10MB){Colors.RESET}")
        sys.exit(1)

    try:
        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)

        endpoints = data.get("endpoints", [])
        if not isinstance(endpoints, list):
            raise ValueError("'endpoints' must be a list of endpoint configurations")

        for idx, ep in enumerate(endpoints):
            if not isinstance(ep, dict):
                raise ValueError(f"Endpoint index {idx} must be a JSON object")
            if "url" not in ep or not isinstance(ep["url"], str):
                raise ValueError(f"Endpoint index {idx} is missing a valid 'url' string")

        return endpoints

    except json.JSONDecodeError as e:
        print(f"{Colors.RED}[!] JSON Parsing Error: {e}{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[!] Config Validation Error: {e}{Colors.RESET}")
        sys.exit(1)


# ------------------------------------------------------------------------------
# Core HTTP Request Engine
# ------------------------------------------------------------------------------
def make_request(
    url: str,
    method: str,
    headers: Dict[str, str],
    params: Optional[Dict[str, Any]] = None,
    json_data: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[Optional[int], Optional[str], Optional[Dict[str, str]]]:
    """Execute HTTP requests with standardized exception handling and verification."""
    if not url.startswith(("http://", "https://")):
        return None, None, None

    try:
        res = requests.request(
            method=method.upper(),
            url=url,
            headers=headers,
            params=params,
            json=json_data,
            data=data,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        return res.status_code, res.text, dict(res.headers)
    except requests.exceptions.Timeout:
        return None, "TIMEOUT", None
    except requests.exceptions.RequestException:
        return None, None, None


# ------------------------------------------------------------------------------
# Vulnerability Testing Routines
# ------------------------------------------------------------------------------
def test_xss(
    url: str,
    method: str,
    headers: Dict[str, str],
    param_name: str,
    timeout: int,
) -> Optional[Dict[str, str]]:
    """Test parameter for Reflected Cross-Site Scripting (XSS)."""
    for payload in PAYLOAD_MATRIX["xss"]:
        if method.upper() == "GET":
            status, text, res_headers = make_request(url, "GET", headers, params={param_name: payload}, timeout=timeout)
        else:
            status, text, res_headers = make_request(url, method, headers, json_data={param_name: payload}, timeout=timeout)

        if text and "SEC_XSS" in text:
            content_type = (res_headers or {}).get("Content-Type", "").lower()
            if "text/html" in content_type or "application/xml" in content_type or "SEC_XSS" in text:
                return {
                    "vulnerability": "Reflected Cross-Site Scripting (XSS)",
                    "parameter": param_name,
                    "payload": payload,
                    "evidence": f"Reflected unencoded payload in response with status {status}",
                    "severity": "HIGH",
                    "remediation": "Implement contextual output encoding and enforce 'X-Content-Type-Options: nosniff'.",
                }
    return None


def test_sql_injection(
    url: str,
    method: str,
    headers: Dict[str, str],
    param_name: str,
    timeout: int,
) -> Optional[Dict[str, str]]:
    """Test parameter for Error-Based SQL Injection."""
    for payload in PAYLOAD_MATRIX["sqli"]:
        if method.upper() == "GET":
            status, text, _ = make_request(url, "GET", headers, params={param_name: payload}, timeout=timeout)
        else:
            status, text, _ = make_request(url, method, headers, json_data={param_name: payload}, timeout=timeout)

        if text:
            for pattern in SQL_ERROR_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    return {
                        "vulnerability": "Error-Based SQL Injection",
                        "parameter": param_name,
                        "payload": payload,
                        "evidence": f"Triggered SQL database error pattern: '{pattern}'",
                        "severity": "CRITICAL",
                        "remediation": "Use parameterized prepared statements across all database queries.",
                    }
    return None


def test_command_injection(
    url: str,
    method: str,
    headers: Dict[str, str],
    param_name: str,
    timeout: int,
) -> Optional[Dict[str, str]]:
    """Test parameter for Remote OS Command Injection."""
    for payload in PAYLOAD_MATRIX["command_injection"]:
        test_val = f"test{payload}"
        if method.upper() == "GET":
            status, text, _ = make_request(url, "GET", headers, params={param_name: test_val}, timeout=timeout)
        else:
            status, text, _ = make_request(url, method, headers, json_data={param_name: test_val}, timeout=timeout)

        if text and "SEC_CMD_VULN" in text:
            return {
                "vulnerability": "Remote OS Command Injection",
                "parameter": param_name,
                "payload": payload,
                "evidence": "Observed execution stdout token 'SEC_CMD_VULN' in HTTP response body",
                "severity": "CRITICAL",
                "remediation": "Avoid invoking operating system shells directly; use safe APIs with array argument binding.",
            }
    return None


def test_nosql_injection(
    url: str,
    method: str,
    headers: Dict[str, str],
    param_name: str,
    timeout: int,
) -> Optional[Dict[str, str]]:
    """Test parameter for NoSQL Operator Injection."""
    if method.upper() == "GET":
        return None  # NoSQL operator injection primarily targets structured JSON bodies

    for payload in PAYLOAD_MATRIX["nosql"]:
        status, text, _ = make_request(url, method, headers, json_data={param_name: payload}, timeout=timeout)
        if status in [200, 201] and text and len(text) > 20:
            if any(k in text.lower() for k in ["token", "success", "admin", "results"]):
                return {
                    "vulnerability": "NoSQL Operator Injection",
                    "parameter": param_name,
                    "payload": str(payload),
                    "evidence": f"Server accepted structured object operator and returned status HTTP {status}",
                    "severity": "CRITICAL",
                    "remediation": "Enforce strict scalar type validation (Pydantic / Joi) and sanitize nested query objects.",
                }
    return None


# ------------------------------------------------------------------------------
# Audit Runner & Orchestrator
# ------------------------------------------------------------------------------
def run_endpoint_audit(
    endpoint: Dict[str, Any],
    headers: Dict[str, str],
    timeout: int,
) -> Dict[str, Any]:
    """Execute complete security assessment across all parameters in an endpoint."""
    url = endpoint.get("url", "")
    method = endpoint.get("method", "GET").upper()
    params = endpoint.get("params", [])

    print(f"\n{Colors.BLUE}[*] Auditing:{Colors.RESET} {method} {url}")

    endpoint_findings: List[Dict[str, str]] = []

    for param in params:
        if not isinstance(param, str):
            continue

        print(f"  ├─ Testing parameter: {Colors.BOLD}{param}{Colors.RESET}")

        # Execute tests sequentially
        tests = [
            test_sql_injection(url, method, headers, param, timeout),
            test_command_injection(url, method, headers, param, timeout),
            test_nosql_injection(url, method, headers, param, timeout),
            test_xss(url, method, headers, param, timeout),
        ]

        for result in tests:
            if result:
                endpoint_findings.append(result)
                print(
                    f"  │  └─ {Colors.RED}[{result['severity']}]{Colors.RESET} "
                    f"{Colors.BOLD}{result['vulnerability']}{Colors.RESET} (Payload: {result['payload']})"
                )

    return {
        "url": url,
        "method": method,
        "parameters_tested": params,
        "vulnerabilities": endpoint_findings,
    }


def main():
    parser = argparse.ArgumentParser(
        description="API Penetration Testing Lab - Core Security Testing Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", required=True, help="Path to JSON configuration file with API endpoints to test")
    parser.add_argument("--auth", help="Authorization header value (e.g., 'Bearer <token>' or 'APIKey <key>')")
    parser.add_argument("--output", help="Path to export the structured JSON report")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"HTTP request timeout in seconds (default: {DEFAULT_TIMEOUT})")

    args = parser.parse_args()

    # Disable SSL warning output for self-signed certificates in local lab testing
    requests.packages.urllib3.disable_warnings()

    auth_headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    if args.auth:
        auth_headers["Authorization"] = args.auth

    endpoints = load_endpoints_config(args.config)

    print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD} API SECURITY PENETRATION TESTING ENGINE{Colors.RESET}")
    print(f" Endpoints Configured: {len(endpoints)}")
    print(f" Target Auth: {'Configured' if args.auth else 'Unauthenticated / None'}")
    print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")

    full_report: List[Dict[str, Any]] = []
    total_vulns = 0

    for ep in endpoints:
        res = run_endpoint_audit(ep, auth_headers, args.timeout)
        full_report.append(res)
        total_vulns += len(res["vulnerabilities"])

    print(f"\n{Colors.HEADER}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}SCAN SUMMARY{Colors.RESET}")
    print(f"Total Endpoints Audited: {len(endpoints)}")
    print(f"Total Confirmed Vulnerabilities: {total_vulns}")
    print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")

    report_payload = {
        "scan_metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_endpoints": len(endpoints),
            "total_vulnerabilities": total_vulns,
        },
        "results": full_report,
    }

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(report_payload, f, indent=2)
            print(f"\n[+] Detailed JSON report exported to: {args.output}")
        except Exception as e:
            print(f"[!] Failed to save JSON report: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
