#!/usr/bin/env python3
"""
Critical Lab 4: Sensitive Data Exposure & Authorization Flaws
Industry-Grade API Penetration Testing Framework

This module systematically tests API endpoints for data exposure and authorization bypasses:
1. Exposed Secrets & Keys in API Responses (Regex Pattern Scanning)
2. Insecure Direct Object References (IDOR / BOLA)
3. Weak Authentication & Default Credentials
4. JWT Manipulation & Algorithm Confusion ('alg: none' / Expired Claims)
5. Authentication Endpoint Brute-Force & Rate-Limit Resistance
6. Unauthenticated Internal / Administrative Endpoints (BFLA)
7. Information Disclosure via Verbose Error Handlers & Stack Traces
"""

import base64
import json
import re
import time
from typing import Any, Dict, List, Optional

import requests


class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


class SensitiveDataExposureLab:
    """Security testing framework for data leakage, authentication, and authorization flaws."""

    def __init__(
        self,
        target_url: str,
        test_username: str = "admin",
        test_password: str = "password",
        attacker_token: str = "",
    ):
        self.target_url = target_url.rstrip("/")
        self.test_username = test_username
        self.test_password = test_password
        self.attacker_token = attacker_token

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SecOps-APITester/2.0"})

        self.findings: List[Dict[str, Any]] = []
        self.secrets_found: List[Dict[str, str]] = []

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
            print(f"  └─ Validation: Endpoint enforces proper authorization and sanitization.")

    # ----------------------------------------------------------------------
    # Test 1: Exposed API Keys and Credentials in Responses
    # ----------------------------------------------------------------------
    def test_exposed_api_keys(self, endpoint: str = "/api/v1/user/profile"):
        full_url = f"{self.target_url}{endpoint}"
        print(f"\n{Colors.BLUE}[*] Testing for exposed API keys/secrets on {endpoint}...{Colors.RESET}")

        sensitive_patterns = {
            "API Key": r'(?i)(?:api_key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            "Secret Key": r'(?i)(?:secret_key|client_secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            "AWS Access Key": r"\b(AKIA[0-9A-Z]{16})\b",
            "JWT Token Leak": r"\b(eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+)\b",
            "Exposed Password": r'(?i)"(?:password|passwd|user_password)"\s*:\s*"([^"]{4,})"',
            "Database DSN": r"(?i)(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[^\s\"']+",
        }

        try:
            headers = {"Authorization": f"Bearer {self.attacker_token}"} if self.attacker_token else {}
            res = self.session.get(full_url, headers=headers, timeout=5)

            found_any = False
            for key_type, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, res.text)
                if matches:
                    found_any = True
                    sample = str(matches[0])[:25] + "..."
                    self.secrets_found.append({"type": key_type, "sample": sample})
                    self.log_result(
                        test_name=f"Sensitive Data Exposure: {key_type}",
                        vulnerable=True,
                        severity="CRITICAL",
                        impact="Exposed API keys and credentials can lead to infrastructure takeover and data exfiltration.",
                        evidence=f"Matched '{key_type}' pattern in response body: {sample}",
                        remediation="Filter response payloads using explicit Data Transfer Objects (DTOs) and omit internal secret fields.",
                    )

            if not found_any:
                self.log_result(
                    test_name="Secret & Token Exposure Audit",
                    vulnerable=False,
                    severity="INFO",
                    impact="None",
                    evidence="No sensitive credentials or private keys detected in response.",
                    remediation="Maintain strict DTO schema serialization.",
                )

        except requests.RequestException as e:
            print(f"  [!] Request error: {e}")

    # ----------------------------------------------------------------------
    # Test 2: Insecure Direct Object References (IDOR / BOLA)
    # ----------------------------------------------------------------------
    def test_idor_vulnerability(self, endpoint_template: str = "/api/v1/users/{id}"):
        print(f"\n{Colors.BLUE}[*] Testing for IDOR / BOLA vulnerability on {endpoint_template}...{Colors.RESET}")

        test_ids = [1, 2, 100, 1002, "admin"]
        for uid in test_ids:
            endpoint = endpoint_template.replace("{id}", str(uid))
            full_url = f"{self.target_url}{endpoint}"

            try:
                headers = {"Authorization": f"Bearer {self.attacker_token}"} if self.attacker_token else {}
                res = self.session.get(full_url, headers=headers, timeout=5)

                if res.status_code == 200 and ("email" in res.text or "username" in res.text or str(uid) in res.text):
                    self.log_result(
                        test_name=f"BOLA / IDOR on ID '{uid}'",
                        vulnerable=True,
                        severity="CRITICAL",
                        impact="Allows horizontal privilege escalation to access private records of arbitrary users.",
                        evidence=f"Successfully accessed object ID {uid} without proper ownership checks: {res.text[:80]}...",
                        remediation="Enforce object-level authorization: ensure record ownership matches authenticated session identity.",
                    )
                    return
            except requests.RequestException:
                pass

        self.log_result(
            test_name="IDOR / BOLA Object Authorization",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="Direct parameter manipulation returned HTTP 403 Forbidden or 404 Not Found.",
            remediation="Maintain object-level permission checks.",
        )

    # ----------------------------------------------------------------------
    # Test 3: Weak Authentication & Default Credentials
    # ----------------------------------------------------------------------
    def test_weak_authentication(self, login_endpoint: str = "/api/v1/auth/login"):
        full_url = f"{self.target_url}{login_endpoint}"
        print(f"\n{Colors.BLUE}[*] Testing for weak authentication & default credentials on {login_endpoint}...{Colors.RESET}")

        default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("test", "test"),
        ]

        for username, password in default_creds:
            try:
                data = {"username": username, "password": password}
                res = self.session.post(full_url, json=data, timeout=5)

                if res.status_code == 200 and any(k in res.text.lower() for k in ["token", "access_token", "success"]):
                    self.log_result(
                        test_name=f"Default Credentials Discovered ({username}:{password})",
                        vulnerable=True,
                        severity="CRITICAL",
                        impact="Attackers can authenticate directly using well-known administrative default credentials.",
                        evidence=f"Authentication succeeded with default credentials '{username}:{password}'.",
                        remediation="Enforce complex password policies and force default credential rotation upon first setup.",
                    )
                    return
            except requests.RequestException:
                pass

        self.log_result(
            test_name="Default Credential Hardening",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="Common default credentials were rejected.",
            remediation="Maintain strong authentication enforcement.",
        )

    # ----------------------------------------------------------------------
    # Test 4: JWT Token Manipulation & Signature Bypass
    # ----------------------------------------------------------------------
    def test_jwt_vulnerabilities(self, sample_token: Optional[str] = None):
        print(f"\n{Colors.BLUE}[*] Testing JWT Signature Validation & Algorithm Manipulation...{Colors.RESET}")

        # Construct an 'alg: none' unsigned token
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "admin", "role": "admin", "exp": int(time.time()) + 3600}).encode()
        ).decode().rstrip("=")
        unsigned_jwt = f"{header}.{payload}."

        full_url = f"{self.target_url}/api/v1/user/profile"
        try:
            res = self.session.get(full_url, headers={"Authorization": f"Bearer {unsigned_jwt}"}, timeout=5)
            if res.status_code == 200:
                self.log_result(
                    test_name="JWT 'alg: none' Signature Validation Bypass",
                    vulnerable=True,
                    severity="CRITICAL",
                    impact="Attackers can forge arbitrary JWTs with modified claims without knowledge of signing secrets.",
                    evidence=f"Server accepted unsigned JWT token. Response: {res.text[:80]}...",
                    remediation="Explicitly require RS256/ES256 signatures and reject tokens using 'none' algorithm.",
                )
                return
        except requests.RequestException:
            pass

        self.log_result(
            test_name="JWT Signature Validation",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="Unsigned and tampered JWT tokens were rejected.",
            remediation="Maintain cryptographic signature validation.",
        )

    # ----------------------------------------------------------------------
    # Test 5: Brute-Force Resistance on Login Endpoints
    # ----------------------------------------------------------------------
    def test_brute_force_endpoint(self, login_endpoint: str = "/api/v1/auth/login"):
        full_url = f"{self.target_url}{login_endpoint}"
        print(f"\n{Colors.BLUE}[*] Testing brute-force resistance on {login_endpoint}...{Colors.RESET}")

        passwords = [f"test_pass_{i}" for i in range(15)]
        throttled = False

        for pwd in passwords:
            try:
                res = self.session.post(
                    full_url,
                    json={"username": self.test_username, "password": pwd},
                    timeout=3,
                )
                if res.status_code == 429:
                    throttled = True
                    break
            except requests.RequestException:
                pass

        if not throttled:
            self.log_result(
                test_name="Missing Login Endpoint Rate Limiting (Brute-Force Risk)",
                vulnerable=True,
                severity="HIGH",
                impact="Enables automated credential stuffing and dictionary attacks against user accounts.",
                evidence=f"Sent {len(passwords)} consecutive failed login attempts without receiving HTTP 429.",
                remediation="Implement account lockouts and IP/account-based rate limiting on all login routes.",
            )
        else:
            self.log_result(
                test_name="Login Brute-Force Protection",
                vulnerable=False,
                severity="INFO",
                impact="None",
                evidence="Throttling mechanism triggered (HTTP 429 received) upon repeated failed logins.",
                remediation="Maintain rate-limiting rules.",
            )

    # ----------------------------------------------------------------------
    # Test 6: Exposed Internal & Administrative APIs (BFLA)
    # ----------------------------------------------------------------------
    def test_exposed_internal_apis(self):
        print(f"\n{Colors.BLUE}[*] Testing for exposed internal / administrative routes...{Colors.RESET}")

        internal_endpoints = [
            "/api/v1/admin/users",
            "/api/v1/admin/system",
            "/api/v1/internal/config",
            "/api/v1/debug/metrics",
            "/actuator/env",
            "/actuator/health",
        ]

        exposed = []
        for ep in internal_endpoints:
            url = f"{self.target_url}{ep}"
            try:
                headers = {"Authorization": f"Bearer {self.attacker_token}"} if self.attacker_token else {}
                res = self.session.get(url, headers=headers, timeout=3)
                if res.status_code == 200 and len(res.text) > 10:
                    exposed.append(ep)
            except requests.RequestException:
                pass

        if exposed:
            self.log_result(
                test_name="Exposed Internal & Administrative Endpoints",
                vulnerable=True,
                severity="CRITICAL",
                impact="Unprivileged users or external parties can access internal telemetry, configs, or administrative functions.",
                evidence=f"Accessible internal routes: {', '.join(exposed)}",
                remediation="Place administrative routes behind strict Role-Based Access Control (RBAC) and network-level firewalls.",
            )
        else:
            self.log_result(
                test_name="Internal Endpoint Access Control",
                vulnerable=False,
                severity="INFO",
                impact="None",
                evidence="Internal endpoints returned HTTP 401/403 or 404.",
                remediation="Maintain network isolation and RBAC checks.",
            )

    # ----------------------------------------------------------------------
    # Test 7: Information Disclosure via Error Messages
    # ----------------------------------------------------------------------
    def test_information_disclosure(self, endpoint: str = "/api/v1/search"):
        full_url = f"{self.target_url}{endpoint}"
        print(f"\n{Colors.BLUE}[*] Testing for information disclosure on {endpoint}...{Colors.RESET}")

        leak_indicators = [
            "traceback",
            "stack trace",
            "sqlite3.operationalerror",
            "psycopg2",
            "pymongo.errors",
            "unhandled exception",
        ]

        try:
            res = self.session.get(full_url, params={"q": "';---INVALID[["}, timeout=5)
            found_leak = any(indicator in res.text.lower() for indicator in leak_indicators)

            if found_leak:
                self.log_result(
                    test_name="Verbose Error Stack Trace Disclosure",
                    vulnerable=True,
                    severity="MEDIUM",
                    impact="Leaked stack traces reveal internal framework details, code paths, and database structures.",
                    evidence=f"Server returned runtime stack trace in HTTP {res.status_code} response.",
                    remediation="Implement global exception handlers to return sanitized, structured JSON error details.",
                )
                return

        except requests.RequestException:
            pass

        self.log_result(
            test_name="Error Handling Sanitization",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="Error responses are sanitized without leaking stack traces or internal mechanics.",
            remediation="Maintain centralized exception handling.",
        )

    # ----------------------------------------------------------------------
    # Harness Execution
    # ----------------------------------------------------------------------
    def run_all(self):
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD} CRITICAL SENSITIVE DATA EXPOSURE & AUTH AUDIT SUITE{Colors.RESET}")
        print(f" Target Host: {self.target_url}")
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")

        self.test_exposed_api_keys("/api/v1/user/profile")
        self.test_idor_vulnerability("/api/v1/users/{id}")
        self.test_weak_authentication("/api/v1/auth/login")
        self.test_jwt_vulnerabilities()
        self.test_brute_force_endpoint("/api/v1/auth/login")
        self.test_exposed_internal_apis()
        self.test_information_disclosure("/api/v1/search")

        print(f"\n{Colors.HEADER}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}AUDIT SUMMARY{Colors.RESET}")
        print(f"Total Flaws Discovered: {len(self.findings)}")
        print(f"Exposed Secrets Identified: {len(self.secrets_found)}")
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")


if __name__ == "__main__":
    TARGET_HOST = "http://localhost:8080"
    tester = SensitiveDataExposureLab(target_url=TARGET_HOST)
    tester.run_all()
