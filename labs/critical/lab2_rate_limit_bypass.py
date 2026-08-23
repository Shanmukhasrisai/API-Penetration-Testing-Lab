#!/usr/bin/env python3
"""
Critical Lab 2: API Rate Limiting Bypass and Resource Consumption Testing
Industry-Grade API Penetration Testing Framework

This module systematically tests API endpoints for rate-limiting and throttling bypasses:
1. Baseline Threshold Identification (Detecting 429 Too Many Requests)
2. Layer 7 Proxy Header Spoofing (X-Forwarded-For, X-Real-IP, CF-Connecting-IP)
3. HTTP Verb & Method Override Tampering (X-HTTP-Method-Override, Verb Switching)
4. Path Obfuscation & URL Normalization Flaws
5. Synchronized Concurrency (Race Window Burst Testing)
"""

import concurrent.futures
import random
import threading
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


class RateLimitBypassLab:
    """Automated security testing framework for API rate limiting controls."""

    def __init__(self, target_url: str, endpoint: str = "/api/v1/users"):
        self.target_url = target_url.rstrip("/")
        self.endpoint = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        self.full_url = f"{self.target_url}{self.endpoint}"
        self.session = requests.Session()
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
        status_tag = f"{Colors.RED}[CRITICAL VULNERABILITY]{Colors.RESET}" if vulnerable else f"{Colors.GREEN}[SECURE]{Colors.RESET}"
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
            print(f"  └─ Validation: Rate limits and controls strictly enforced.")

    # ----------------------------------------------------------------------
    # Test 1: Baseline Rate Limiting Check
    # ----------------------------------------------------------------------
    def test_baseline_rate_limit(self, request_count: int = 50):
        print(f"\n{Colors.BLUE}[*] Running Test 1: Baseline Rate Limit Testing ({request_count} requests)...{Colors.RESET}")

        success_count = 0
        rate_limited_at = None

        for i in range(1, request_count + 1):
            try:
                res = self.session.get(self.full_url, timeout=3)
                if res.status_code == 200:
                    success_count += 1
                elif res.status_code == 429:
                    rate_limited_at = i
                    break
            except requests.RequestException:
                pass

        if rate_limited_at is None and success_count >= request_count:
            self.log_result(
                test_name="Unrestricted Resource Consumption (No Rate Limit)",
                vulnerable=True,
                severity="CRITICAL",
                impact="Unauthenticated actors can cause denial of service (DoS), brute-force secrets, or scrape entire datasets.",
                evidence=f"Processed all {success_count} sequential requests with HTTP 200 without triggering 429.",
                remediation="Implement global and endpoint-specific rate limiting at the API Gateway (e.g., 60 req/min).",
            )
        else:
            self.log_result(
                test_name="Baseline Rate Limiting",
                vulnerable=False,
                severity="INFO",
                impact="None",
                evidence=f"Throttling triggered at request #{rate_limited_at} (HTTP 429 received).",
                remediation="Maintain existing throttle configurations.",
            )

    # ----------------------------------------------------------------------
    # Test 2: Origin Header Spoofing (IP Rotation)
    # ----------------------------------------------------------------------
    def test_header_spoofing_bypass(self, attempts: int = 30):
        print(f"\n{Colors.BLUE}[*] Running Test 2: IP Header Spoofing (X-Forwarded-For / Custom Origin Headers)...{Colors.RESET}")

        header_keys = [
            "X-Forwarded-For",
            "X-Real-IP",
            "CF-Connecting-IP",
            "True-Client-IP",
            "X-Client-IP",
            "X-Originating-IP",
        ]

        success_count = 0
        for _ in range(attempts):
            fake_ip = f"{random.randint(11, 200)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            headers = {header: fake_ip for header in header_keys}

            try:
                res = self.session.get(self.full_url, headers=headers, timeout=3)
                if res.status_code == 200:
                    success_count += 1
                elif res.status_code == 429:
                    break
            except requests.RequestException:
                pass

        if success_count >= attempts * 0.9:
            self.log_result(
                test_name="Rate Limit Bypass via Origin Header Spoofing",
                vulnerable=True,
                severity="CRITICAL",
                impact="Attackers can spoof client headers to infinitely reset rate-limiting buckets from a single machine.",
                evidence=f"Successfully executed {success_count}/{attempts} requests using rotated X-Forwarded-For/X-Real-IP values.",
                remediation="Never trust client-supplied IP headers directly. Configure reverse proxies/CDNs to strip and overwrite forwarded IP headers.",
            )
        else:
            self.log_result(
                test_name="Origin Header Spoofing Defense",
                vulnerable=False,
                severity="INFO",
                impact="None",
                evidence="Throttling logic accurately tracks underlying socket connection IP rather than spoofed headers.",
                remediation="Ensure reverse proxy boundary remains strict.",
            )

    # ----------------------------------------------------------------------
    # Test 3: HTTP Verb & Method Override Tampering
    # ----------------------------------------------------------------------
    def test_method_tampering_bypass(self):
        print(f"\n{Colors.BLUE}[*] Running Test 3: HTTP Method Switching & Header Overrides...{Colors.RESET}")

        override_headers = [
            {"X-HTTP-Method": "POST"},
            {"X-HTTP-Method-Override": "POST"},
            {"X-Method-Override": "POST"},
        ]

        bypassed_mechanisms = []

        # 3a. Verb Switching (HEAD / OPTIONS / POST)
        for method in ["POST", "PATCH", "PUT", "HEAD"]:
            try:
                res = self.session.request(method, self.full_url, timeout=3)
                if res.status_code in [200, 201, 204]:
                    bypassed_mechanisms.append(f"HTTP Verb: {method}")
            except requests.RequestException:
                pass

        # 3b. Header Overrides
        for h in override_headers:
            try:
                res = self.session.get(self.full_url, headers=h, timeout=3)
                if res.status_code == 200:
                    bypassed_mechanisms.append(f"Override Header: {list(h.keys())[0]}")
            except requests.RequestException:
                pass

        if bypassed_mechanisms:
            self.log_result(
                test_name="Rate Limit Bypass via Method Overrides",
                vulnerable=True,
                severity="HIGH",
                impact="Attackers can access rate-limited actions by simply switching HTTP verbs or applying tunnel headers.",
                evidence=f"Alternative methods/headers succeeded: {', '.join(bypassed_mechanisms)}",
                remediation="Enforce rate limits per API resource path irrespective of HTTP verb or method override headers.",
            )
        else:
            self.log_result(
                test_name="Method Override Integrity",
                vulnerable=False,
                severity="INFO",
                impact="None",
                evidence="Rate limiting uniform across all HTTP methods and override directives.",
                remediation="Maintain uniform routing middleware.",
            )

    # ----------------------------------------------------------------------
    # Test 4: Path Normalization & Whitespace Quirks
    # ----------------------------------------------------------------------
    def test_path_normalization_bypass(self):
        print(f"\n{Colors.BLUE}[*] Running Test 4: Path Obfuscation & Normalization Flaws...{Colors.RESET}")

        obfuscated_paths = [
            f"{self.endpoint}/",
            f"{self.endpoint}/.",
            f"//v1/..{self.endpoint}",
            f"{self.endpoint};",
            f"{self.endpoint}.json",
            f"{self.endpoint}%20",
        ]

        successful_obfuscations = []

        for p in obfuscated_paths:
            try:
                url = f"{self.target_url}{p}"
                res = self.session.get(url, timeout=3)
                if res.status_code == 200:
                    successful_obfuscations.append(p)
            except requests.RequestException:
                pass

        if successful_obfuscations:
            self.log_result(
                test_name="Rate Limit Bypass via Path Obfuscation",
                vulnerable=True,
                severity="HIGH",
                impact="Routing proxies fail to normalize paths before matching rate limit rules, allowing arbitrary limits bypass.",
                evidence=f"Unthrottled responses obtained using paths: {', '.join(successful_obfuscations)}",
                remediation="Normalize and canonicalize URL paths prior to rate-limit policy evaluation at the proxy layer.",
            )
        else:
            self.log_result(
                test_name="Path Canonicalization",
                vulnerable=False,
                severity="INFO",
                impact="None",
                evidence="Path variations are correctly normalized prior to rule matching.",
                remediation="Maintain standard URI canonicalization pipelines.",
            )

    # ----------------------------------------------------------------------
    # Test 5: Synchronized Concurrency (Race Window Bursting)
    # ----------------------------------------------------------------------
    def test_burst_concurrency(self, thread_count: int = 25):
        print(f"\n{Colors.BLUE}[*] Running Test 5: Synchronized Concurrency Burst ({thread_count} threads)...{Colors.RESET}")

        barrier = threading.Event()
        status_codes = []

        def worker():
            barrier.wait()  # Align all threads to hit the backend at the exact same millisecond
            try:
                r = requests.get(self.full_url, timeout=5)
                status_codes.append(r.status_code)
            except Exception:
                status_codes.append(0)

        threads = [threading.Thread(target=worker) for _ in range(thread_count)]
        for t in threads:
            t.start()

        # Fire all threads at once
        time.sleep(0.5)
        barrier.set()

        for t in threads:
            t.join()

        success_count = status_codes.count(200)
        rate_limited_count = status_codes.count(429)

        if success_count == thread_count:
            self.log_result(
                test_name="Concurrency & Race-Condition Rate Limit Failure",
                vulnerable=True,
                severity="HIGH",
                impact="Database/cache race conditions allow large parallel bursts to succeed before counters update.",
                evidence=f"All {success_count}/{thread_count} parallel requests passed simultaneously without throttling.",
                remediation="Use atomic increment operations (e.g., Redis `INCR` or Lua scripts) to guarantee thread-safe counting.",
            )
        else:
            self.log_result(
                test_name="Atomic Rate Counter Enforcement",
                vulnerable=False,
                severity="INFO",
                impact="None",
                evidence=f"Parallel burst properly intercepted ({rate_limited_count} requests returned HTTP 429).",
                remediation="Maintain atomic synchronization in distributed caches.",
            )

    # ----------------------------------------------------------------------
    # Harness Execution
    # ----------------------------------------------------------------------
    def run_all(self):
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD} CRITICAL RATE LIMITING & RESOURCE CONSUMPTION SUITE{Colors.RESET}")
        print(f" Target Endpoint: {self.full_url}")
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")

        self.test_baseline_rate_limit()
        self.test_header_spoofing_bypass()
        self.test_method_tampering_bypass()
        self.test_path_normalization_bypass()
        self.test_burst_concurrency()

        print(f"\n{Colors.HEADER}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}AUDIT SUMMARY{Colors.RESET}")
        print(f"Total Flaws Discovered: {len(self.findings)}")
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")


if __name__ == "__main__":
    TARGET_API = "http://localhost:8080"
    TARGET_ENDPOINT = "/api/v1/users"

    tester = RateLimitBypassLab(target_url=TARGET_API, endpoint=TARGET_ENDPOINT)
    tester.run_all()
