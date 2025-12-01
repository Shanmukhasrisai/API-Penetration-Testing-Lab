#!/usr/bin/env python3
"""
Critical Lab: Sensitive Data Exposure and Authentication Bypass
Real-world scenario: Testing for exposed secrets, credentials, and weak authentication

This lab covers:
- Exposed API keys and secrets in responses
- Authentication bypass techniques
- Insecure direct object references (IDOR)
- Credential stuffing and brute force attacks
- JWT manipulation and signature bypass
- API key extraction and reuse
- Exposed internal APIs
"""

import requests
import json
import re
from typing import Dict, List, Optional, Tuple
import hashlib
import jwt
import base64
from datetime import datetime, timedelta

class SensitiveDataExposureLab:
    """
    Lab for testing sensitive data exposure vulnerabilities
    """
    
    def __init__(self, target_url: str, test_username: str = "admin", test_password: str = "password"):
        self.target_url = target_url
        self.test_username = test_username
        self.test_password = test_password
        self.session = requests.Session()
        self.vulnerabilities = []
        self.secrets_found = []
    
    def test_exposed_api_keys(self, endpoint: str) -> Dict:
        """
        Test 1: API responses containing exposed keys/secrets
        Vulnerability: Sensitive data exposed in API responses
        """
        print(f"[*] Testing for exposed API keys/secrets on {endpoint}...")
        
        sensitive_patterns = {
            r'api[_-]?key["\'\ ]?:?["\']?([a-zA-Z0-9_-]{20,})': 'API Key',
            r'secret[_-]?key["\'\ ]?:?["\']?([a-zA-Z0-9_-]{20,})': 'Secret Key',
            r'access[_-]?token["\'\ ]?:?["\']?([a-zA-Z0-9._-]{20,})': 'Access Token',
            r'aws[_-]?secret[_-]?access[_-]?key["\'\ ]?:?["\']?([A-Za-z0-9/+]{40})': 'AWS Secret',
            r'password["\'\ ]?:?["\']?([a-zA-Z0-9!@#$%^&*]{8,})': 'Password',
            r'token["\'\ ]?:?["\']?([a-zA-Z0-9._-]{32,})': 'Token',
        }
        
        try:
            response = self.session.get(f"{self.target_url}{endpoint}", timeout=5)
            response_text = response.text
            response_json = {}
            
            try:
                response_json = response.json()
                response_text = json.dumps(response_json, indent=2)
            except:
                pass
            
            for pattern, key_type in sensitive_patterns.items():
                matches = re.findall(pattern, response_text, re.IGNORECASE)
                if matches:
                    for match in matches:
                        self.secrets_found.append({"type": key_type, "value": match[:20] + "..."})
                        self.vulnerabilities.append(f"Exposed {key_type}: {match[:30]}...")
                    return {"vulnerable": True, "severity": "CRITICAL", "type": key_type, "matches": len(matches)}
        except Exception as e:
            print(f"[!] Error: {e}")
        
        return {"vulnerable": False}
    
    def test_idor_vulnerability(self, endpoint_template: str) -> Dict:
        """
        Test 2: Insecure Direct Object References
        Vulnerability: Access to objects by ID without authorization checks
        """
        print(f"[*] Testing for IDOR vulnerability on {endpoint_template}...")
        
        # Test with different user IDs
        for user_id in [1, 2, 100, 999, "admin", "root"]:
            try:
                endpoint = endpoint_template.replace("{id}", str(user_id))
                response = self.session.get(f"{self.target_url}{endpoint}", timeout=5)
                
                if response.status_code == 200:
                    # Check if we got different user data
                    if f'{user_id}' in response.text or any(indicator in response.text for indicator in ['user', 'email', 'password']):
                        self.vulnerabilities.append(f"IDOR - Unauthorized access to user {user_id}")
                        return {"vulnerable": True, "severity": "CRITICAL", "user_id": user_id}
            except Exception as e:
                pass
        
        return {"vulnerable": False}
    
    def test_weak_authentication(self, login_endpoint: str) -> Dict:
        """
        Test 3: Weak or missing authentication
        Vulnerability: Resources accessible without proper authentication
        """
        print(f"[*] Testing for weak authentication on {login_endpoint}...")
        
        # Test 3a: No authentication required
        try:
            response = self.session.get(f"{self.target_url}{login_endpoint}", timeout=5)
            if response.status_code == 200 and len(response.text) > 100:
                self.vulnerabilities.append("No Authentication Required - Open Access")
                return {"vulnerable": True, "severity": "CRITICAL", "method": "no_auth"}
        except:
            pass
        
        # Test 3b: Default credentials
        default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("test", "test"),
            ("user", "password"),
        ]
        
        for username, password in default_creds:
            try:
                data = {"username": username, "password": password}
                response = self.session.post(f"{self.target_url}{login_endpoint}", json=data, timeout=5)
                
                if response.status_code == 200 and any(token in response.text.lower() for token in ['token', 'success', 'authenticated']):
                    self.vulnerabilities.append(f"Default Credentials Found: {username}:{password}")
                    return {"vulnerable": True, "severity": "CRITICAL", "creds": f"{username}:{password}"}
            except:
                pass
        
        return {"vulnerable": False}
    
    def test_jwt_vulnerabilities(self, token: str = None) -> Dict:
        """
        Test 4: JWT signature bypass and manipulation
        Vulnerability: Weak JWT signing or no verification
        """
        print("[*] Testing JWT vulnerabilities...")
        
        if not token:
            token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0."
        
        try:
            # Try to decode without verification
            parts = token.split('.')
            if len(parts) == 3:
                # Decode payload
                payload_encoded = parts[1]
                padding = 4 - len(payload_encoded) % 4
                if padding != 4:
                    payload_encoded += '=' * padding
                
                payload_decoded = base64.urlsafe_b64decode(payload_encoded)
                claims = json.loads(payload_decoded)
                
                # Check for weak algorithms
                header_encoded = parts[0]
                padding = 4 - len(header_encoded) % 4
                if padding != 4:
                    header_encoded += '=' * padding
                
                header_decoded = base64.urlsafe_b64decode(header_encoded)
                header = json.loads(header_decoded)
                
                if header.get('alg') == 'none':
                    self.vulnerabilities.append("JWT with 'none' algorithm")
                    return {"vulnerable": True, "severity": "CRITICAL", "issue": "none_algorithm"}
                
                if 'HS256' in header.get('alg', '') and not claims.get('exp'):
                    self.vulnerabilities.append("JWT without expiration")
                    return {"vulnerable": True, "severity": "HIGH", "issue": "no_expiration"}
        except Exception as e:
            pass
        
        return {"vulnerable": False}
    
    def test_brute_force_endpoint(self, endpoint: str, param: str) -> Dict:
        """
        Test 5: Brute force vulnerability
        Vulnerability: No rate limiting on authentication endpoint
        """
        print(f"[*] Testing brute force resistance on {endpoint}...")
        
        # Try a few common passwords
        passwords = ["123456", "password", "123456789", "12345678", "password123"]
        
        for pwd in passwords:
            try:
                data = {param: "admin", "password": pwd}
                response = self.session.post(f"{self.target_url}{endpoint}", json=data, timeout=5)
                
                if response.status_code != 429:  # Not rate limited
                    if response.status_code == 200:
                        self.vulnerabilities.append(f"Credentials cracked: admin:{pwd}")
                        return {"vulnerable": True, "severity": "CRITICAL", "password": pwd}
            except:
                pass
        
        return {"vulnerable": False}
    
    def test_exposed_internal_apis(self) -> Dict:
        """
        Test 6: Internal APIs exposed to internet
        Vulnerability: Administrative or internal endpoints accessible
        """
        print("[*] Testing for exposed internal APIs...")
        
        internal_endpoints = [
            "/api/admin",
            "/api/internal",
            "/api/debug",
            "/api/config",
            "/api/system",
            "/admin",
            "/internal",
            "/api/health",
            "/.well-known/openid-configuration",
            "/actuator",
        ]
        
        for endpoint in internal_endpoints:
            try:
                response = self.session.get(f"{self.target_url}{endpoint}", timeout=5)
                if response.status_code == 200:
                    self.vulnerabilities.append(f"Exposed Internal API: {endpoint}")
                    return {"vulnerable": True, "severity": "HIGH", "endpoint": endpoint}
            except:
                pass
        
        return {"vulnerable": False}
    
    def test_information_disclosure(self, endpoint: str) -> Dict:
        """
        Test 7: Information disclosure through error messages
        Vulnerability: Detailed error messages revealing system info
        """
        print(f"[*] Testing for information disclosure on {endpoint}...")
        
        # Send malformed request
        try:
            response = self.session.get(f"{self.target_url}{endpoint}", params={"id": "' OR 1=1--"}, timeout=5)
            
            # Check for sensitive information in error
            sensitive_info = ['stack trace', 'traceback', 'mysql', 'postgresql', 'exception', 'line ', 'file ']
            
            for info in sensitive_info:
                if info in response.text.lower():
                    self.vulnerabilities.append(f"Information Disclosure: {info} revealed")
                    return {"vulnerable": True, "severity": "MEDIUM", "info_type": info}
        except Exception as e:
            pass
        
        return {"vulnerable": False}
    
    def run_all_tests(self) -> None:
        """
        Execute all sensitive data exposure tests
        """
        print("\n[+] Starting Critical Sensitive Data Exposure Lab")
        print(f"[+] Target: {self.target_url}")
        print("\n" + "="*60 + "\n")
        
        # Run all tests
        self.test_exposed_api_keys("/api/user/profile")
        self.test_idor_vulnerability("/api/users/{id}")
        self.test_weak_authentication("/api/login")
        self.test_jwt_vulnerabilities()
        self.test_brute_force_endpoint("/api/login", "username")
        self.test_exposed_internal_apis()
        self.test_information_disclosure("/api/search")
        
        print("\n" + "="*60)
        print("[+] Sensitive Data Exposure Testing Complete")
        print(f"[+] Vulnerabilities Found: {len(self.vulnerabilities)}")
        print(f"[+] Secrets Found: {len(self.secrets_found)}")
        print("\n" + "="*60 + "\n")
        
        for idx, vuln in enumerate(self.vulnerabilities, 1):
            print(f"[{idx}] {vuln}")


if __name__ == "__main__":
    target = "http://api.vulnerable-app.local:8080"
    lab = SensitiveDataExposureLab(target)
    lab.run_all_tests()
