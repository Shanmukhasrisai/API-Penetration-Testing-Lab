#!/usr/bin/env python3
"""
API Penetration Testing Lab - Beginner Lab 1: API Basics

Topics: Understanding REST APIs, HTTP methods, requests/responses, status codes, auth headers
Difficulty: Beginner
"""

import requests
import json
import sys
from typing import Dict, Any

# Target API base endpoint
DEFAULT_BASE_URL = "http://127.0.0.1:5000/api"


class APIBasicsLab:
    """Interactive educational client for learning API fundamentals."""
    
    def __init__(self, base_url: str = DEFAULT_BASE_URL):
        self.session = requests.Session()
        self.base_url = base_url.rstrip('/')
        self.offline_mode = False

    def _build_url(self, endpoint: str) -> str:
        """Properly appends endpoint paths without stripping subdirectories."""
        endpoint = endpoint.lstrip('/')
        return f"{self.base_url}/{endpoint}"

    def check_connectivity(self) -> bool:
        """Verifies if the target API server is online."""
        try:
            resp = self.session.get(self.base_url, timeout=2)
            return True
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            print(f"[!] Warning: Target server at '{self.base_url}' is not reachable.")
            print("[*] Switching to Simulated Lab Mode for offline learning.\n")
            self.offline_mode = True
            return False

    # EXERCISE 1: Making basic API requests
    def exercise_1_basic_requests(self):
        print("\n" + "="*50)
        print("Exercise 1: Basic API Requests (GET & Response Parsing)")
        print("="*50)
        
        # Task 1: GET request to /users
        print("\n[Task 1] Sending GET request to /users...")
        url = self._build_url("users")
        
        if not self.offline_mode:
            try:
                response = self.session.get(url, timeout=5)
                print(f"Status Code: {response.status_code}")
                print(f"Response Headers: {dict(list(response.headers.items())[:3])}")
                print(f"Response Body (sample): {response.text[:180]}")
            except Exception as e:
                print(f"Request error: {e}")
        else:
            print("HTTP/1.1 200 OK")
            print("Content-Type: application/json")
            print('{"status": "success", "users": [{"id": 1, "username": "admin"}, {"id": 2, "username": "guest"}]}')

        # Task 2: GET request to /products
        print("\n[Task 2] Sending GET request to /products...")
        url = self._build_url("products")
        if not self.offline_mode:
            try:
                response = self.session.get(url, timeout=5)
                print(f"Status Code: {response.status_code}")
                if response.status_code == 200:
                    data = response.json()
                    print(f"Parsed JSON keys: {list(data.keys()) if isinstance(data, dict) else 'List'}")
            except Exception as e:
                print(f"Request error: {e}")
        else:
            print("HTTP/1.1 200 OK")
            print('{"products": [{"id": 101, "name": "Security Scanner", "price": 299}]}')

    # EXERCISE 2: HTTP methods and parameter passing
    def exercise_2_http_methods(self):
        print("\n" + "="*50)
        print("Exercise 2: HTTP Methods (Query Params vs JSON Body)")
        print("="*50)
        
        # Task 1: GET with Query Parameters
        print("\n[Task 1] GET /users with Query Parameters (?filter=active&limit=5)...")
        params = {"filter": "active", "limit": 5}
        url = self._build_url("users")
        
        if not self.offline_mode:
            try:
                response = self.session.get(url, params=params, timeout=5)
                print(f"Resolved URL: {response.url}")
                print(f"Status Code: {response.status_code}")
            except Exception as e:
                print(f"Request error: {e}")
        else:
            print(f"Resolved URL: {url}?filter=active&limit=5")
            print("Status Code: 200 OK")

        # Task 2: POST with JSON body
        print("\n[Task 2] POST /users with JSON Payload...")
        payload = {"username": "new_researcher", "email": "researcher@lab.local", "role": "tester"}
        
        if not self.offline_mode:
            try:
                response = self.session.post(url, json=payload, timeout=5)
                print(f"Status Code: {response.status_code}")
                print(f"Response Body: {response.text[:180]}")
            except Exception as e:
                print(f"Request error: {e}")
        else:
            print("Request Body: " + json.dumps(payload))
            print("HTTP/1.1 201 Created")
            print('{"message": "User created successfully", "user_id": 3}')

    # EXERCISE 3: Understanding status codes
    def exercise_3_status_codes(self):
        print("\n" + "="*50)
        print("Exercise 3: HTTP Status Codes")
        print("="*50)
        
        # 404 Endpoint check
        print("\n[Task 1] Triggering 404 Not Found (/nonexistent-route)...")
        url = self._build_url("nonexistent-route")
        
        if not self.offline_mode:
            try:
                response = self.session.get(url, timeout=5)
                print(f"Result: {response.status_code} {response.reason}")
            except Exception as e:
                print(f"Request error: {e}")
        else:
            print("Result: 404 Not Found")

    # EXERCISE 4: API authentication basics
    def exercise_4_authentication(self):
        print("\n" + "="*50)
        print("Exercise 4: Authentication Headers (API Keys & Bearer Tokens)")
        print("="*50)
        
        # API Key Header
        print("\n[Task 1] Testing custom header 'X-API-Key'...")
        headers = {"X-API-Key": "lab_secret_key_beginner_123"}
        url = self._build_url("protected/users")
        
        if not self.offline_mode:
            try:
                response = self.session.get(url, headers=headers, timeout=5)
                print(f"Status Code: {response.status_code}")
            except Exception as e:
                print(f"Request error: {e}")
        else:
            print("Headers Sent: {'X-API-Key': 'lab_secret_key_beginner_123'}")
            print("HTTP/1.1 200 OK - Access Granted")

        # Bearer Token Header
        print("\n[Task 2] Testing Bearer Token in 'Authorization' header...")
        headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummyPayload.signature"}
        if not self.offline_mode:
            try:
                response = self.session.get(url, headers=headers, timeout=5)
                print(f"Status Code: {response.status_code}")
            except Exception as e:
                print(f"Request error: {e}")
        else:
            print("Headers Sent: {'Authorization': 'Bearer eyJhbGciOiJIUz...'}")
            print("HTTP/1.1 200 OK - Authorized Session")

    # EXERCISE 5: Endpoint Discovery
    def exercise_5_endpoint_discovery(self):
        print("\n" + "="*50)
        print("Exercise 5: API Surface & Documentation Reconnaissance")
        print("="*50)
        
        common_endpoints = ["users", "products", "orders", "docs", "swagger", "openapi.json"]
        print(f"Scanning target for common endpoints: {common_endpoints}")
        
        for ep in common_endpoints:
            url = self._build_url(ep)
            if not self.offline_mode:
                try:
                    resp = self.session.head(url, timeout=2)
                    if resp.status_code != 404:
                        print(f"  [+] Discovered: /{ep} (Status: {resp.status_code})")
                except Exception:
                    pass
            else:
                print(f"  [+] Discovered: /{ep} (Status: 200 OK)")

    def run_all(self):
        print("="*60)
        print("  API PENETRATION TESTING LAB: BEGINNER LEVEL 1  ")
        print("="*60)
        self.check_connectivity()
        self.exercise_1_basic_requests()
        self.exercise_2_http_methods()
        self.exercise_3_status_codes()
        self.exercise_4_authentication()
        self.exercise_5_endpoint_discovery()
        print("\n" + "="*60)
        print("  Beginner Lab 1 Complete! Move on to Lab 2.")
        print("="*60 + "\n")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BASE_URL
    lab = APIBasicsLab(base_url=target)
    lab.run_all()
