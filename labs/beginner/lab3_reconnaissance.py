#!/usr/bin/env python3
"""
API Penetration Testing Lab - Beginner Lab 3: Reconnaissance & Information Gathering

Topics: API discovery, endpoint enumeration, documentation analysis, method fuzzing
Difficulty: Beginner
"""

import requests
import json
import sys
from typing import List, Dict

DEFAULT_BASE_URL = "http://127.0.0.1:5000"


class ReconnaissanceLab:
    """Educational client for discovering API surfaces, documentation, and supported methods."""
    
    def __init__(self, base_url: str = DEFAULT_BASE_URL):
        self.session = requests.Session()
        self.base_url = base_url.rstrip('/')
        self.discovered_endpoints = []
        self.offline_mode = False

    def _build_url(self, endpoint: str) -> str:
        """Constructs target URLs cleanly."""
        endpoint = endpoint.lstrip('/')
        return f"{self.base_url}/{endpoint}"

    def check_connectivity(self) -> bool:
        """Verifies if the lab API target is reachable."""
        try:
            self.session.get(self.base_url, timeout=2)
            return True
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            print(f"[!] Target at '{self.base_url}' is unreachable.")
            print("[*] Switching to Simulated Lab Mode for offline learning.\n")
            self.offline_mode = True
            return False

    # EXERCISE 1: Finding API Documentation
    def exercise_1_find_api_docs(self):
        print("\n" + "="*50)
        print("Exercise 1: Discovering API Documentation & Schemas")
        print("="*50)
        
        doc_endpoints = [
            "swagger",
            "swagger.json",
            "swagger-ui.html",
            "api/docs",
            "docs",
            "openapi.json",
            "openapi.yaml",
            "api-docs",
            "graphql"
        ]
        
        print("\n[Task 1] Fuzzing common documentation paths...")
        for ep in doc_endpoints:
            url = self._build_url(ep)
            if not self.offline_mode:
                try:
                    resp = self.session.get(url, timeout=3)
                    if resp.status_code == 200:
                        print(f"  [+] Found documentation: /{ep} (Status: 200)")
                        self.discovered_endpoints.append(f"/{ep}")
                except Exception:
                    pass
            else:
                if ep in ["swagger.json", "docs", "openapi.json"]:
                    print(f"  [+] Found documentation: /{ep} (Status: 200 - OpenAPI Specification)")
                    self.discovered_endpoints.append(f"/{ep}")

    # EXERCISE 2: Basic Endpoint Enumeration
    def exercise_2_endpoint_enumeration(self):
        print("\n" + "="*50)
        print("Exercise 2: API Resource Enumeration")
        print("="*50)
        
        common_resources = ["users", "products", "orders", "admin", "debug", "status"]
        api_prefixes = ["api", "api/v1", "api/v2"]
        
        print("\n[Task 1] Testing resource matrices across version prefixes...")
        for prefix in api_prefixes:
            for res in common_resources:
                target_path = f"{prefix}/{res}"
                url = self._build_url(target_path)
                
                if not self.offline_mode:
                    try:
                        resp = self.session.get(url, timeout=2)
                        if resp.status_code != 404:
                            print(f"  [+] Discovered: /{target_path} (Status: {resp.status_code})")
                            self.discovered_endpoints.append(f"/{target_path}")
                    except Exception:
                        pass
                else:
                    if res in ["users", "products", "status"]:
                        print(f"  [+] Discovered: /{target_path} (Status: 200)")
                        self.discovered_endpoints.append(f"/{target_path}")

    # EXERCISE 3: HTTP Method Fuzzing
    def exercise_3_http_methods(self):
        print("\n" + "="*50)
        print("Exercise 3: HTTP Method Fuzzing (OPTIONS / Verb Tampering)")
        print("="*50)
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
        test_endpoints = ['api/v1/users', 'api/v1/products']
        
        for ep in test_endpoints:
            print(f"\n[Testing Methods] Endpoint: /{ep}")
            url = self._build_url(ep)
            
            for method in methods:
                if not self.offline_mode:
                    try:
                        resp = self.session.request(method, url, json={}, timeout=3)
                        if resp.status_code not in [404, 405]:
                            print(f"  [{method}] -> Status: {resp.status_code}")
                    except Exception:
                        pass
                else:
                    status_map = {'GET': 200, 'POST': 201, 'PUT': 403, 'DELETE': 401, 'OPTIONS': 200}
                    print(f"  [{method}] -> Status: {status_map.get(method, 405)}")

    # EXERCISE 4: Header & Fingerprinting Analysis
    def exercise_4_header_analysis(self):
        print("\n" + "="*50)
        print("Exercise 4: Security Header & Server Fingerprinting")
        print("="*50)
        
        url = self._build_url("api/v1/users")
        important_headers = [
            "Server", "X-Powered-By", "Content-Type", 
            "Access-Control-Allow-Origin", "X-Content-Type-Options"
        ]
        
        print(f"\n[Task 1] Analyzing response headers from /{url.split('/')[-1]}...")
        if not self.offline_mode:
            try:
                resp = self.session.get(url, timeout=3)
                print("Observed headers:")
                for h in important_headers:
                    if h in resp.headers:
                        print(f"  * {h}: {resp.headers[h]}")
                    else:
                        print(f"  * [MISSING SECURITY HEADER] {h}")
            except Exception as e:
                print(f"  [x] Error: {e}")
        else:
            print("Observed headers:")
            print("  * Server: Werkzeug/Python 3.10")
            print("  * Content-Type: application/json")
            print("  * [MISSING SECURITY HEADER] Access-Control-Allow-Origin")
            print("  * [MISSING SECURITY HEADER] X-Content-Type-Options")

    def print_summary(self):
        print("\n" + "="*60)
        print("  RECONNAISSANCE SUMMARY")
        print("="*60)
        unique_eps = sorted(list(dict.fromkeys(self.discovered_endpoints)))
        print(f"Total Unique Endpoints Discovered: {len(unique_eps)}")
        for ep in unique_eps:
            print(f"  - {ep}")
        print("="*60)

    def run_all(self):
        print("="*60)
        print("  API PENETRATION TESTING LAB: BEGINNER LEVEL 3  ")
        print("="*60)
        self.check_connectivity()
        self.exercise_1_find_api_docs()
        self.exercise_2_endpoint_enumeration()
        self.exercise_3_http_methods()
        self.exercise_4_header_analysis()
        self.print_summary()


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BASE_URL
    lab = ReconnaissanceLab(base_url=target)
    lab.run_all()
