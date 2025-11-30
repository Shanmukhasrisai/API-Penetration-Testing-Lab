#!/usr/bin/env python3
"""
API Penetration Testing Lab - Beginner Lab 3: Reconnaissance & Information Gathering

Topics: API discovery, endpoint enumeration, documentation analysis, fuzzing basics
Difficulty: Beginner
"""

import requests
import json
from urllib.parse import urljoin, urlencode
from typing import List, Dict

BASE_URL = "http://localhost:5000"

class ReconnaissanceLab:
    """Lab for API reconnaissance and information gathering"""
    
    def __init__(self):
        self.session = requests.Session()
        self.base_url = BASE_URL
        self.discovered_endpoints = []
    
    # EXERCISE 1: Finding API Documentation
    def exercise_1_find_api_docs(self):
        """
        Exercise 1: Locate API documentation
        
        Learning Goals:
        - Find Swagger/OpenAPI documentation
        - Locate API schemas
        - Discover API versioning
        
        Tasks:
        1. Test common documentation paths
        2. Analyze documentation
        """
        print("\n=== Exercise 1: Finding API Documentation ===")
        
        doc_endpoints = [
            "/swagger",
            "/swagger.json",
            "/swagger-ui.html",
            "/swagger/index.html",
            "/api/docs",
            "/api/v1/docs",
            "/docs",
            "/openapi.json",
            "/openapi.yaml",
            "/.openapi",
            "/api-docs",
            "/graphql",
        ]
        
        print("\n[Task 1] Testing common documentation endpoints...")
        for endpoint in doc_endpoints:
            try:
                response = self.session.get(urljoin(self.base_url, endpoint))
                if response.status_code == 200:
                    print(f"[+] Found documentation: {endpoint}")
                    if 'swagger' in response.text.lower() or 'openapi' in response.text.lower():
                        print(f"    Type: Swagger/OpenAPI")
                    self.discovered_endpoints.append(endpoint)
            except Exception:
                pass
    
    # EXERCISE 2: Basic Endpoint Enumeration
    def exercise_2_endpoint_enumeration(self):
        """
        Exercise 2: Enumerate API endpoints
        
        Learning Goals:
        - Discover available endpoints
        - Understand endpoint structure
        - Identify resource paths
        
        Tasks:
        1. Test common endpoints
        2. Test with different methods
        3. Identify patterns
        """
        print("\n=== Exercise 2: Endpoint Enumeration ===")
        
        common_resources = [
            "users",
            "products",
            "orders",
            "invoices",
            "customers",
            "accounts",
            "transactions",
            "settings",
            "profile",
            "admin",
        ]
        
        api_prefixes = [
            "/api",
            "/api/v1",
            "/api/v2",
            "/v1",
            "/v2",
            "",
        ]
        
        print("\n[Task 1] Testing common endpoint patterns...")
        for prefix in api_prefixes:
            for resource in common_resources:
                endpoint = f"{prefix}/{resource}"
                try:
                    response = self.session.get(urljoin(self.base_url, endpoint), timeout=2)
                    if response.status_code != 404:
                        print(f"[+] Found: {endpoint} (Status: {response.status_code})")
                        self.discovered_endpoints.append(endpoint)
                except Exception:
                    pass
    
    # EXERCISE 3: HTTP Method Testing
    def exercise_3_http_methods(self):
        """
        Exercise 3: Test different HTTP methods on endpoints
        
        Learning Goals:
        - Understand HTTP method implementation
        - Identify method-specific vulnerabilities
        - Test CRUD operations
        
        Tasks:
        1. Test GET, POST, PUT, DELETE
        2. Identify supported methods
        """
        print("\n=== Exercise 3: HTTP Method Testing ===")
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        test_endpoints = ['/api/users', '/api/products', '/api/orders']
        
        print("\n[Task 1] Testing HTTP methods on discovered endpoints...")
        for endpoint in test_endpoints:
            print(f"\nTesting endpoint: {endpoint}")
            for method in methods:
                try:
                    if method == 'GET':
                        response = self.session.get(urljoin(self.base_url, endpoint))
                    elif method == 'POST':
                        response = self.session.post(urljoin(self.base_url, endpoint), json={})
                    elif method == 'PUT':
                        response = self.session.put(urljoin(self.base_url, endpoint), json={})
                    elif method == 'DELETE':
                        response = self.session.delete(urljoin(self.base_url, endpoint))
                    elif method == 'PATCH':
                        response = self.session.patch(urljoin(self.base_url, endpoint), json={})
                    elif method == 'OPTIONS':
                        response = self.session.options(urljoin(self.base_url, endpoint))
                    
                    if response.status_code != 404 and response.status_code != 405:
                        print(f"  [{method}]: {response.status_code}")
                except Exception:
                    pass
    
    # EXERCISE 4: Parameter Discovery
    def exercise_4_parameter_discovery(self):
        """
        Exercise 4: Discover API parameters
        
        Learning Goals:
        - Identify query parameters
        - Discover required vs optional parameters
        - Test parameter handling
        
        Tasks:
        1. Common parameter names
        2. Test parameter acceptance
        """
        print("\n=== Exercise 4: Parameter Discovery ===")
        
        common_params = [
            "id", "user_id", "product_id", "order_id",
            "page", "limit", "offset", "sort", "filter", "search",
            "api_key", "token", "key", "secret",
            "format", "type", "lang", "version",
        ]
        
        print("\n[Task 1] Testing parameter acceptance...")
        endpoint = "/api/users"
        
        for param in common_params[:5]:  # Test first 5 params
            try:
                params = {param: "test"}
                response = self.session.get(
                    urljoin(self.base_url, endpoint),
                    params=params
                )
                if response.status_code == 200:
                    print(f"  [+] Parameter accepted: {param}")
            except Exception:
                pass
    
    # EXERCISE 5: Version Detection
    def exercise_5_version_detection(self):
        """
        Exercise 5: Detect API versions
        
        Learning Goals:
        - Identify API versions
        - Understand version differences
        - Find deprecated versions
        
        Tasks:
        1. Test multiple versions
        2. Compare responses
        """
        print("\n=== Exercise 5: API Version Detection ===")
        
        version_patterns = [
            "/api/users",
            "/api/v1/users",
            "/api/v2/users",
            "/api/v3/users",
            "/v1/users",
            "/v2/users",
            "/v3/users",
        ]
        
        print("\n[Task 1] Testing different API versions...")
        for endpoint in version_patterns:
            try:
                response = self.session.get(urljoin(self.base_url, endpoint))
                if response.status_code != 404:
                    print(f"[+] Version found: {endpoint} (Status: {response.status_code})")
                    self.discovered_endpoints.append(endpoint)
            except Exception:
                pass
    
    # EXERCISE 6: Analyzing Responses
    def exercise_6_response_patterns(self):
        """
        Exercise 6: Identify response patterns
        
        Learning Goals:
        - Understand API response formats
        - Identify data structures
        - Recognize sensitive information patterns
        
        Tasks:
        1. Analyze response format
        2. Identify data patterns
        """
        print("\n=== Exercise 6: Response Pattern Analysis ===")
        
        print("\n[Task 1] Analyzing response patterns...")
        endpoints_to_analyze = [
            "/api/users",
            "/api/products",
            "/api/orders",
        ]
        
        for endpoint in endpoints_to_analyze:
            try:
                response = self.session.get(urljoin(self.base_url, endpoint))
                if response.status_code == 200:
                    print(f"\nEndpoint: {endpoint}")
                    try:
                        data = response.json()
                        print(f"  Format: JSON")
                        if isinstance(data, dict):
                            print(f"  Root type: Object")
                            print(f"  Keys: {list(data.keys())[:5]}")
                        elif isinstance(data, list):
                            print(f"  Root type: Array")
                            if data and isinstance(data[0], dict):
                                print(f"  Item keys: {list(data[0].keys())[:5]}")
                    except:
                        print(f"  Format: Not JSON")
            except Exception:
                pass
    
    # EXERCISE 7: Testing HTTP Headers
    def exercise_7_header_analysis(self):
        """
        Exercise 7: Analyze important HTTP headers
        
        Learning Goals:
        - Identify important headers
        - Recognize security headers
        - Understand header vulnerabilities
        
        Tasks:
        1. Analyze response headers
        2. Check for missing security headers
        """
        print("\n=== Exercise 7: HTTP Header Analysis ===")
        
        print("\n[Task 1] Analyzing response headers...")
        try:
            response = self.session.get(urljoin(self.base_url, "/api/users"))
            
            important_headers = [
                "Server",
                "X-Powered-By",
                "Content-Type",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "Access-Control-Allow-Origin",
                "X-API-Version",
            ]
            
            print("\nHeaders present:")
            for header in important_headers:
                if header in response.headers:
                    print(f"  {header}: {response.headers[header]}")
        except Exception as e:
            print(f"Error: {e}")
    
    def print_summary(self):
        """Print reconnaissance summary"""
        print("\n" + "="*60)
        print("Reconnaissance Summary")
        print("="*60)
        print(f"\nDiscovered endpoints: {len(set(self.discovered_endpoints))}")
        for endpoint in sorted(set(self.discovered_endpoints))[:10]:
            print(f"  - {endpoint}")
        
        if len(set(self.discovered_endpoints)) > 10:
            print(f"  ... and {len(set(self.discovered_endpoints)) - 10} more")
    
    def run_all_exercises(self):
        """Run all exercises"""
        print("\n" + "="*60)
        print("API Penetration Testing Lab - Beginner Lab 3")
        print("Reconnaissance & Information Gathering")
        print("="*60)
        
        self.exercise_1_find_api_docs()
        self.exercise_2_endpoint_enumeration()
        self.exercise_3_http_methods()
        self.exercise_4_parameter_discovery()
        self.exercise_5_version_detection()
        self.exercise_6_response_patterns()
        self.exercise_7_header_analysis()
        
        self.print_summary()
        
        print("\nNext Steps:")
        print("1. Document all discovered endpoints")
        print("2. Note parameter requirements")
        print("3. Compare different API versions")
        print("4. Move to Intermediate Labs: JWT and Authentication Attacks")

if __name__ == "__main__":
    try:
        lab = ReconnaissanceLab()
        lab.run_all_exercises()
    except KeyboardInterrupt:
        print("\n\nLab interrupted by user.")
    except Exception as e:
        print(f"\nLab error: {e}")
