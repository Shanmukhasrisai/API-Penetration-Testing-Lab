#!/usr/bin/env python3
"""
API Penetration Testing Lab - Beginner Lab 1: API Basics

Topics: Understanding REST APIs, HTTP methods, requests/responses, status codes
Difficulty: Beginner
"""

import requests
import json
from urllib.parse import urljoin
from typing import Dict, Any

# Target API (vulnerable demo API)
BASE_URL = "http://localhost:5000/api"

class APIBasicsLab:
    """Lab for learning API fundamentals and reconnaissance"""
    
    def __init__(self):
        self.session = requests.Session()
        self.base_url = BASE_URL
    
    # EXERCISE 1: Making basic API requests
    def exercise_1_basic_requests(self):
        """
        Exercise 1: Make basic GET requests and analyze responses
        
        Learning Goals:
        - Understand GET vs POST requests
        - Analyze response status codes
        - Parse JSON responses
        
        Tasks:
        1. Make a GET request to /users endpoint
        2. Print the status code and response
        3. Make a GET request to /products endpoint
        4. Identify differences in responses
        """
        print("\n=== Exercise 1: Basic API Requests ===")
        
        # Task 1: GET request to /users
        print("\n[Task 1] Making GET request to /users...")
        try:
            response = self.session.get(urljoin(self.base_url, "/users"))
            print(f"Status Code: {response.status_code}")
            print(f"Response Headers: {dict(response.headers)}")
            print(f"Response Body: {response.text[:200]}")
        except Exception as e:
            print(f"Error: {e}")
        
        # Task 2: GET request to /products
        print("\n[Task 2] Making GET request to /products...")
        try:
            response = self.session.get(urljoin(self.base_url, "/products"))
            print(f"Status Code: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                print(f"Number of products: {len(data.get('products', []))}")
        except Exception as e:
            print(f"Error: {e}")
    
    # EXERCISE 2: HTTP methods and parameter passing
    def exercise_2_http_methods(self):
        """
        Exercise 2: Understand different HTTP methods
        
        Learning Goals:
        - Difference between GET and POST
        - Query parameters vs request body
        - Request headers importance
        
        Tasks:
        1. GET with query parameters
        2. POST with JSON body
        3. Analyze differences
        """
        print("\n=== Exercise 2: HTTP Methods ===")
        
        # Task 1: GET with query parameters
        print("\n[Task 1] GET with query parameters...")
        params = {"filter": "active", "limit": 10}
        try:
            response = self.session.get(
                urljoin(self.base_url, "/users"),
                params=params
            )
            print(f"URL: {response.url}")
            print(f"Status: {response.status_code}")
        except Exception as e:
            print(f"Error: {e}")
        
        # Task 2: POST with JSON body
        print("\n[Task 2] POST with JSON body...")
        payload = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "SecurePassword123"
        }
        try:
            response = self.session.post(
                urljoin(self.base_url, "/users"),
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            print(f"Status: {response.status_code}")
            print(f"Response: {response.text[:200]}")
        except Exception as e:
            print(f"Error: {e}")
    
    # EXERCISE 3: Understanding status codes
    def exercise_3_status_codes(self):
        """
        Exercise 3: Learn HTTP status codes
        
        Learning Goals:
        - 2xx (Success): 200 OK, 201 Created
        - 3xx (Redirect): 301, 302
        - 4xx (Client Error): 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found
        - 5xx (Server Error): 500, 503
        
        Tasks:
        1. Trigger various status codes
        2. Understand their meanings
        """
        print("\n=== Exercise 3: HTTP Status Codes ===")
        
        # 200 OK
        print("\n[Task 1] 200 OK - Successful request")
        try:
            response = self.session.get(urljoin(self.base_url, "/users"))
            print(f"Status: {response.status_code} - {response.reason}")
        except Exception as e:
            print(f"Error: {e}")
        
        # 400 Bad Request
        print("\n[Task 2] 400 Bad Request - Invalid parameters")
        try:
            response = self.session.get(
                urljoin(self.base_url, "/users"),
                params={"invalid_param": "test"}
            )
            print(f"Status: {response.status_code} - {response.reason}")
        except Exception as e:
            print(f"Error: {e}")
        
        # 404 Not Found
        print("\n[Task 3] 404 Not Found - Non-existent endpoint")
        try:
            response = self.session.get(urljoin(self.base_url, "/nonexistent"))
            print(f"Status: {response.status_code} - {response.reason}")
        except Exception as e:
            print(f"Error: {e}")
    
    # EXERCISE 4: API authentication basics
    def exercise_4_authentication(self):
        """
        Exercise 4: Understand API authentication
        
        Learning Goals:
        - API Key authentication
        - Bearer token authentication
        - Basic authentication
        - Importance of HTTPS for authentication
        
        Tasks:
        1. API Key in headers
        2. Bearer token authentication
        3. Basic authentication
        """
        print("\n=== Exercise 4: API Authentication ===")
        
        # Task 1: API Key authentication
        print("\n[Task 1] API Key authentication")
        headers = {
            "X-API-Key": "test-api-key-12345"
        }
        try:
            response = self.session.get(
                urljoin(self.base_url, "/protected/users"),
                headers=headers
            )
            print(f"Status: {response.status_code}")
        except Exception as e:
            print(f"Error: {e}")
        
        # Task 2: Bearer token
        print("\n[Task 2] Bearer token authentication")
        headers = {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        }
        try:
            response = self.session.get(
                urljoin(self.base_url, "/protected/users"),
                headers=headers
            )
            print(f"Status: {response.status_code}")
        except Exception as e:
            print(f"Error: {e}")
        
        # Task 3: Basic authentication
        print("\n[Task 3] Basic authentication")
        try:
            response = self.session.get(
                urljoin(self.base_url, "/protected/users"),
                auth=("admin", "password123")
            )
            print(f"Status: {response.status_code}")
        except Exception as e:
            print(f"Error: {e}")
    
    # EXERCISE 5: API endpoint discovery
    def exercise_5_endpoint_discovery(self):
        """
        Exercise 5: Discover API endpoints
        
        Learning Goals:
        - Common API endpoint patterns
        - Endpoint naming conventions
        - API documentation discovery
        
        Tasks:
        1. Test common endpoints
        2. Look for API documentation
        3. Identify available resources
        """
        print("\n=== Exercise 5: Endpoint Discovery ===")
        
        common_endpoints = [
            "/users",
            "/products",
            "/orders",
            "/api/v1/users",
            "/api/v2/users",
            "/admin",
            "/admin/users",
            "/swagger",
            "/swagger-ui.html",
            "/api-docs",
            "/docs",
        ]
        
        print("\n[Task 1] Testing common endpoints...")
        for endpoint in common_endpoints:
            try:
                url = urljoin(self.base_url, endpoint)
                response = self.session.head(url, timeout=2)
                if response.status_code != 404:
                    print(f"✓ Found: {endpoint} (Status: {response.status_code})")
            except Exception:
                pass
    
    # EXERCISE 6: Analyzing API responses
    def exercise_6_response_analysis(self):
        """
        Exercise 6: Understand and analyze API responses
        
        Learning Goals:
        - Response headers (Content-Type, Server, etc.)
        - Response body structure
        - Error responses
        - Response sizes
        
        Tasks:
        1. Analyze response headers
        2. Parse JSON responses
        3. Identify sensitive information in responses
        """
        print("\n=== Exercise 6: Response Analysis ===")
        
        print("\n[Task 1] Analyzing response headers...")
        try:
            response = self.session.get(urljoin(self.base_url, "/users"))
            print("\nResponse Headers:")
            for header, value in response.headers.items():
                print(f"  {header}: {value}")
        except Exception as e:
            print(f"Error: {e}")
        
        print("\n[Task 2] Analyzing response body...")
        try:
            response = self.session.get(urljoin(self.base_url, "/users"))
            if response.status_code == 200:
                data = response.json()
                print(f"Response structure:")
                print(f"  Type: {type(data).__name__}")
                print(f"  Size: {len(response.text)} bytes")
                print(f"  Keys: {list(data.keys())[:5] if isinstance(data, dict) else 'N/A'}")
        except Exception as e:
            print(f"Error: {e}")
    
    def run_all_exercises(self):
        """Run all exercises in sequence"""
        print("\n" + "="*60)
        print("API Penetration Testing Lab - Beginner Lab 1: API Basics")
        print("="*60)
        
        self.exercise_1_basic_requests()
        self.exercise_2_http_methods()
        self.exercise_3_status_codes()
        self.exercise_4_authentication()
        self.exercise_5_endpoint_discovery()
        self.exercise_6_response_analysis()
        
        print("\n" + "="*60)
        print("Lab Completed!")
        print("="*60)
        print("\nNext Steps:")
        print("1. Review all responses carefully")
        print("2. Understand how each HTTP method works")
        print("3. Practice with curl commands")
        print("4. Move to Lab 2: Basic Vulnerability Identification")

if __name__ == "__main__":
    try:
        lab = APIBasicsLab()
        lab.run_all_exercises()
    except KeyboardInterrupt:
        print("\n\nLab interrupted by user.")
    except Exception as e:
        print(f"\nLab error: {e}")
