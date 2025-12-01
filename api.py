#!/usr/bin/env python3
"""
Advanced HackerHunt-Lab for API Pentesting Practice
- Dynamic endpoints from config
- Supports Auth headers
- Tests multiple HTTP methods and vulnerabilities
- Generates detailed JSON output report
"""
import sys
import json
import argparse
import os
import requests
from typing import List, Dict, Any, Optional, Tuple

USER_AGENT = "AdvancedHackerHuntLab/2.0"
DEFAULT_TIMEOUT = 7
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit for config files


def load_endpoints_config(filename: str) -> List[Dict[str, Any]]:
    """Load API endpoints and test details from JSON config file"""
    try:
        # Validate file exists and size
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Config file not found: {filename}")
        
        file_size = os.path.getsize(filename)
        if file_size > MAX_FILE_SIZE:
            raise ValueError(f"Config file too large: {file_size} bytes (max: {MAX_FILE_SIZE})")
        
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Validate endpoints structure
        endpoints = data.get("endpoints", [])
        if not isinstance(endpoints, list):
            raise ValueError("'endpoints' must be a list")
        
        for idx, endpoint in enumerate(endpoints):
            if not isinstance(endpoint, dict):
                raise ValueError(f"Endpoint {idx} must be a dictionary")
            if 'url' not in endpoint:
                raise ValueError(f"Endpoint {idx} missing 'url' field")
            if not isinstance(endpoint.get('url'), str):
                raise ValueError(f"Endpoint {idx} 'url' must be a string")
        
        return endpoints
    
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON in config file: {e}")
        sys.exit(1)
    except (FileNotFoundError, ValueError) as e:
        print(f"[!] Config error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error loading config: {e}")
        sys.exit(1)


def make_request(
    url: str,
    method: str,
    headers: Dict[str, str],
    params: Optional[Dict[str, str]] = None,
    data: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT
) -> Tuple[Optional[int], Optional[str]]:
    """Make HTTP request with proper error handling and security settings"""
    try:
        # Validate URL scheme
        if not url.startswith(('http://', 'https://')):
            print(f"[!] Invalid URL scheme: {url}")
            return None, None
        
        resp = requests.request(
            method, 
            url, 
            headers=headers, 
            params=params, 
            data=data, 
            timeout=timeout,
            verify=True,  # Enable SSL verification
            allow_redirects=False  # Prevent open redirect vulnerabilities
        )
        return resp.status_code, resp.text
    
    except requests.exceptions.Timeout:
        print(f"[!] Request timeout for {url} with {method}")
        return None, None
    except requests.exceptions.SSLError as e:
        print(f"[!] SSL verification failed for {url}: {e}")
        return None, None
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed for {url} with {method}: {e}")
        return None, None
    except Exception as e:
        print(f"[!] Unexpected error during request to {url}: {e}")
        return None, None


def test_reflected_xss(
    url: str,
    method: str,
    headers: Dict[str, str],
    param_name: str,
    timeout: int = DEFAULT_TIMEOUT
) -> bool:
    """Test for reflected XSS vulnerabilities"""
    # Sanitize parameter name
    if not param_name or not isinstance(param_name, str):
        return False
    
    payload = "<script>alert('XSS')</script>"
    
    try:
        if method.upper() == "GET":
            params = {param_name: payload}
            status, content = make_request(url, "GET", headers, params=params, timeout=timeout)
        else:
            data = {param_name: payload}
            status, content = make_request(url, method.upper(), headers, data=data, timeout=timeout)
        
        if content and payload in content:
            return True
    except Exception as e:
        print(f"[!] Error testing XSS on {url}: {e}")
    
    return False


def test_sql_injection(
    url: str,
    method: str,
    headers: Dict[str, str],
    param_name: str,
    timeout: int = DEFAULT_TIMEOUT
) -> bool:
    """Test for SQL injection vulnerabilities"""
    # Sanitize parameter name
    if not param_name or not isinstance(param_name, str):
        return False
    
    payload = "'"
    
    try:
        if method.upper() == "GET":
            params = {param_name: payload}
            status, content = make_request(url, "GET", headers, params=params, timeout=timeout)
        else:
            data = {param_name: payload}
            status, content = make_request(url, method.upper(), headers, data=data, timeout=timeout)
        
        if content:
            errors = [
                "sql syntax", "mysql", "syntax error", "unclosed quotation",
                "sqlite error", "pg_query", "sqlstate", "mysql_fetch",
                "mysql_num_rows", "sql error", "ora-", "postgresql"
            ]
            content_lower = content.lower()
            if any(e in content_lower for e in errors):
                return True
    except Exception as e:
        print(f"[!] Error testing SQL injection on {url}: {e}")
    
    return False


def run_tests(
    endpoint: Dict[str, Any],
    auth_headers: Dict[str, str],
    timeout: int = DEFAULT_TIMEOUT
) -> Dict[str, Any]:
    """Run security tests on an endpoint"""
    results = {
        "url": endpoint.get("url"),
        "method": endpoint.get("method", "GET"),
        "vulnerabilities": {}
    }
    
    param_names = endpoint.get("params", [])
    
    # Validate params is a list
    if not isinstance(param_names, list):
        print(f"[!] Warning: 'params' should be a list for {endpoint.get('url')}")
        return results
    
    for param in param_names:
        if not isinstance(param, str):
            continue
        
        try:
            if test_reflected_xss(endpoint["url"], results["method"], auth_headers, param, timeout):
                results["vulnerabilities"].setdefault("reflected_xss", []).append(param)
            
            if test_sql_injection(endpoint["url"], results["method"], auth_headers, param, timeout):
                results["vulnerabilities"].setdefault("sql_injection", []).append(param)
        except Exception as e:
            print(f"[!] Error testing parameter '{param}': {e}")
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Advanced HackerHunt Lab for API Pentesting")
    parser.add_argument("--config", required=True, help="JSON config file with API endpoints to test")
    parser.add_argument("--auth", help="Authorization header value, e.g. 'Bearer <token>' or 'APIKey <key>'")
    parser.add_argument("--output", help="Output JSON report file")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout in seconds")
    
    args = parser.parse_args()
    
    # Validate timeout
    timeout = args.timeout if args.timeout > 0 else DEFAULT_TIMEOUT
    
    auth_headers = {"User-Agent": USER_AGENT}
    if args.auth:
        # Basic sanitization of auth header
        if len(args.auth) > 1000:  # Reasonable limit
            print("[!] Authorization header too long")
            sys.exit(1)
        auth_headers["Authorization"] = args.auth
    
    endpoints = load_endpoints_config(args.config)
    
    if not endpoints:
        print("[!] No endpoints found in config file")
        sys.exit(1)
    
    report = []
    
    for endpoint in endpoints:
        try:
            print(f"[*] Testing endpoint {endpoint.get('url')} with method {endpoint.get('method', 'GET')}")
            result = run_tests(endpoint, auth_headers, timeout)
            report.append(result)
        except Exception as e:
            print(f"[!] Error testing endpoint {endpoint.get('url')}: {e}")
    
    if args.output:
        try:
            with open(args.output, "w", encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            print(f"[+] Report saved to {args.output}")
        except Exception as e:
            print(f"[!] Error saving report: {e}")
            sys.exit(1)
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
