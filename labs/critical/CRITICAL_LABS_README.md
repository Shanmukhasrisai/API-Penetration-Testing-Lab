# Critical API Penetration Testing Labs

## Overview

This directory contains **CRITICAL** level API penetration testing labs designed to simulate real-world attack scenarios and vulnerabilities found in production APIs. These labs are challenging and require advanced penetration testing techniques.

## Labs Included

### Lab 1: OAuth 2.0 Security Bypass and Token Manipulation
**Filename:** `lab1_oauth2_security_bypass.py`
**Severity:** CRITICAL
**Difficulty:** Advanced

#### Vulnerabilities Tested:
- Missing state parameter validation (CSRF)
- Redirect URI validation bypass
- Token endpoint authentication bypass
- Refresh token abuse and unlimited renewal
- Implicit flow token leakage
- JWT token manipulation and signature bypass
- Scope escalation and privilege elevation

#### Real-World Scenarios:
- OAuth provider implementations with weak validation
- Third-party application OAuth implementations
- Token refresh mechanisms without proper controls
- JWT implementations without signature verification

#### Usage:
```bash
python3 lab1_oauth2_security_bypass.py
```

---

### Lab 2: API Rate Limiting Bypass and DDoS Simulation
**Filename:** `lab2_rate_limit_bypass.py`
**Severity:** CRITICAL
**Difficulty:** Advanced

#### Vulnerabilities Tested:
- No rate limiting implementation
- X-Forwarded-For header bypass
- User-Agent string variation bypass
- Concurrent request handling flaws
- Rate limit reset timing exploitation
- HTTP method bypass (GET vs POST)
- Distributed denial of service (DDoS) techniques

#### Real-World Scenarios:
- Login endpoints without brute force protection
- API endpoints vulnerable to resource exhaustion
- Rate limiting based on single IP address
- Load balancer misconfigurations
- Proxy rotation for distributed attacks

#### Usage:
```bash
python3 lab2_rate_limit_bypass.py
```

---

### Lab 3: Injection Attacks (SQL, NoSQL, Command, LDAP, XML, Template)
**Filename:** `lab3_injection_attacks.py`
**Severity:** CRITICAL
**Difficulty:** Advanced

#### Vulnerabilities Tested:
- SQL injection (basic, error-based, time-based blind)
- NoSQL injection (MongoDB, operator injection)
- OS command injection
- LDAP injection attacks
- XML/XXE injection
- Server-side template injection (SSTI)

#### Real-World Scenarios:
- Poorly sanitized user input in database queries
- API endpoints accepting unvalidated search parameters
- Application APIs interfacing with command-line tools
- LDAP authentication systems
- Template engine usage without input validation
- XML parsing without XXE protection

#### Usage:
```bash
python3 lab3_injection_attacks.py
```

---

### Lab 4: Sensitive Data Exposure and Authentication Bypass
**Filename:** `lab4_sensitive_data_exposure.py`
**Severity:** CRITICAL
**Difficulty:** Advanced

#### Vulnerabilities Tested:
- Exposed API keys and secrets in responses
- Insecure Direct Object References (IDOR)
- Weak or missing authentication
- Default credentials
- JWT manipulation and signature bypass
- Brute force attacks on authentication endpoints
- Exposed internal/administrative APIs
- Information disclosure through error messages

#### Real-World Scenarios:
- API responses containing sensitive tokens
- Enumeration attacks on resource endpoints
- User enumeration in login endpoints
- Default credentials in production systems
- Administrative endpoints accessible without authentication
- Detailed error messages revealing system information

#### Usage:
```bash
python3 lab4_sensitive_data_exposure.py
```

---

## Setup Requirements

### Prerequisites
```bash
pip install requests pyjwt
```

### Dependencies
- Python 3.7+
- requests library
- PyJWT library
- Standard library modules (json, re, base64, hashlib, threading, concurrent.futures)

## Configuration

Before running the labs, you need to configure the target API:

```python
# For each lab, modify the target URL and credentials:
target_url = "http://api.vulnerable-app.local:8080"
client_id = "your_client_id"
client_secret = "your_client_secret"
```

## Running the Labs

### Individual Lab Execution
```bash
# Run OAuth 2.0 security lab
python3 lab1_oauth2_security_bypass.py

# Run rate limiting bypass lab
python3 lab2_rate_limit_bypass.py

# Run injection attacks lab
python3 lab3_injection_attacks.py

# Run sensitive data exposure lab
python3 lab4_sensitive_data_exposure.py
```

### With Verbose Output
```bash
python3 -u lab1_oauth2_security_bypass.py 2>&1 | tee results.log
```

## Interpreting Results

Each lab outputs:
- **Vulnerabilities Found:** Count of confirmed vulnerabilities
- **Severity Levels:**
  - CRITICAL: Immediate exploitation possible
  - HIGH: Significant security impact
  - MEDIUM: Moderate security concern
  - LOW: Minor security issue
- **Detailed Findings:** Specific vulnerabilities with technical details

## Real-World Application

These labs simulate vulnerabilities commonly found in:
- SaaS API platforms
- Mobile backend APIs
- Microservice architectures
- OAuth providers and integrations
- GraphQL APIs
- RESTful web services
- Payment processing APIs
- Authentication systems

## Remediation Guidelines

### OAuth 2.0 Vulnerabilities
- Implement strict state parameter validation
- Use exact redirect URI matching
- Implement client authentication on token endpoint
- Use short-lived tokens with refresh token rotation
- Avoid storing secrets in URL fragments

### Rate Limiting
- Implement rate limiting on all endpoints
- Use per-user rate limiting (after authentication)
- Implement per-IP rate limiting (before authentication)
- Ignore X-Forwarded-For in rate limit calculations
- Use distributed rate limiting for multi-server deployments

### Injection Attacks
- Use parameterized queries for all database access
- Implement input validation and sanitization
- Avoid dynamic query construction
- Disable dangerous functions (exec, eval, system commands)
- Use allowlists for input validation

### Sensitive Data
- Never expose secrets in API responses
- Implement proper authorization checks (OAuth, JWT, API keys)
- Avoid information disclosure in error messages
- Implement input validation to prevent IDOR attacks
- Use secure token generation and storage

## Testing Checklist

- [ ] OAuth 2.0 state parameter validation
- [ ] Rate limiting effectiveness
- [ ] Injection attack vectors
- [ ] Sensitive data exposure
- [ ] Authentication bypass techniques
- [ ] IDOR vulnerabilities
- [ ] JWT signature validation
- [ ] Default credential testing
- [ ] Brute force attack resistance
- [ ] Error message information disclosure

## Advanced Testing Scenarios

1. **Multi-endpoint chaining:** Use vulnerabilities across multiple endpoints
2. **Privilege escalation:** Start with low-privilege access and escalate
3. **Data exfiltration:** Extract sensitive data using injection techniques
4. **Account takeover:** Combine multiple vulnerabilities for account compromise
5. **Distributed attacks:** Use rate limit bypass for coordinated attacks

## Legal and Ethical Considerations

⚠️ **IMPORTANT:** These labs are designed for authorized security testing only.

- Obtain explicit written permission before testing any API
- Use these tools only on systems you own or have permission to test
- Unauthorized access to computer systems is illegal
- Follow responsible disclosure practices
- Document all findings and maintain confidentiality

## Support and Resources

- OWASP API Security: https://owasp.org/www-project-api-security/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CWE/SANS Top 25: https://cwe.mitre.org/
- CVE Details: https://www.cvedetails.com/

## Contributing

Contributions are welcome! Please submit pull requests with:
- Additional lab scenarios
- Improved payload libraries
- Better detection mechanisms
- Documentation improvements

## License

See LICENSE file in the repository root.

---

**Last Updated:** December 2025
**Version:** 1.0
**Status:** Production Ready
