# Advanced API Penetration Testing Labs
Comprehensive collection of advanced security labs designed to test sophisticated API attack vectors and exploitation techniques.

## Overview
This directory contains five advanced labs covering critical API security vulnerabilities:

### Lab 1: GraphQL Security (lab1_graphql_security.py)
**Port:** 5001
**Difficulty:** Advanced
**Focus:** GraphQL-specific vulnerabilities

**Vulnerabilities Covered:**
- Introspection query exploitation
- GraphQL injection attacks
- Field-level authorization bypass
- Batch query attacks
- Alias-based enumeration
- Query complexity exploitation
- Fragment-based attacks

**Challenge Endpoint:** `/graphql/challenge`

---

### Lab 2: Authentication Bypass (lab2_authentication_bypass.py)
**Port:** 5002
**Difficulty:** Advanced
**Focus:** JWT manipulation and authentication vulnerabilities

**Vulnerabilities Covered:**
1. **Weak JWT Token Generation** - Predictable timestamps and token claims
2. **JWT Algorithm Confusion** - Accept 'none' algorithm
3. **Bearer Scheme Bypass** - Improper token validation
4. **Username Enumeration** - Information disclosure in error messages
5. **Plaintext Password Storage** - No password hashing
6. **Token Forgery** - Weak secret keys allowing brute force
7. **No Token Revocation** - Tokens usable after logout
8. **Weak Token Refresh** - No verification of old tokens
9. **Role Bypass** - No role verification in protected endpoints
10. **Default Credentials** - Hardcoded backup credentials
11. **Expired Token Acceptance** - No proper expiration validation
12. **Header Injection** - Custom header-based role escalation

---

### Lab 3: Injection Attacks (lab3_injection_attacks.py)
**Port:** 5003
**Difficulty:** Advanced
**Focus:** Multiple injection vulnerability types

**Vulnerabilities Covered:**
- SQL Injection (SQLi)
- NoSQL Injection
- Command Injection
- LDAP Injection
- XML Injection
- XPath Injection
- Template Injection

---

### Lab 4: Session Management (lab4_session_management.py)
**Port:** 5004
**Difficulty:** Advanced
**Focus:** Session handling and cookie security

**Vulnerabilities Covered:**
- Session Fixation
- Predictable Session IDs
- No Session Timeout
- Insecure Cookie Attributes
- Session Token Exposure
- Concurrent Session Handling

---

### Lab 5: API Security (lab5_api_security.py)
**Port:** 5005
**Difficulty:** Advanced
**Focus:** Comprehensive API security issues

**Vulnerabilities Covered:**
- Mass Assignment
- IDOR (Insecure Direct Object References)
- Missing Rate Limiting
- Verbose Error Messages
- No Input Validation
- CORS Misconfiguration
- API Key Exposure

---

## Running the Labs

### Prerequisites
```bash
# Install dependencies
pip install -r requirements.txt
```

### Starting Individual Labs
```bash
# Run individual labs
python labs/advanced/lab1_graphql_security.py
python labs/advanced/lab2_authentication_bypass.py
python labs/advanced/lab3_injection_attacks.py
python labs/advanced/lab4_session_management.py
python labs/advanced/lab5_api_security.py
```

Each lab runs on its designated port (5001-5005). Access them via:
- Lab 1: http://localhost:5001
- Lab 2: http://localhost:5002
- Lab 3: http://localhost:5003
- Lab 4: http://localhost:5004
- Lab 5: http://localhost:5005

## Testing Methodology

### Tools
- Burp Suite
- Postman
- curl
- jwt.io (for JWT manipulation)
- sqlmap (for SQLi testing)

### Approach
1. Reconnaissance - Explore API endpoints
2. Authentication Testing - Test auth mechanisms
3. Authorization Testing - Test access controls
4. Input Validation - Test injection vectors
5. Business Logic - Test workflow bypasses
6. Session Management - Test session handling

## Learning Objectives

### GraphQL Security
- Understanding introspection queries
- Recognizing batch attack patterns
- Implementing query depth limiting
- Field-level authorization concepts

### Authentication & Authorization
- JWT structure and vulnerabilities
- Token manipulation techniques
- Algorithm confusion attacks
- Proper token validation

### Injection Attacks
- Multiple injection types
- Context-specific payload crafting
- Input validation bypass techniques
- Parameterized query importance

### Session Management
- Secure session generation
- Proper cookie attributes
- Session lifecycle management
- Concurrent session handling

### API Security Best Practices
- Input validation strategies
- Rate limiting implementation
- Proper error handling
- CORS configuration

## Mitigation Strategies

### Authentication & Authorization
- Use strong, unpredictable secrets
- Implement proper algorithm whitelisting
- Validate all JWT claims
- Use refresh token rotation
- Implement token revocation
- Hash passwords with bcrypt/argon2
- Never expose tokens in URLs

### Injection Prevention
- Use parameterized queries
- Implement input validation
- Apply output encoding
- Use ORM/ODM frameworks properly
- Implement least privilege
- Regular security testing

### Session Security
- Generate cryptographically random session IDs
- Set secure cookie attributes (HttpOnly, Secure, SameSite)
- Implement session timeouts
- Regenerate session IDs after authentication
- Implement concurrent session controls

### API Security
- Implement rate limiting
- Use API keys/tokens properly
- Configure CORS restrictively
- Never expose sensitive data in errors
- Implement proper logging
- Use HTTPS everywhere

## Best Practices

### Security Headers
```http
Strict-Transport-Security: max-age=31536000
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'
```

### API Design
- Use RESTful principles
- Implement proper status codes (401 vs 403, 404 vs 403)
- Version your APIs to manage breaking changes
- Use resource-based URLs, not action-based

#### GraphQL Security Patterns
- Implement query depth limiting
- Use query complexity analysis
- Disable introspection in production
- Implement field-level authorization
- Monitor for batch attack patterns

#### Rate Limiting Strategies
- Token bucket algorithm for burst handling
- Sliding window for precise rate control
- Distributed rate limiting for scaled systems
- Per-user and per-IP rate limiting

### Secure Coding Checklist
- [ ] All inputs validated and sanitized
- [ ] Authentication required for sensitive endpoints
- [ ] Authorization checks on every request
- [ ] Cryptographically secure random values
- [ ] No sensitive data in logs or errors
- [ ] HTTPS enforced for all communications
- [ ] Security headers properly configured
- [ ] Rate limiting implemented
- [ ] Regular security testing performed
- [ ] Dependencies kept up to date

## Resources

- [OWASP Top 10 API](https://owasp.org/www-project-api-security/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox](https://www.hackthebox.com/)
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)

## Notes

- These labs are intentionally vulnerable for educational purposes only
- Never deploy this code to production
- Use only in isolated lab environments
- These examples demonstrate real-world attack vectors
- Understanding these vulnerabilities helps build more secure APIs

## Author

API Penetration Testing Lab - Advanced Track

## License

Educational use only
