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

**Challenge Endpoint:** `/api/challenge` (requires admin role)

**Expected Flag:** `FLAG{auth_bypass_master}`

---

### Lab 3: Injection Attacks (lab3_injection_attacks.py)

**Port:** 5003

**Difficulty:** Advanced

**Focus:** SQL Injection, NoSQL Injection, Command Injection, and XSS

**Vulnerabilities Covered:**

1. **SQL Injection:**
   - Union-based injection
   - Error-based injection
   - Blind SQL injection
   - Time-based injection
   - String concatenation bypass

2. **NoSQL Injection:**
   - MongoDB query injection
   - Operator injection
   - JavaScript injection in queries
   - JSON parameter pollution

3. **Command Injection:**
   - Shell command injection
   - Path traversal
   - Command chaining
   - Environment variable manipulation

4. **Cross-Site Scripting (XSS):**
   - Reflected XSS
   - Stored XSS
   - DOM-based XSS

**Challenge Endpoint:** `/api/admin/challenge` (requires SQL injection to access)

**Expected Flag:** `FLAG{injection_expert}`

---

### Lab 4: Session Management (lab4_session_management.py)

**Port:** 5004

**Difficulty:** Advanced

**Focus:** Session handling vulnerabilities and CSRF

**Vulnerabilities Covered:**

1. **Weak Session Generation:**
   - Predictable session IDs
   - Sequential session tokens
   - Timestamp-based sessions

2. **Session Fixation:**
   - Session ID reuse
   - Pre-authenticated session adoption
   - Missing session regeneration

3. **Session Hijacking:**
   - Session token in URL
   - Session token in logs
   - Insecure session storage

4. **CSRF Vulnerabilities:**
   - Missing CSRF tokens
   - Weak CSRF validation
   - State-changing GET requests

5. **Insecure Session Storage:**
   - Client-side session data
   - Unencrypted session cookies
   - Missing secure/httponly flags

**Challenge Endpoint:** `/api/admin/sensitive` (requires session hijacking)

**Expected Flag:** `FLAG{session_master}`

---

### Lab 5: API Security (lab5_api_security.py)

**Port:** 5005

**Difficulty:** Advanced

**Focus:** IDOR, authorization bypass, and rate limiting

**Vulnerabilities Covered:**

1. **Insecure Direct Object References (IDOR):**
   - Direct ID manipulation
   - Predictable resource IDs
   - Missing authorization checks
   - Horizontal privilege escalation
   - Vertical privilege escalation

2. **Broken Function Level Authorization:**
   - Admin endpoints without checks
   - Role-based access bypass
   - Method-based authorization bypass

3. **Mass Assignment:**
   - Direct property manipulation
   - Unvalidated input parameters
   - Privilege escalation through parameters

4. **Rate Limiting Issues:**
   - Missing rate limits
   - Bypassable rate limits
   - Header-based rate limit bypass

**Challenge Endpoint:** `/api/admin/flag` (requires authorization bypass)

**Expected Flag:** `FLAG{api_security_pro}`

---

## Running the Labs

Each lab runs independently on its designated port:

```bash
# Install dependencies
pip install -r requirements.txt

# Run individual labs
python labs/advanced/lab1_graphql_security.py
python labs/advanced/lab2_authentication_bypass.py
python labs/advanced/lab3_injection_attacks.py
python labs/advanced/lab4_session_management.py
python labs/advanced/lab5_api_security.py
```

## Security Remediations

### General Best Practices:

1. **Input Validation:**
   - Validate all user inputs
   - Use parameterized queries
   - Implement proper encoding
   - Sanitize data before processing

2. **Authentication:**
   - Use strong cryptographic algorithms
   - Implement proper password hashing
   - Use secure JWT libraries
   - Never accept 'none' algorithm

3. **Session Management:**
   - Generate cryptographically random sessions
   - Implement proper session expiration
   - Validate session tokens server-side

4. **Authorization:**
   - Implement proper IDOR checks
   - Verify user has access to requested resource
   - Use server-side access control lists
   - Avoid exposing internal IDs

5. **Rate Limiting:**
   - Implement proper rate limiting checks
   - Use reliable identifiers (not headers)
   - Implement exponential backoff
   - Monitor for abuse patterns

## Lab Progression

Recommended order of difficulty:

1. Lab 2 - Authentication Bypass (foundational)
2. Lab 4 - Session Management (related to auth)
3. Lab 3 - Injection Attacks (common vulnerability)
4. Lab 5 - API Security (IDOR and authorization)
5. Lab 1 - GraphQL Security (specialized)

## Assessment Criteria

Successfully completing a lab requires:

- [ ] Identifying all vulnerability types
- [ ] Understanding root causes
- [ ] Demonstrating exploitation
- [ ] Obtaining all challenge flags
- [ ] Documenting the attack vector
- [ ] Proposing remediation

## Programming Concepts and API Security

### Core Programming Principles for Secure APIs

Understanding fundamental programming concepts is essential for building and securing APIs:

#### 1. Input Validation and Sanitization
- **Concept:** Never trust user input - validate, sanitize, and encode all data
- **Application:** Prevents injection attacks, XSS, and data corruption
- **Best Practice:** Use allowlists over denylists, validate data types and ranges

#### 2. Principle of Least Privilege
- **Concept:** Grant minimum necessary permissions for operations
- **Application:** Limits damage from compromised accounts or vulnerabilities
- **Best Practice:** Implement role-based access control (RBAC) with granular permissions

#### 3. Defense in Depth
- **Concept:** Multiple layers of security controls
- **Application:** If one layer fails, others provide protection
- **Best Practice:** Combine authentication, authorization, encryption, and monitoring

#### 4. Secure by Default
- **Concept:** Security should be the default state, not an optional feature
- **Application:** Deny access unless explicitly granted
- **Best Practice:** Fail securely, use secure defaults in configurations

#### 5. Error Handling and Information Disclosure
- **Concept:** Handle errors gracefully without revealing sensitive information
- **Application:** Prevents enumeration and information leakage
- **Best Practice:** Use generic error messages, log detailed errors server-side

### API Security Fundamentals

#### Authentication vs Authorization
- **Authentication:** Verifying identity ("Who are you?")
- **Authorization:** Verifying permissions ("What can you do?")
- **Common Pitfall:** Implementing authentication without proper authorization checks

#### Stateless vs Stateful Sessions
- **Stateless (JWT):** Self-contained tokens, scalable but harder to revoke
- **Stateful (Session IDs):** Server-stored sessions, easier to manage but requires storage
- **Security Trade-offs:** Consider revocation needs, scalability, and attack surface

#### Data Integrity and Confidentiality
- **Integrity:** Ensuring data hasn't been tampered with (HMAC, digital signatures)
- **Confidentiality:** Protecting data from unauthorized access (encryption, TLS)
- **Implementation:** Use HTTPS, encrypt sensitive data at rest, sign critical data

### Common Programming Mistakes Leading to Vulnerabilities

1. **String Concatenation in Queries:** Use parameterized queries instead
2. **Client-Side Validation Only:** Always validate server-side
3. **Hardcoded Secrets:** Use environment variables and secret management
4. **Weak Random Number Generators:** Use cryptographically secure RNGs
5. **Ignoring Return Values:** Check error conditions and handle failures
6. **Race Conditions:** Implement proper locking and atomic operations
7. **Insecure Deserialization:** Validate and sanitize before deserializing

### API Design Patterns for Security

#### RESTful Security Patterns
- Use proper HTTP methods (GET for reads, POST/PUT/DELETE for modifications)
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
