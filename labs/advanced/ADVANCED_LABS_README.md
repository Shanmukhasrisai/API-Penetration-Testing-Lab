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
**Focus:** Multiple injection attack vectors

**Vulnerabilities Covered:**
1. **SQL Injection (Basic)**
   - `/api/search/users` - LIKE clause injection
   - `/api/user/<id>` - URL parameter injection

2. **SQL Injection (Authentication)**
   - `/api/user/login` - Authentication bypass
   - Example: `admin' --` or `' OR '1'='1`

3. **NoSQL Injection**
   - `/api/nosql/search` - MongoDB operator injection
   - Example: `{"$ne": null}`

4. **Command Injection**
   - `/api/file/retrieve` - File reading via command execution
   - `/api/ping` - Network utility injection
   - `/api/image/resize` - ImageMagick command injection

5. **XML External Entity (XXE) Injection**
   - `/api/xml/parse` - No XXE protection

6. **LDAP Injection**
   - `/api/ldap/search` - LDAP filter manipulation

7. **Multiple Injection Vectors**
   - `/api/admin/export` - Combined SQL and command injection

**Challenge Endpoint:** `/api/challenge/injection`
**Expected Flag:** `FLAG{injection_master}`

**Exploitation Examples:**
```
SQL: /api/search/users?q=admin' OR '1'='1
SQL: /api/user/login -d '{"username":"admin' --","password":"anything"}'
Command: /api/file/retrieve?file=/etc/passwd
Command: /api/ping?target=127.0.0.1; cat /etc/passwd
LDAP: /api/ldap/search?username=*
```

---

### Lab 4: Session Management (lab4_session_management.py)
**Port:** 5004
**Difficulty:** Advanced
**Focus:** Session handling and cookie manipulation

**Vulnerabilities Covered:**
1. **Weak Session ID Generation** - Timestamp-based predictable IDs
2. **Sequential Session IDs** - Incrementing counter
3. **Session Fixation** - Accepting arbitrary session IDs
4. **CSRF Token Weakness** - Predictable, reusable tokens
5. **Insufficient CSRF Protection** - No token validation on dangerous operations
6. **CSRF Bypass via GET** - State-changing operations via GET requests
7. **Session Timeout Not Enforced** - Expired sessions still accepted
8. **Automatic Session Extension** - Indefinite session lifetime without re-auth
9. **Sensitive Data in Session** - Passwords/tokens exposed via session info
10. **Session Enumeration** - Listing all active sessions
11. **Role in Cookies** - Client-side role manipulation
12. **Cookie Echo** - Echoing user input back in cookies

**Exploitation Vectors:**
```
Week Session: /api/login/weak - timestamps are predictable
Sequential: /api/login/sequential - session IDs are 0000000001, 0000000002, etc.
Fixation: /api/session/set?session_id=attacker_controlled
Role Bypass: Set-Cookie: user_role=admin
CSRF: POST /api/transfer without CSRF token
```

**Challenge Endpoint:** `/api/admin/panel` or `/api/challenge/session`
**Expected Flag:** `FLAG{session_master}`

---

### Lab 5: API Security & IDOR (lab5_api_security.py)
**Port:** 5005
**Difficulty:** Advanced
**Focus:** API-specific vulnerabilities

**Vulnerabilities Covered:**
1. **Rate Limiting Bypass** - Using X-Forwarded-For header
2. **API Key Exposure** - Keys listed in response
3. **Weak API Key Validation** - Overly permissive checks
4. **Version-Based Differences** - v1 API has fewer security controls
5. **IDOR - User Data** - Direct object reference without authorization
6. **IDOR - Financial Data** - Accessing balance of other users
7. **IDOR - Update Operations** - Modifying other users' data
8. **Mass Assignment** - Unintended fields accepted in requests
9. **Server-Side Template Injection (SSTI)** - User input in template rendering
10. **Format String Vulnerabilities** - Improper string formatting

**Exploitation Examples:**
```
IDOR User: GET /api/user/1 (access admin profile)
IDOR Balance: GET /api/user/2/balance (check balance of other users)
IDOR Update: PUT /api/user/3 -d '{"email":"hacker@evil.com"}'
Rate Limit Bypass: Add header X-Forwarded-For: 127.0.0.2
API Key: GET /api/keys/list (list all API keys)
Mass Assignment: POST /api/product/create -d '{"discount":90}'
SSTI: POST /api/template -d '{"template":"{{7*7}}"}'
```

**Challenge Endpoints:**
- `/api/challenge/idor` - Access admin data (user_id=1)
- `/api/challenge/ratelimit` - Bypass rate limiting
- `/api/challenge/api-key` - Use admin API key

**Expected Flags:**
- `FLAG{idor_master}`
- `FLAG{ratelimit_bypass}`
- `FLAG{api_key_master}`

---

## Getting Started

### Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Required packages:
- Flask
- PyJWT
- requests (for testing)

### Running the Labs

Each lab runs on a different port:

```bash
# Terminal 1 - Lab 1
python lab1_graphql_security.py

# Terminal 2 - Lab 2
python lab2_authentication_bypass.py

# Terminal 3 - Lab 3
python lab3_injection_attacks.py

# Terminal 4 - Lab 4
python lab4_session_management.py

# Terminal 5 - Lab 5
python lab5_api_security.py
```

### Testing with curl

```bash
# Test Lab 2 - Authentication Bypass
curl -X POST http://localhost:5002/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# Test Lab 3 - SQL Injection
curl 'http://localhost:5003/api/search/users?q=admin%27%20OR%20%271%27=%271'

# Test Lab 4 - Session Fixation
curl 'http://localhost:5004/api/session/set?session_id=hacker123'

# Test Lab 5 - IDOR
curl http://localhost:5005/api/user/1
```

## Common Exploitation Patterns

### Authentication Bypass
- Modify JWT claims (change role to 'admin')
- Use 'none' algorithm in JWT
- Bypass with username enumeration: `admin' --`
- Use default credentials: `default:backup:12345`

### Injection Attacks
- SQL: `' OR '1'='1`, `admin' --`, `' UNION SELECT`
- Command: `; cat /etc/passwd`, `| whoami`
- LDAP: `*`, `admin*)(|(uid=*`, `*)(objectClass=*`

### Session Manipulation
- Predict session IDs (timestamps, sequences)
- Set arbitrary session IDs via /api/session/set
- Modify cookies to set admin role
- Bypass CSRF by omitting token

### IDOR
- Change numeric IDs: /api/user/1, /api/user/2, /api/user/3
- Try UUID variations
- Use API version differences: /api/v1 vs /api/v2
- Access admin resources by ID

## Defense Mechanisms

To remediate these vulnerabilities:

1. **Authentication:**
   - Use strong, cryptographically secure token generation
   - Implement proper JWT verification
   - Enforce token expiration and refresh token rotation
   - Use httponly, secure flags on cookies

2. **Injection Prevention:**
   - Use parameterized queries/prepared statements
   - Input validation and sanitization
   - Escape user input
   - Use ORM frameworks

3. **Session Security:**
   - Generate cryptographically secure session IDs
   - Implement proper CSRF tokens (unique per request)
   - Enforce session timeouts
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
