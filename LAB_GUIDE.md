 API Penetration Testing Lab — Comprehensive Guide

A structured, zero-knowledge-to-expert hands-on curriculum for API security testing. This guide connects architectural theory, manual traffic analysis (cURL / Burp Suite), automated exploit scripting, and secure code remediation.

---

## Curriculum Roadmap

```text
┌─────────────────────────┐
│   Phase 1: Beginner     │ ──► HTTP basics, REST API recon, endpoint fuzzing, baseline BOLA
└───────────┬─────────────┘
            ▼
┌─────────────────────────┐
│  Phase 2: Intermediate  │ ──► JWT flaws, Key Confusion, NoSQL injection, Path Traversal
└───────────┬─────────────┘
            ▼
┌─────────────────────────┐
│    Phase 3: Critical    │ ──► OAuth 2.0 bypass, Rate-limit spoofing, RCE/XXE/SSTI, BFLA
└───────────┬─────────────┘
            ▼
┌─────────────────────────┐
│     Phase 4: Expert     │ ──► Multi-stage exploit chaining, GraphQL, SSRF, Cloud/Mobile APIs
└─────────────────────────┘

```

---

## Phase 1: Beginner — Foundations & Reconnaissance

**Target Skill Level:** Zero prior security experience

**Core Objective:** Master API traffic flow, inspection tools, and baseline authorization checks.

### Module 1.1: API Fundamentals & Traffic Interception

* **Theory:** REST vs. GraphQL, JSON serialization, HTTP verbs (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`), header injection points, and HTTP status codes (`401`, `403`, `429`).
* **Hands-on Exercises:**
1. Configure Burp Suite / OWASP ZAP to intercept local traffic.
2. Inspect and replay API requests using cURL and Postman.
3. Map application attack surfaces from Swagger/OpenAPI documentation (`/swagger.json`, `/api/docs`).



### Module 1.2: Baseline Authorization Checks (BOLA/IDOR)

* **Theory:** Identifying direct object identifiers in URI paths and query parameters.
* **Hands-on Exercises:**
1. Swap sequential and UUID resource identifiers in `/api/v1/users/{id}`.
2. Differentiate between horizontal privilege escalation (same role, different tenant) and vertical privilege escalation (user to admin).



---

## Phase 2: Intermediate — Tokens & Targeted Injections

**Directory:** `labs/intermediate/`

**Target Skill Level:** Practical understanding of web protocols & scripting

**Core Objective:** Exploit authentication mechanics and modern database query selectors.

### Module 2.1: JWT Manipulation & Authentication Attacks

* **Script:** `labs/intermediate/lab1_jwt_attacks.py`
* **Vulnerabilities Tested:**
* Header tampering and algorithm stripping (`"alg": "none"`).
* Asymmetric-to-Symmetric Key Confusion (`RS256` public key verified as `HS256` secret).
* Offline HMAC secret dictionary brute-forcing.
* Expired token claim acceptance and lack of revocation.


* **Execution:**
```bash
python3 labs/intermediate/lab1_jwt_attacks.py

```



### Module 2.2: Polyglot API Injection Scanning

* **Script:** `labs/intermediate/lab2_injection_attacks.py`
* **Vulnerabilities Tested:**
* Error-based and blind time-based SQL injection in REST query parameters.
* MongoDB NoSQL operator injection (`$gt`, `$ne`, `$regex`, `$where`).
* Path traversal and Local File Inclusion (LFI) via file download endpoints.
* Content-Type confusion and reflected API XSS.


* **Execution:**
```bash
python3 labs/intermediate/lab2_injection_attacks.py --url http://localhost:8080 --report intermediate_report.json

```



---

## Phase 3: Critical — Advanced Exploitation & Bypasses

**Directory:** `labs/critical/`

**Target Skill Level:** Advanced

**Core Objective:** Execute complex protocol bypasses, race conditions, and server-side code execution.

### Module 3.1: OAuth 2.0 Security Bypass & Token Manipulation

* **Script:** `labs/critical/lab1_oauth2_security_bypass.py`
* **Vectors:** CSRF via missing state parameters, open redirect chaining on `redirect_uri`, unauthenticated token endpoints, and scope privilege escalation (`scope=admin`).
* **Execution:**
```bash
python3 labs/critical/lab1_oauth2_security_bypass.py

```



### Module 3.2: Rate Limiting & Resource Exhaustion (DDoS Simulation)

* **Script:** `labs/critical/lab2_rate_limit_bypass.py`
* **Vectors:** Layer 7 origin header spoofing (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`), HTTP verb tunneling (`X-HTTP-Method-Override`), path obfuscation, and synchronized multi-threaded race conditions.
* **Execution:**
```bash
python3 labs/critical/lab2_rate_limit_bypass.py

```



### Module 3.3: Polyglot Injections (RCE / SSTI / XXE)

* **Script:** `labs/critical/lab3_injection_attacks.py`
* **Vectors:** Remote OS command injection via subshell delimiters (`;`, `|`, ```), Server-Side Template Injection (Jinja2/Twig/FreeMarker), and XML External Entity (XXE) file retrieval.
* **Execution:**
```bash
python3 labs/critical/lab3_injection_attacks.py

```



### Module 3.4: Sensitive Data Exposure & BFLA

* **Script:** `labs/critical/lab4_sensitive_data_exposure.py`
* **Vectors:** Response scanning for leaked credentials/DSNs, mass assignment on entity update routes, unauthenticated administrative routing (BFLA), and verbose stack trace leaks.
* **Execution:**
```bash
python3 labs/critical/lab4_sensitive_data_exposure.py

```



---

## Phase 4: Expert — Real-World Attack Chains & Specialized APIs

**Target Skill Level:** Professional Penetration Tester / Bug Bounty Hunter

**Core Objective:** Chain isolated low-severity findings into critical system compromises.

### Module 4.1: Multi-Stage Attack Chains

* **Chain A (Mass Assignment $\rightarrow$ BFLA):** Elevate an unprivileged account via profile update mass assignment, then invoke exposed administrative endpoints.
* **Chain B (SSRF $\rightarrow$ Cloud Metadata $\rightarrow$ IAM Escalation):** Exploit URL-fetching endpoints to access cloud metadata instances and extract temporary worker credentials.
* **Chain C (BOLA $\rightarrow$ IDOR $\rightarrow$ Account Takeover):** Access password reset tokens or session identifiers via unauthorized object endpoint manipulation.

### Module 4.2: GraphQL Security Testing

* **Vectors:** Schema harvesting via enabled introspection, batching queries for high-speed credential stuffing, nested relation denial-of-service, and mutation access control bypasses.

---

## Hands-On Environment Setup

### 1. Start the Local Vulnerable Target

The lab includes a self-hosted FastAPI target simulating real-world backend microservices.

```bash
# Build and run the target container
docker compose up --build -d

```

*The target API will be live at `http://localhost:8080`.*

### 2. Install Attacker Environment Dependencies

```bash
pip install -r requirements.txt

```

### 3. Verify System Health

```bash
curl -s http://localhost:8080/docs

```

---

## Testing & Verification Checklist

* [ ] **Recon:** Map all public and hidden endpoints via `/docs`, `/swagger.json`, or fuzzing.
* [ ] **Auth:** Test JWT signature integrity (`alg: none`, weak keys, key confusion).
* [ ] **Access Control:** Verify object-level (BOLA) and function-level (BFLA) boundaries.
* [ ] **Rate Limits:** Attempt header spoofing (`X-Forwarded-For`) and burst concurrency.
* [ ] **Injections:** Audit all query parameters and JSON bodies for SQLi, NoSQL, and Command Injection.
* [ ] **Data Sanitization:** Check response payloads for internal secrets, PII, and debug traces.

---

## Responsible Use & Ethics Notice

These labs and exploit scripts are designed strictly for **authorized educational research, security training, and defensive hardening**. Testing third-party systems without prior explicit written authorization is illegal.
