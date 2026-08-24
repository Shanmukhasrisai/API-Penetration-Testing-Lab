# 🛤️ API Penetration Testing — Complete Learning Path to Production Expertise

Welcome to the **API Penetration Testing Lab** structured learning curriculum. This roadmap takes you from zero foundational knowledge to executing advanced multi-stage attack chains against modern microservices, OAuth providers, and cloud-integrated REST APIs.

---

## 🎯 Curriculum Matrix & Milestone Roadmap

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                            CURRICULUM PHASES                                │
├───────────────────┬───────────────────┬───────────────────┬─────────────────┤
│  🟢 Beginner      │  🟡 Intermediate  │  🟠 Critical      │  🔴 Expert      │
│  (Weeks 1–3)      │  (Weeks 4–7)      │  (Weeks 8–11)     │  (Weeks 12–16)  │
├───────────────────┼───────────────────┼───────────────────┼─────────────────┤
│ • HTTP & Verbs    │ • JWT Tampering   │ • OAuth 2.0 Flaws │ • Attack Chains │
│ • Burp Suite / cURL│ • Key Confusion  │ • Rate-Limit DDoS │ • GraphQL Exploits│
│ • Recon & Swagger │ • NoSQL / LFI     │ • RCE / SSTI / XXE│ • Cloud / SSRF  │
│ • Baseline BOLA   │ • Path Traversal  │ • Mass Assignment │ • Report Writing│
└───────────────────┴───────────────────┴───────────────────┴─────────────────┘

```

---

## 🟢 Level 1: Beginner (Weeks 1–3)

**Goal:** Understand HTTP transport protocols, API architecture, inspection tooling, and baseline parameter tampering.

### Weekly Breakdown:

* **Week 1: HTTP Protocols & Tooling Setup**
* Core Concepts: REST vs GraphQL, JSON bodies, HTTP methods (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`), HTTP status codes (`401 Unauthorized` vs `403 Forbidden` vs `429 Too Many Requests`).
* Hands-On: Configure Burp Suite proxy, install certificates, and execute raw HTTP requests via `cURL` and Postman.
* *Deliverable:* A custom Postman collection documenting 10 standard API calls.


* **Week 2: API Reconnaissance & Discovery**
* Core Concepts: Attack surface mapping, Swagger/OpenAPI spec harvesting (`/swagger.json`, `/v2/api-docs`, `/openapi.json`), hidden endpoint fuzzing.
* Hands-On: Fuzz target routes using `ffuf` or `kiterunner` with API wordlists.
* *Deliverable:* Complete route map of the local target API.


* **Week 3: Baseline Authorization Flaws (BOLA/IDOR Basics)**
* Core Concepts: Direct object reference exposure in query parameters and URI paths.
* Hands-On: Replace sequential IDs and test cross-tenant data boundaries on `/api/v1/users/{id}`.
* *Deliverable:* Baseline vulnerability report detailing horizontal access control failures.



---

## 🟡 Level 2: Intermediate (Weeks 4–7)

**Goal:** Master token security analysis, cryptographic downgrade attacks, and modern database query selectors.

### Weekly Breakdown:

* **Weeks 4–5: JWT Attacks & Cryptographic Flaws**
* Script: `labs/intermediate/lab1_jwt_attacks.py`
* Core Concepts: Base64URL structure, signature verification workflows, `"alg": "none"` header injection, asymmetric-to-symmetric key confusion (`RS256` $\rightarrow$ `HS256`), weak HMAC dictionary cracking.
* Hands-On: Forge administrative JWT tokens offline and bypass endpoint authentication.


* **Weeks 6–7: Polyglot API Injection Scanning**
* Script: `labs/intermediate/lab2_injection_attacks.py`
* Core Concepts: REST parameter handling, MongoDB/Document-store operator injection (`$gt`, `$ne`, `$regex`, `$where`), file handler path traversal (`../../etc/passwd`), API-reflected XSS.
* Hands-On: Build automated Python scanners to identify SQLi, NoSQLi, and LFI across dynamic parameter routes.



---

## 🟠 Level 3: Critical (Weeks 8–11)

**Goal:** Exploit protocol flaws, bypass layer 7 controls, and execute arbitrary code on backend servers.

### Weekly Breakdown:

* **Week 8: OAuth 2.0 Security Bypass**
* Script: `labs/critical/lab1_oauth2_security_bypass.py`
* Core Concepts: Authorization code flow, CSRF `state` parameter omission, `redirect_uri` validation bypass (parameter pollution, path traversal), unauthenticated token exchange, scope escalation (`scope=admin`).


* **Week 9: Rate Limiting Bypass & Resource Exhaustion**
* Script: `labs/critical/lab2_rate_limit_bypass.py`
* Core Concepts: Reverse proxy IP evaluation, header spoofing (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`), HTTP method override tunneling (`X-HTTP-Method-Override`), concurrency race windows.


* **Week 10: Server-Side Injection & RCE (SSTI / XXE / Commands)**
* Script: `labs/critical/lab3_injection_attacks.py`
* Core Concepts: Template engine context evaluation (Jinja2/Twig/FreeMarker), XML parser external entity expansion (XXE), OS command chaining via shell separators (`;`, `|`, ```).


* **Week 11: Broken Object & Function Level Authorization (BOLA / BFLA)**
* Script: `labs/critical/lab4_sensitive_data_exposure.py`
* Core Concepts: Mass assignment on entity updates (`is_admin: true`), unauthenticated administrative APIs (`/api/v1/admin/*`), regex auditing for leaked API keys, DSNs, and stack traces.



---

## 🔴 Level 4: Expert (Weeks 12–16)

**Goal:** Execute multi-stage attack chains, audit specialized API architectures, and write production-grade penetration testing reports.

### Weekly Breakdown:

* **Weeks 12–13: Advanced Attack Chaining & SSRF**
* Scenario 1: **Mass Assignment $\rightarrow$ BFLA $\rightarrow$ Administrative Takeover**.
* Scenario 2: **BOLA $\rightarrow$ Token Leakage $\rightarrow$ Full Account Takeover**.
* Scenario 3: **SSRF via Webhooks $\rightarrow$ Cloud Metadata Exfiltration (AWS/GCP) $\rightarrow$ IAM Privilege Escalation**.


* **Week 14: GraphQL & Modern API Architectures**
* Core Concepts: Introspection exploitation, query depth/nesting denial-of-service, query batching for credential stuffing, mutation authorization bypasses.


* **Week 15: Mobile API Testing & Reversing**
* Core Concepts: APK decompilation, network security config bypass, SSL pinning evasion via Frida/Objection, hardcoded API secret extraction.


* **Week 16: Professional Reporting & Responsible Disclosure**
* Deliverables: Writing formal penetration test executive summaries, assigning CVSS v3.1 scores, and constructing step-by-step remediation roadmaps for engineering teams.



---

## 🧰 Toolkit Reference Matrix

| Skill Level | Primary Tools | Use Case |
| --- | --- | --- |
| **Beginner** | Burp Suite Community, Postman, cURL, Browser DevTools | Manual request inspection, replay, and parameter tampering |
| **Intermediate** | `ffuf`, `kiterunner`, `jwt_tool`, Python `requests` | Route fuzzing, token manipulation, automated injection scripts |
| **Critical** | Custom Python Harnesses, Docker, Burp Intruder/Turbo Intruder | Race condition testing, protocol bypasses, reverse shell catchers |
| **Expert** | Frida, Objection, GraphQL Voyager, AWS CLI, Cloudfox | Mobile runtime hooking, schema visualization, cloud credential abuse |

---

## 🚀 Quickstart: Running Your Environment

```bash
# 1. Clone the repository
git clone https://github.com/Shanmukhasrisai/API-Penetration-Testing-Lab.git
cd API-Penetration-Testing-Lab

# 2. Launch the local target environment via Docker
docker compose up --build -d

# 3. Install testing dependencies
pip install -r requirements.txt

# 4. Execute a targeted test harness (e.g., Critical Lab 1)
python3 labs/critical/lab1_oauth2_security_bypass.py

```

---

## ⚖️ Legal & Ethical Mandate

All activities must strictly comply with authorized testing boundaries.

* **Explicit Permission:** Only test systems you own or have explicit, documented permission to audit.
* **Responsible Disclosure:** Report vulnerabilities confidentially with reproducible proof-of-concept steps.
* **Protection of Production Data:** Do not perform destructive attacks or denial-of-service simulations against production systems.
