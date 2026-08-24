# 🛠️ Repository Improvements & Architecture Changelog

This document tracks completed enhancements, architectural upgrades, and pending roadmap items for the **API-Penetration-Testing-Lab** repository.

---

## 📊 Status Dashboard

| Category | Status | Details |
| :--- | :--- | :--- |
| **Lab Progression Architecture** | ✅ Completed | Dual-tier curriculum: `intermediate/` (Foundations & JWT) and `critical/` (OWASP Criticals). |
| **Local Dockerized Environment** | ✅ Completed | Containerized FastAPI/Flask backend (`server/app.py` + `docker-compose.yml`). |
| **Dependency Standardization** | ✅ Completed | Unified `requirements.txt` across attacker scripts and target backend. |
| **File Naming & Clean Repository** | ✅ Completed | Eliminated redundant extensions (e.g., `api.py.py` $\rightarrow$ `app.py`); updated `.gitignore`. |
| **Vulnerability Detection Engines** | ✅ Completed | Replaced static string checks with dynamic exploits and statistical blind timing checks. |
| **Manual Burp / cURL Walkthroughs** | ⏳ In Progress | Step-by-step HTTP inspection manuals for zero-knowledge learners. |

---

## 🚀 Key Improvements Implemented

### 1. Dual Architecture (Target Backend vs. Exploit Harness)
- **Local Target Backend (`server/app.py`):** Added a self-hosted FastAPI target exposing genuine, realistic vulnerability endpoints.
- **Docker Compose Setup (`docker-compose.yml`):** Allows instant local deployment (`docker compose up --build -d`) without requiring external network connectivity or cloud infrastructure.

### 2. Upgraded Critical Lab Modules (`labs/critical/`)
- **`lab1_oauth2_security_bypass.py`:**
  - Dynamic CSRF state validation testing.
  - Redirect URI parameter pollution, traversal, and open redirect chaining.
  - JWT `alg: none` token forgery and scope privilege escalation.
- **`lab2_rate_limit_bypass.py`:**
  - Layer 7 IP origin header spoofing (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`).
  - HTTP verb switching and `X-HTTP-Method-Override` testing.
  - URL normalization and path whitespace bypass probes.
  - Synchronized multi-threaded concurrency bursts (`threading.Event`) for race conditions.
- **`lab3_injection_attacks.py`:**
  - Context-aware testing for URL query params, JSON bodies, and XML parsers.
  - Statistical baseline latency calculation for time-based blind SQLi (`pg_sleep()`, `SLEEP()`).
  - NoSQL operator injection (`$gt`, `$ne`, `$regex`, `$where`).
  - Remote OS command injection and multi-engine SSTI validation (Jinja2, Twig, FreeMarker, ERB).
- **`lab4_sensitive_data_exposure.py`:**
  - Multi-tenant BOLA / IDOR verification (cross-account object token exchange).
  - Mass assignment testing on profile update routes (`is_admin`, `role`, `account_balance`).
  - Regex-based response scanning for leaked cloud keys, JWTs, and database DSNs.
  - Verbose error stack trace disclosure profiling.

### 3. Upgraded Intermediate Lab Modules (`labs/intermediate/`)
- **`lab1_jwt_attacks.py`:**
  - Guided step-by-step interactive workflow (Structure $\rightarrow$ Algorithm 'none' $\rightarrow$ Signature Integrity $\rightarrow$ Secret Cracking $\rightarrow$ Key Confusion $\rightarrow$ Expiration).
  - Asymmetric-to-Symmetric (RS256 $\rightarrow$ HS256) Key Confusion attack.
  - Offline dictionary brute-forcing against weak HMAC-SHA256 secrets.
- **`lab2_injection_attacks.py`:**
  - Comprehensive CLI scanner supporting `--url`, `--auth`, `--endpoints`, and `--report`.
  - Detection for SQLi, NoSQL, Path Traversal / LFI, and API-reflected XSS.

### 4. Repository & Tooling Standardization
- **Security-Focused `.gitignore`:** Added rules blocking raw packet captures (`*.pcap`, `*.har`), Burp Suite project files, loot directories, report exports (`*.json`, `*.html`), and private keys (`*.pem`, `*.key`).
- **ANSI Terminal Output:** Standardized color-coded test output across all test harnesses (`[CRITICAL VULNERABILITY]`, `[SECURE]`, evidence, business impact, and remediation steps).

---

## 📋 Recommended Next Steps

1. **Step-by-Step Walkthrough Guides (`walkthroughs/`):**
   - Create Markdown walkthroughs with exact Burp Suite Repeater request/response tabs and cURL snippets for zero-knowledge users.
2. **Beginner Phase (Phase 1):**
   - Implement `labs/beginner/` covering basic REST API recon, endpoint enumeration, Postman collection imports, and standard HTTP status code interpretation.
3. **Advanced Production Attacks (Phase 4):**
   - Add GraphQL introspection, batching, and alias injection labs.
   - Add Server-Side Request Forgery (SSRF) and webhook manipulation labs.

---

## 🔒 Security & Usage Notice

All scripts, target backends, and documentation in this repository are developed strictly for **authorized educational research, defensive security engineering, and penetration testing training**. Testing targets without prior explicit written authorization is illegal.
