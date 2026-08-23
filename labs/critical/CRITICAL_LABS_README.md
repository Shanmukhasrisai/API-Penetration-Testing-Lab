# 🛡️ Critical API Penetration Testing Labs (Zero to Industry Expert)

## 📌 Overview

This directory contains production-grade, simulated **CRITICAL** API vulnerabilities. Unlike theoretical labs, this environment provides a dual-layer setup:
1. **A live vulnerable REST backend** that mimics modern microservice architectures (FastAPI/Flask).
2. **Manual and automated exploit toolkits** accompanied by industry remediation blueprints.

Each lab is structured into a 4-phase pedagogical loop:
- **Concept & Architecture:** How the mechanism works in legitimate production environments.
- **The Root Flaw:** The specific code defect causing the vulnerability.
- **Hands-On Exploitation:** Manual reproduction (cURL/Burp Suite) followed by automated verification (`.py` scripts).
- **Hardening & Defense:** Production-ready code fixes and architectural safeguards.

---

## 🗺️ Lab Progression Roadmap

| Lab | Focus Area | OWASP API Top 10 | Real-World Attack Technique | Skill Level |
| :--- | :--- | :--- | :--- | :--- |
| **Lab 1** | OAuth 2.0 & Token Abuse | API2: Broken Auth | State CSRF, Redirect hijacking, JWT `alg: none` & secret brute-force | Intermediate → Advanced |
| **Lab 2** | Rate Limiting & Resource Exhaustion | API4: Resource Consumption | Header spoofing (`X-Forwarded-For`), HTTP method flipping, race conditions | Beginner → Intermediate |
| **Lab 3** | Polyglot Injection | API8: Security Misconfiguration | SQLi, NoSQL `$where` / operator injection, OS command execution | Intermediate → Advanced |
| **Lab 4** | Auth Bypass & BOLA/IDOR | API1: BOLA & API3: Data Exposure | Object-level tampering, mass assignment, debug error leaks | Beginner → Advanced |

---

## 📁 Repository Structure

```text
critical_labs/
├── docker-compose.yml              # Single-command lab environment
├── server/                         # Vulnerable backend target
│   ├── app.py                      # FastAPI/Flask target server
│   ├── models.py                   # Vulnerable DB & ORM models
│   └── requirements.txt
├── exploits/                       # Exploit & verification scripts
│   ├── lab1_oauth2_security_bypass.py
│   ├── lab2_rate_limit_bypass.py
│   ├── lab3_injection_attacks.py
│   └── lab4_sensitive_data_exposure.py
└── walkthroughs/                   # Step-by-step Burp/cURL guides
    ├── LAB1_WALKTHROUGH.md
    ├── LAB2_WALKTHROUGH.md
    ├── LAB3_WALKTHROUGH.md
    └── LAB4_WALKTHROUGH.md
