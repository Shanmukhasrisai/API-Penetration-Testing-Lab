# 🛡️ API Penetration Testing Lab

A comprehensive, industry-grade API penetration testing and learning laboratory designed to guide security professionals, developers, and students from zero-knowledge to expert-level vulnerability discovery, exploitation, and remediation.

---

## 🌟 Key Features

- **Dual-Layer Architecture:** Includes a self-hosted, vulnerable REST backend target (`server/app.py`) running in Docker alongside automated attacker verification scripts.
- **Multi-Tier Curriculum:** Structured labs categorized into **Beginner**, **Intermediate**, **Critical**, and **Expert** phases.
- **Production-Grade Exploit Harnesses:** Fully functional Python scripts (`requests`, `jwt`, `threading`) that test real-world vulnerability patterns.
- **OWASP API Top 10 Coverage:** Systematic checks for BOLA/IDOR, Broken Authentication, Mass Assignment, Injection, Rate Limiting Flaws, and Security Misconfigurations.
- **Exportable Audit Reporting:** Automated color-coded terminal output paired with structured JSON reporting options.

---

## 📁 Repository Structure

```text
API-Penetration-Testing-Lab/
├── docker-compose.yml              # Single-command target container environment
├── requirements.txt                # Unified dependency list
├── IMPROVEMENTS.md                 # Changelog and architectural evolution
├── LAB_GUIDE.md                    # Complete module-by-module learning path
├── LEARNING_PATH.md                # Self-assessment and weekly study schedule
├── LICENSE                         # MIT License
├── server/
│   └── app.py                      # Vulnerable FastAPI target backend
└── labs/
    ├── intermediate/               # JWT security and injection audit scripts
    │   ├── lab1_jwt_attacks.py
    │   └── lab2_injection_attacks.py
    └── critical/                   # Critical-tier exploit harnesses
        ├── lab1_oauth2_security_bypass.py
        ├── lab2_rate_limit_bypass.py
        ├── lab3_injection_attacks.py
        └── lab4_sensitive_data_exposure.py
