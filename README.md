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
├── api.py                          # Core multi-vector API vulnerability scanner
├── endpoints.json                  # Sample endpoint scan configuration
├── test_api.py                     # Pytest automated test suite
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

```

---

## 🚀 Setup & Installation Guide

### Prerequisites

* **Python 3.8+**
* **Git**
* **Docker & Docker Compose** (for running the local vulnerable target backend)

---

### Step 1: Clone the Repository

#### On Linux / macOS / Windows (Git Bash or Terminal):

```bash
git clone [https://github.com/Shanmukhasrisai/API-Penetration-Testing-Lab.git](https://github.com/Shanmukhasrisai/API-Penetration-Testing-Lab.git)
cd API-Penetration-Testing-Lab

```

---

### Step 2: Virtual Environment Setup & Dependency Installation

#### 🐧 On Linux & macOS:

```bash
# 1. Create a Python virtual environment
python3 -m venv venv

# 2. Activate the virtual environment
source venv/bin/activate

# 3. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

```

#### 🪟 On Windows (PowerShell or Command Prompt):

```powershell
# 1. Create a Python virtual environment
python -m venv venv

# 2. Activate the virtual environment
# In PowerShell:
.\venv\Scripts\Activate.ps1
# In Command Prompt (cmd.exe):
.\venv\Scripts\activate.bat

# 3. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

```

---

### Step 3: Start the Vulnerable Target Backend

Launch the containerized target API backend using Docker:

#### Linux / macOS / Windows:

```bash
docker compose up --build -d

```

*The target application will start at `http://localhost:8080`. You can inspect the interactive OpenAPI documentation at `http://localhost:8080/docs`.*

To stop the target container when finished:

```bash
docker compose down

```

---

## 🧪 Running the Security Scans & Labs

### 1. Core Scanner Engine (`api.py`)

Run automated multi-vector checks (SQLi, NoSQL, Command Injection, XSS) across endpoints defined in `endpoints.json`:

```bash
# Unauthenticated scan with JSON report output
python3 api.py --config endpoints.json --output scan_report.json

# Authenticated scan using a Bearer token
python3 api.py --config endpoints.json --auth "Bearer YOUR_TOKEN_HERE" --output authenticated_report.json

```

*(On Windows Command Prompt, replace `python3` with `python`)*

---

### 2. Intermediate Labs (`labs/intermediate/`)

```bash
# Lab 1: JWT & Authentication Manipulation
python3 labs/intermediate/lab1_jwt_attacks.py

# Lab 2: Targeted API Injection Scanner
python3 labs/intermediate/lab2_injection_attacks.py --url http://localhost:8080 --report intermediate_report.json

```

---

### 3. Critical Labs (`labs/critical/`)

```bash
# Lab 1: OAuth 2.0 Security Bypass & Token Manipulation
python3 labs/critical/lab1_oauth2_security_bypass.py

# Lab 2: Rate Limiting Bypass & DDoS Simulation
python3 labs/critical/lab2_rate_limit_bypass.py

# Lab 3: Modern API Injections (SQLi, NoSQL, Command Injection, SSTI, XXE)
python3 labs/critical/lab3_injection_attacks.py

# Lab 4: Sensitive Data Exposure & BOLA/IDOR Audit
python3 labs/critical/lab4_sensitive_data_exposure.py

```

---

## 🔍 Running Automated Unit Tests

Verify the scanner engine, configuration validation, and mock detection routines using `pytest`:

```bash
pytest -v

```

---

## 📚 Curriculum & Guides

* **[LAB_GUIDE.md](https://www.google.com/search?q=LAB_GUIDE.md)** — Step-by-step module breakdown from beginner to expert.
* **[LEARNING_PATH.md](https://www.google.com/search?q=LEARNING_PATH.md)** — Weekly study schedule, certification paths, and self-assessment checklists.
* **[IMPROVEMENTS.md](https://www.google.com/search?q=IMPROVEMENTS.md)** — Architecture history, changelog, and code improvements.

---

## ⚠️ Legal & Ethical Disclaimer

This repository is developed **strictly for educational research, defensive security engineering, and authorized penetration testing training**.

* Always obtain explicit, written permission before testing any third-party API or network resource.
* Unauthorized scanning, testing, or exploitation of computer systems is illegal.
* The authors assume no liability for misuse of the code or techniques provided.

---

## 📝 License

This project is licensed under the [MIT License](https://www.google.com/search?q=LICENSE).

```

```
