# API Penetration Testing Lab - Complete Learning Path

## 🎯 Overview
This lab provides a structured, hands-on approach to learning API penetration testing, progressing from beginner to expert level. Each module builds on previous knowledge with practical exercises and real-world scenarios.

---

## 📚 Lab Structure

### **Level 1: BEGINNER (Weeks 1-3)**
Focus: Understanding API fundamentals and basic security concepts

#### Module 1.1: API Fundamentals
- **Topics Covered:**
  - What are APIs? (REST, SOAP, GraphQL)
  - HTTP methods (GET, POST, PUT, DELETE, PATCH)
  - Request/Response structure
  - Status codes and headers
  - Authentication basics (API keys, Basic Auth)

- **Lab Exercises:**
  1. Making API requests with cURL and Postman
  2. Analyzing request/response pairs
  3. Understanding HTTP headers
  4. Basic authentication implementation

#### Module 1.2: Basic API Vulnerabilities
- **Topics Covered:**
  - OWASP API Security Top 10
  - Broken Object Level Authorization (BOLA)
  - Broken Authentication
  - Excessive Data Exposure
  - Information disclosure

- **Lab Exercises:**
  1. Identifying exposed endpoints
  2. Testing parameter manipulation
  3. Analyzing verbose error messages
  4. Basic input validation bypass

#### Module 1.3: Reconnaissance & Information Gathering
- **Topics Covered:**
  - API discovery techniques
  - Documentation analysis
  - Subdomain enumeration
  - Endpoint fuzzing basics

- **Lab Exercises:**
  1. Using Burp Suite to intercept API calls
  2. Discovering hidden endpoints
  3. Analyzing Swagger/OpenAPI specs
  4. Directory brute-forcing

---

### **Level 2: INTERMEDIATE (Weeks 4-7)**
Focus: Advanced vulnerability exploitation and testing methodologies

#### Module 2.1: Authentication & Authorization Attacks
- **Topics Covered:**
  - JWT token analysis and manipulation
  - OAuth 2.0 vulnerabilities
  - Session management flaws
  - Token replay attacks
  - IDOR (Insecure Direct Object References)

- **Lab Exercises:**
  1. JWT token decoding and tampering
  2. None algorithm attack on JWT
  3. OAuth redirect_uri manipulation
  4. Privilege escalation through IDOR
  5. Session fixation attacks

#### Module 2.2: Injection Attacks
- **Topics Covered:**
  - SQL Injection in API parameters
  - NoSQL Injection
  - Command Injection
  - XXE (XML External Entity)
  - XSS through API responses

- **Lab Exercises:**
  1. SQL injection in REST APIs
  2. MongoDB NoSQL injection
  3. Command injection via API endpoints
  4. XXE exploitation in SOAP APIs
  5. Stored XSS through API data

#### Module 2.3: Business Logic & Rate Limiting
- **Topics Covered:**
  - Business logic flaws
  - Rate limiting bypass techniques
  - Mass assignment vulnerabilities
  - Function level authorization
  - Resource exhaustion

- **Lab Exercises:**
  1. Bypassing rate limits with IP rotation
  2. Mass assignment attacks
  3. Price manipulation scenarios
  4. Function-level access control bypass
  5. API resource abuse

---

### **Level 3: ADVANCED (Weeks 8-11)**
Focus: Complex attack chains and specialized API testing

#### Module 3.1: GraphQL Security
- **Topics Covered:**
  - GraphQL introspection
  - Query depth and complexity attacks
  - Batching attacks
  - Field suggestions abuse
  - Authorization in GraphQL

- **Lab Exercises:**
  1. GraphQL introspection enumeration
  2. Nested query DoS attacks
  3. Batching for credential stuffing
  4. Schema poisoning
  5. Mutation abuse scenarios

#### Module 3.2: API Security Testing Automation
- **Topics Covered:**
  - Writing custom scripts for API testing
  - Burp Suite extensions
  - ZAP API scan automation
  - CI/CD integration
  - Custom fuzzing frameworks

- **Lab Exercises:**
  1. Python scripts for API enumeration
  2. Custom Burp extensions
  3. Automated security scanning pipelines
  4. API fuzzing with custom wordlists
  5. Building attack orchestration tools

#### Module 3.3: Advanced Exploitation Techniques
- **Topics Covered:**
  - SSRF (Server-Side Request Forgery)
  - Deserialization attacks
  - API gateway bypass
  - WebSocket security
  - gRPC security testing

- **Lab Exercises:**
  1. Blind SSRF exploitation
  2. Unsafe deserialization in APIs
  3. WAF and API gateway evasion
  4. WebSocket hijacking
  5. gRPC reflection abuse

---

### **Level 4: EXPERT (Weeks 12-16)**
Focus: Real-world scenarios, bug bounty, and advanced research

#### Module 4.1: Complex Attack Chains
- **Topics Covered:**
  - Multi-stage exploitation
  - Chaining vulnerabilities
  - Advanced persistence techniques
  - Data exfiltration methods
  - Pivoting through APIs

- **Lab Exercises:**
  1. BOLA + SQL injection chains
  2. JWT + privilege escalation combinations
  3. SSRF to RCE escalation
  4. Complete account takeover scenarios
  5. API-based lateral movement

#### Module 4.2: Mobile & IoT API Security
- **Topics Covered:**
  - Mobile app API analysis
  - Certificate pinning bypass
  - API key extraction
  - IoT API vulnerabilities
  - Reverse engineering mobile APIs

- **Lab Exercises:**
  1. Intercepting mobile app traffic
  2. SSL pinning bypass techniques
  3. Decompiling APKs for API secrets
  4. IoT device API exploitation
  5. Mobile OAuth implementation flaws

#### Module 4.3: Cloud API Security
- **Topics Covered:**
  - AWS API security
  - Azure API vulnerabilities
  - GCP API testing
  - Cloud metadata API exploitation
  - Serverless API security

- **Lab Exercises:**
  1. AWS IAM privilege escalation
  2. Azure AD token manipulation
  3. GCP service account abuse
  4. SSRF to cloud metadata access
  5. Lambda function exploitation

#### Module 4.4: Bug Bounty & Responsible Disclosure
- **Topics Covered:**
  - Bug bounty methodology
  - Report writing best practices
  - Impact assessment
  - Responsible disclosure
  - Real-world case studies

- **Lab Exercises:**
  1. Conducting full API security assessments
  2. Writing professional security reports
  3. Calculating CVSS scores
  4. Creating proof-of-concept exploits
  5. Live bug bounty practice

---

## 🛠️ Required Tools

### Essential Tools:
- **Burp Suite Professional** - HTTP proxy and testing
- **Postman** - API client
- **cURL** - Command-line HTTP client
- **Python 3.x** - Scripting
- **Git** - Version control

### Intermediate Tools:
- **OWASP ZAP** - Security scanner
- **Ffuf** - Web fuzzer
- **SQLmap** - SQL injection tool
- **JWT_Tool** - JWT manipulation
- **Nuclei** - Vulnerability scanner

### Advanced Tools:
- **Frida** - Dynamic instrumentation
- **Objection** - Mobile testing
- **GraphQL Voyager** - Schema visualization
- **Arjun** - HTTP parameter discovery
- **Kiterunner** - API endpoint discovery

---

## 📋 Prerequisites

### For Beginners:
- Basic understanding of HTTP protocol
- Familiarity with command line
- Basic programming knowledge (any language)

### For Intermediate:
- Completed beginner modules
- Understanding of web application security
- Experience with at least one programming language

### For Advanced/Expert:
- Solid foundation in API security
- Experience with penetration testing
- Proficiency in Python or similar scripting language

---

## 🎓 Learning Outcomes

By completing this lab, you will:

✅ Understand API architectures and security principles
✅ Identify and exploit common API vulnerabilities
✅ Conduct comprehensive API security assessments
✅ Automate API security testing
✅ Perform advanced exploitation techniques
✅ Test cloud and mobile API implementations
✅ Participate effectively in bug bounty programs
✅ Write professional security reports

---

## 📖 How to Use This Lab

1. **Start at Your Level**: Assess your current knowledge and begin at the appropriate level
2. **Follow the Progression**: Complete modules in order, as later modules build on earlier concepts
3. **Hands-On Practice**: Each module includes practical exercises - complete them all
4. **Document Your Learning**: Keep notes and create your own testing methodologies
5. **Practice Responsibly**: Only test on systems you own or have explicit permission to test

---

## 🚀 Getting Started

### Environment Setup:
```bash
# Clone the repository
git clone https://github.com/Shanmukhasrisai/API-Penetration-Testing-Lab.git
cd API-Penetration-Testing-Lab

# Install dependencies
pip install -r requirements.txt

# Start the vulnerable API server
python vulnerable_api.py
```

### Running Specific Labs:
```bash
# Beginner labs
cd labs/beginner
python lab1_basics.py

# Intermediate labs
cd labs/intermediate
python lab1_jwt_attacks.py

# Advanced labs
cd labs/advanced
python lab1_graphql.py

# Expert labs
cd labs/expert
python lab1_attack_chains.py
```

---

## 🔗 Additional Resources

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [PortSwigger API Testing Guide](https://portswigger.net/web-security/api-testing)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)
- [API Security Best Practices](https://github.com/shieldfy/API-Security-Checklist)

---

## 📞 Support & Community

- **Issues**: Report bugs or request features via GitHub Issues
- **Discussions**: Join our community discussions
- **Contributing**: See CONTRIBUTING.md for guidelines

---

## ⚠️ Legal Disclaimer

This lab is for educational purposes only. Always:
- Obtain explicit written permission before testing any API
- Test only on systems you own or have authorization to test
- Follow responsible disclosure practices
- Comply with local laws and regulations

Unauthorized access to computer systems is illegal.

---

## 📝 License

This project is licensed under the MIT License - see LICENSE file for details.

---

**Happy Learning! 🎯**
