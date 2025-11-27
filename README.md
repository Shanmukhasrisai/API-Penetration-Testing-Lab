# API-Penetration-Testing-Lab

A comprehensive API penetration testing lab designed to help security professionals test API endpoints for common vulnerabilities including XSS and SQL injection.

## Features

- **Dynamic Endpoint Testing**: Configure multiple API endpoints via JSON configuration file
- **Authentication Support**: Supports Authorization headers (Bearer tokens, API keys)
- **Multiple Vulnerability Tests**:
  - Reflected XSS detection
  - SQL Injection detection
- **Detailed Reporting**: Generates comprehensive JSON reports with timestamps
- **Flexible Configuration**: Easily customize test parameters and endpoints

## Installation

### Prerequisites

Before setting up the project, ensure you have the following installed:

- Python 3.7 or higher
- pip (Python package installer)
- Git

### Setup Instructions

#### 1. Clone the Repository

You can clone this repository using HTTPS or SSH:

**Using HTTPS:**
```bash
git clone https://github.com/Shanmukhasrisai/API-Penetration-Testing-Lab.git
```

**Using SSH:**
```bash
git clone git@github.com:Shanmukhasrisai/API-Penetration-Testing-Lab.git
```

**Using GitHub CLI:**
```bash
gh repo clone Shanmukhasrisai/API-Penetration-Testing-Lab
```

#### 2. Navigate to Project Directory

```bash
cd API-Penetration-Testing-Lab
```

#### 3. Create a Virtual Environment (Recommended)

Creating a virtual environment helps isolate project dependencies:

**On Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**On macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

#### 4. Install Required Dependencies

```bash
pip install -r requirements.txt
```

The required dependencies include:
- Flask (for potential web interface)
- requests (for HTTP requests)
- colorama (for colored terminal output)

## Usage

### Basic Usage

To run a penetration test on configured API endpoints:

```bash
python api.py --config endpoints.json
```

### With Authentication

To test endpoints that require authentication:

```bash
python api.py --config endpoints.json --auth "Bearer YOUR_TOKEN_HERE"
```

or with an API key:

```bash
python api.py --config endpoints.json --auth "APIKey YOUR_KEY_HERE"
```

### Save Results to File

To save the test results to a JSON file:

```bash
python api.py --config endpoints.json --output results.json
```

### Configuration File Format

Create a JSON configuration file (e.g., `endpoints.json`) with the following structure:

```json
{
  "endpoints": [
    {
      "url": "https://example.com/api/search",
      "method": "GET",
      "params": ["q", "filter"]
    },
    {
      "url": "https://example.com/api/users",
      "method": "POST",
      "params": ["username", "email"]
    }
  ]
}
```

## Command Line Options

- `--config`: **(Required)** Path to JSON configuration file with API endpoints
- `--auth`: Authorization header value (e.g., 'Bearer <token>' or 'APIKey <key>')
- `--output`: Path to save JSON report file

## Vulnerability Detection

### Reflected XSS

The tool tests for reflected cross-site scripting by injecting various XSS payloads and checking if they're reflected in the response.

### SQL Injection

The tool tests for SQL injection vulnerabilities by injecting SQL-specific payloads and checking for database error messages in responses.

## Report Format

The tool generates detailed JSON reports with the following structure:

```json
{
  "url": "https://example.com/api/endpoint",
  "method": "GET",
  "vulnerabilities": {
    "reflected_xss": ["param1"],
    "sql_injection": ["param2"]
  }
}
```

## Troubleshooting

- **Permission Errors**: Try running commands with `sudo` (Linux/macOS) or as Administrator (Windows)
- **Module Not Found**: Ensure you've activated the virtual environment and installed dependencies
- **Dependency Installation Fails**: Try upgrading pip first: `pip install --upgrade pip`
- **Virtual Environment Issues**: Make sure you've activated the virtual environment before installing dependencies
- **Connection Errors**: Verify that target URLs are accessible and properly formatted

## Important Notes

### ⚠️ Legal and Ethical Considerations

- This tool is designed for **educational purposes only**
- Only use this tool on systems you **own** or have **explicit written permission** to test
- Unauthorized penetration testing is **illegal** and unethical
- Always follow responsible disclosure practices
- Respect the privacy and security of others

### Best Practices

- Always obtain proper authorization before conducting penetration tests
- Document all testing activities
- Follow your organization's security policies
- Report vulnerabilities responsibly
- Do not use this tool in production environments without proper safeguards

## Improvements

For a comprehensive list of improvements and enhancements made to this repository, see [IMPROVEMENTS.md](IMPROVEMENTS.md).

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests to improve this tool.

## License

Review the LICENSE file for usage terms and conditions.

## Disclaimer

This tool is provided for educational and authorized testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have explicit permission before testing any systems you do not own.
