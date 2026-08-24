"""
Automated Test Suite for API Penetration Testing Lab
Validates core scanner engine (api.py), payload matrices, configuration parsing,
and repository structure.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

# Import the core scanner module
import api


# ==============================================================================
# 1. Structural & Environmental Tests
# ==============================================================================
def test_labs_directory_structure():
    """Verify that all lab tiers and essential subdirectories exist."""
    base_dirs = [
        Path("labs"),
        Path("labs/intermediate"),
        Path("labs/critical"),
        Path("server"),
    ]
    for directory in base_dirs:
        assert directory.exists(), f"Expected directory '{directory}' does not exist"
        assert directory.is_dir(), f"'{directory}' must be a valid directory"


def test_lab_scripts_exist():
    """Verify that all core attack harnesses and target servers exist."""
    expected_files = [
        Path("api.py"),
        Path("requirements.txt"),
        Path("docker-compose.yml"),
        Path("server/app.py"),
        Path("labs/intermediate/lab1_jwt_attacks.py"),
        Path("labs/intermediate/lab2_injection_attacks.py"),
        Path("labs/critical/lab1_oauth2_security_bypass.py"),
        Path("labs/critical/lab2_rate_limit_bypass.py"),
        Path("labs/critical/lab3_injection_attacks.py"),
        Path("labs/critical/lab4_sensitive_data_exposure.py"),
    ]
    for script_path in expected_files:
        assert script_path.exists(), f"Missing lab file: '{script_path}'"
        assert script_path.is_file(), f"'{script_path}' should be a file"


# ==============================================================================
# 2. Configuration Loader Tests
# ==============================================================================
def test_load_valid_config():
    """Verify that valid JSON configuration is properly loaded."""
    valid_data = {
        "endpoints": [
            {"url": "http://localhost:8080/api/v1/search", "method": "GET", "params": ["q"]},
            {"url": "http://localhost:8080/api/v1/auth/login", "method": "POST", "params": ["username", "password"]},
        ]
    }
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tmp:
        json.dump(valid_data, tmp)
        tmp_name = tmp.name

    try:
        endpoints = api.load_endpoints_config(tmp_name)
        assert len(endpoints) == 2
        assert endpoints[0]["url"] == "http://localhost:8080/api/v1/search"
        assert endpoints[1]["method"] == "POST"
    finally:
        os.remove(tmp_name)


def test_load_invalid_json_config():
    """Verify that malformed JSON raises SystemExit."""
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tmp:
        tmp.write("{ invalid_json: true, }")
        tmp_name = tmp.name

    try:
        with pytest.raises(SystemExit):
            api.load_endpoints_config(tmp_name)
    finally:
        os.remove(tmp_name)


def test_load_nonexistent_config():
    """Verify that a missing configuration file raises SystemExit."""
    with pytest.raises(SystemExit):
        api.load_endpoints_config("non_existent_file_xyz.json")


# ==============================================================================
# 3. HTTP Engine & Vulnerability Detection Tests (Mocked)
# ==============================================================================
@patch("api.requests.request")
def test_make_request_success(mock_request):
    """Test successful HTTP request execution."""
    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.text = "OK"
    mock_res.headers = {"Content-Type": "application/json"}
    mock_request.return_value = mock_res

    status, text, headers = api.make_request(
        url="http://localhost:8080/api/test",
        method="GET",
        headers={"User-Agent": "TestAgent"},
    )
    assert status == 200
    assert text == "OK"
    assert "Content-Type" in headers


@patch("api.requests.request")
def test_make_request_timeout(mock_request):
    """Test request timeout handling."""
    mock_request.side_effect = requests.exceptions.Timeout("Connection timeout")

    status, text, headers = api.make_request(
        url="http://localhost:8080/api/slow",
        method="GET",
        headers={},
    )
    assert status is None
    assert text == "TIMEOUT"
    assert headers is None


@patch("api.make_request")
def test_detect_sql_injection(mock_make_request):
    """Verify that SQL error patterns are accurately detected."""
    mock_make_request.return_value = (
        500,
        "sqlite3.OperationalError: syntax error in query expression near 'UNION'",
        {},
    )

    finding = api.test_sql_injection(
        url="http://localhost:8080/api/v1/search",
        method="GET",
        headers={},
        param_name="q",
        timeout=5,
    )
    assert finding is not None
    assert finding["vulnerability"] == "Error-Based SQL Injection"
    assert finding["severity"] == "CRITICAL"


@patch("api.make_request")
def test_detect_xss(mock_make_request):
    """Verify that unencoded script reflections are flagged as XSS."""
    mock_make_request.return_value = (
        200,
        "Search results for: <script>alert('SEC_XSS')</script>",
        {"Content-Type": "text/html"},
    )

    finding = api.test_xss(
        url="http://localhost:8080/api/v1/search",
        method="GET",
        headers={},
        param_name="q",
        timeout=5,
    )
    assert finding is not None
    assert finding["vulnerability"] == "Reflected Cross-Site Scripting (XSS)"
    assert finding["severity"] == "HIGH"


@patch("api.make_request")
def test_detect_command_injection(mock_make_request):
    """Verify that reflected execution tokens are flagged as Command Injection."""
    mock_make_request.return_value = (
        200,
        "Search Results:\nSEC_CMD_VULN\nFile not found",
        {"Content-Type": "text/plain"},
    )

    finding = api.test_command_injection(
        url="http://localhost:8080/api/v1/search",
        method="GET",
        headers={},
        param_name="q",
        timeout=5,
    )
    assert finding is not None
    assert finding["vulnerability"] == "Remote OS Command Injection"
    assert finding["severity"] == "CRITICAL"


# ==============================================================================
# 4. Audit Execution & Reporting Tests
# ==============================================================================
@patch("api.test_sql_injection")
@patch("api.test_command_injection")
@patch("api.test_nosql_injection")
@patch("api.test_xss")
def test_run_endpoint_audit(mock_xss, mock_nosql, mock_cmd, mock_sqli):
    """Verify that endpoint audit orchestrates tests and aggregates findings."""
    mock_sqli.return_value = {
        "vulnerability": "Error-Based SQL Injection",
        "parameter": "id",
        "payload": "' OR '1'='1",
        "severity": "CRITICAL",
        "evidence": "SQL syntax error",
        "remediation": "Use parameterized queries",
    }
    mock_cmd.return_value = None
    mock_nosql.return_value = None
    mock_xss.return_value = None

    endpoint = {
        "url": "http://localhost:8080/api/v1/users",
        "method": "GET",
        "params": ["id"],
    }

    result = api.run_endpoint_audit(endpoint, headers={}, timeout=5)

    assert result["url"] == "http://localhost:8080/api/v1/users"
    assert len(result["vulnerabilities"]) == 1
    assert result["vulnerabilities"][0]["vulnerability"] == "Error-Based SQL Injection"
