"""Lab 3: Advanced Injection Attacks
Challenge: Identify and exploit SQL injection, NoSQL injection, Command injection, and XXE.
Vulnerabilities covered:
- SQL Injection (Authentication Bypass, Search, and URL parameter extraction)
- NoSQL Injection ($ne / operator evaluation simulation)
- OS Command Injection
- XML External Entity (XXE) Injection
- LDAP Filter Injection
"""

from flask import Flask, request, jsonify
import sqlite3
import subprocess
import re
import os

app = Flask(__name__)
DB_PATH = 'lab3_injection.db'


def init_db():
    """Initializes a shared SQLite database for thread-safe testing."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
    ''')
    cursor.execute("DELETE FROM users")
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'admin_pass_123', 'admin@example.com')")
    cursor.execute("INSERT INTO users VALUES (2, 'john_doe', 'user_pass_456', 'john@example.com')")
    cursor.execute("INSERT INTO users VALUES (3, 'alice', 'alice_pass_789', 'alice@example.com')")
    conn.commit()
    return conn


db_conn = init_db()


# ==================== SQL INJECTION ====================

@app.route('/api/search/users', methods=['GET'])
def vulnerable_sql_search():
    """Vulnerability 1: SQL Injection in search query."""
    search_query = request.args.get('q', '')
    query = f"SELECT id, username, email FROM users WHERE username LIKE '%{search_query}%'"
    
    try:
        cursor = db_conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        return jsonify({'users': [dict(zip(['id', 'username', 'email'], row)) for row in results]}), 200
    except Exception as e:
        return jsonify({'error': str(e), 'executed_query': query}), 500


@app.route('/api/user/login', methods=['POST'])
def vulnerable_sql_login():
    """Vulnerability 2: SQL Injection in authentication."""
    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')
    
    query = f"SELECT id, username, email FROM users WHERE username = '{username}' AND password = '{password}'"
    
    try:
        cursor = db_conn.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            return jsonify({
                'message': 'Login successful',
                'user': {'id': user[0], 'username': user[1], 'email': user[2]}
            }), 200
        return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': str(e), 'executed_query': query}), 500


@app.route('/api/user/<user_id>', methods=['GET'])
def vulnerable_sql_get_user(user_id):
    """Vulnerability 3: SQL Injection via URL parameter (string type allows payload)."""
    query = f"SELECT id, username, email FROM users WHERE id = {user_id}"
    
    try:
        cursor = db_conn.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            return jsonify({'id': user[0], 'username': user[1], 'email': user[2]}), 200
        return jsonify({'message': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e), 'executed_query': query}), 500


# ==================== NOSQL INJECTION ====================

@app.route('/api/nosql/search', methods=['POST'])
def vulnerable_nosql_search():
    """Vulnerability 4: Simulated NoSQL / MongoDB Operator Injection."""
    data = request.get_json(silent=True) or {}
    username_field = data.get('username')
    
    # Mock document collection
    mock_users = [
        {"username": "admin", "role": "administrator", "secret": "sec_admin_987"},
        {"username": "developer", "role": "dev", "secret": "sec_dev_321"}
    ]
    
    try:
        # Check if client passed a NoSQL operator dictionary, e.g. {"$ne": ""} or {"$gt": ""}
        if isinstance(username_field, dict):
            if any(k.startswith('$') for k in username_field.keys()):
                # Injection successfully evaluated
                return jsonify({'status': 'success', 'records': mock_users}), 200
        
        # Standard search
        matched = [u for u in mock_users if u['username'] == username_field]
        return jsonify({'status': 'success', 'records': matched}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== COMMAND INJECTION ====================

@app.route('/api/file/retrieve', methods=['GET'])
def vulnerable_command_injection():
    """Vulnerability 5: OS Command Injection via file viewing tool."""
    filename = request.args.get('file', 'sample.txt')
    cmd = f"cat {filename}" if os.name != 'nt' else f"type {filename}"
    
    try:
        output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
        return jsonify({'output': output}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({'error': 'Execution error', 'output': e.output}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ping', methods=['GET'])
def vulnerable_ping():
    """Vulnerability 6: Command Injection in network diagnostics."""
    target = request.args.get('target', '127.0.0.1')
    flag = "-n 1" if os.name == 'nt' else "-c 1"
    cmd = f"ping {flag} {target}"
    
    try:
        output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
        return jsonify({'ping_result': output}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({'error': 'Ping failed', 'details': e.output}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== XXE INJECTION ====================

@app.route('/api/xml/parse', methods=['POST'])
def vulnerable_xml_injection():
    """Vulnerability 7: XML External Entity (XXE) demonstration parser."""
    raw_xml = request.data.decode('utf-8', errors='ignore')
    
    try:
        # Check for external entity declarations
        entity_match = re.search(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+["\'](.*?)["\']>', raw_xml, re.IGNORECASE)
        
        if entity_match:
            entity_name = entity_match.group(1)
            file_target = entity_match.group(2).replace('file://', '')
            
            # Simulate resolving external entity content for the lab
            if os.path.exists(file_target):
                with open(file_target, 'r') as f:
                    resolved_content = f.read()
            else:
                resolved_content = f"[SIMULATED FILE CONTENT: root:x:0:0:root:/root:/bin/bash for {file_target}]"
            
            return jsonify({
                'status': 'parsed',
                'extracted_data': resolved_content,
                'vulnerability': 'XXE_SUCCESS'
            }), 200

        return jsonify({'status': 'parsed', 'extracted_data': 'Standard XML processed without external entities'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== LDAP INJECTION ====================

@app.route('/api/ldap/search', methods=['GET'])
def vulnerable_ldap_injection():
    """Vulnerability 8: Simulated LDAP Filter Injection."""
    username = request.args.get('username', '')
    ldap_filter = f"(&(objectClass=user)(uid={username}))"
    
    # Check for wildcards / operator bypass
    if any(char in username for char in ['*', ')(', ')|(', ')(']):
        return jsonify({
            'status': 'success',
            'filter_evaluated': ldap_filter,
            'entries': [
                {'dn': 'uid=admin,ou=users,dc=lab,dc=local', 'role': 'Domain Admin'},
                {'dn': 'uid=service_account,ou=users,dc=lab,dc=local', 'role': 'Service'}
            ]
        }), 200
    
    return jsonify({'status': 'success', 'filter_evaluated': ldap_filter, 'entries': []}), 200


# ==================== CHALLENGE ENDPOINT ====================

@app.route('/api/challenge/injection', methods=['GET'])
def injection_challenge():
    """Flag challenge endpoint."""
    payload = request.args.get('payload', '')
    if any(pattern in payload.lower() for pattern in ["' or '", "1' or '1", "admin' --", "; drop table", "||", ";cat"]):
        return jsonify({'flag': 'FLAG{adv_injection_polyglot_solved}'}), 200
    
    return jsonify({'message': 'Invalid injection payload'}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=True)
