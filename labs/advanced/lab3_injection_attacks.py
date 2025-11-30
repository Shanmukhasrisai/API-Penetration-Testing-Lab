"""Lab 3: Advanced Injection Attacks
Challenge: Identify and exploit SQL injection, NoSQL injection, and command injection
Vulnerabilities covered:
- SQL Injection (basic and advanced)
- NoSQL Injection
- Command Injection
- XML External Entity (XXE) Injection
- LDAP Injection
"""

from flask import Flask, request, jsonify
import sqlite3
import subprocess
import json
from pymongo import MongoClient

app = Flask(__name__)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
    ''')
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'admin_pass_123', 'admin@example.com')")
    cursor.execute("INSERT INTO users VALUES (2, 'user', 'user_pass_456', 'user@example.com')")
    conn.commit()
    return conn

db_conn = init_db()

# ==================== SQL INJECTION ====================

@app.route('/api/search/users', methods=['GET'])
def vulnerable_sql_search():
    """Vulnerability 1: SQL Injection in search"""
    search_query = request.args.get('q', '')
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE username LIKE '%{search_query}%'"
    
    try:
        cursor = db_conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        return jsonify({'users': [dict(zip(['id', 'username', 'password', 'email'], row)) for row in results]}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/login', methods=['POST'])
def vulnerable_sql_login():
    """Vulnerability 2: SQL Injection in authentication"""
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    # VULNERABLE: Direct concatenation in authentication query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    try:
        cursor = db_conn.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            return jsonify({'message': 'Login successful', 'username': user[1]}), 200
        else:
            return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/<int:user_id>', methods=['GET'])
def vulnerable_sql_get_user(user_id):
    """Vulnerability 3: SQL Injection via URL parameter"""
    # VULNERABLE: No sanitization
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    try:
        cursor = db_conn.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            return jsonify({'id': user[0], 'username': user[1], 'password': user[2], 'email': user[3]}), 200
        else:
            return jsonify({'message': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== NOSQL INJECTION ====================

@app.route('/api/nosql/search', methods=['POST'])
def vulnerable_nosql_search():
    """Vulnerability 4: NoSQL Injection"""
    data = request.get_json()
    username = data.get('username', '')
    
    # VULNERABLE: Direct object injection
    query = {"username": username}
    
    try:
        # This would connect to MongoDB in production
        # For lab purposes, we'll simulate it
        if isinstance(username, dict):  # Detect object injection
            # If username contains operators like $ne, it's injection
            if any(k.startswith('$') for k in username.keys()):
                return jsonify({'found_users': 'ALL'}), 200  # Simulated injection success
        
        return jsonify({'found_users': []}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== COMMAND INJECTION ====================

@app.route('/api/file/retrieve', methods=['GET'])
def vulnerable_command_injection():
    """Vulnerability 5: Command Injection"""
    filename = request.args.get('file', '')
    
    # VULNERABLE: Direct command execution
    try:
        result = subprocess.check_output(f"cat {filename}", shell=True, text=True)
        return jsonify({'content': result}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ping', methods=['GET'])
def vulnerable_ping():
    """Vulnerability 6: Command Injection in network tools"""
    target = request.args.get('target', '')
    
    # VULNERABLE: Command injection
    try:
        result = subprocess.check_output(f"ping -c 4 {target}", shell=True, text=True)
        return jsonify({'ping_result': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/image/resize', methods=['POST'])
def vulnerable_image_command():
    """Vulnerability 7: Command Injection via image processing"""
    data = request.get_json()
    image_path = data.get('image_path', '')
    width = data.get('width', '100')
    height = data.get('height', '100')
    
    # VULNERABLE: Unsanitized parameters in command
    try:
        result = subprocess.check_output(f"convert {image_path} -resize {width}x{height} output.jpg", shell=True, text=True)
        return jsonify({'status': 'Image resized'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== XXE INJECTION ====================

@app.route('/api/xml/parse', methods=['POST'])
def vulnerable_xml_injection():
    """Vulnerability 8: XML External Entity (XXE) Injection"""
    xml_data = request.data.decode('utf-8')
    
    try:
        import xml.etree.ElementTree as ET
        # VULNERABLE: No XXE protection
        root = ET.fromstring(xml_data)
        data = root.find('data').text
        return jsonify({'data': data}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== LDAP INJECTION ====================

@app.route('/api/ldap/search', methods=['GET'])
def vulnerable_ldap_injection():
    """Vulnerability 9: LDAP Injection"""
    username = request.args.get('username', '')
    
    # VULNERABLE: Direct LDAP filter concatenation
    ldap_filter = f"(uid={username})"
    
    # Simulated LDAP query - in reality this would query an LDAP server
    if '*' in username or ')' in username or '(' in username:
        return jsonify({'found': 'LDAP Injection Detected'}), 200
    
    return jsonify({'found': []}), 200

# ==================== ADVANCED CHALLENGES ====================

@app.route('/api/admin/export', methods=['GET'])
def vulnerable_export_injection():
    """Vulnerability 10: Multiple injection vectors combined"""
    format_type = request.args.get('format', 'csv')
    filters = request.args.get('filters', '')
    
    # VULNERABLE: Multiple injection points
    try:
        if format_type == 'csv':
            query = f"SELECT * FROM users WHERE {filters}"
            cursor = db_conn.cursor()
            cursor.execute(query)
            results = cursor.fetchall()
            return jsonify({'data': results}), 200
        elif format_type == 'json':
            # Command injection here
            result = subprocess.check_output(f"sqlite3 test.db 'SELECT * FROM users WHERE {filters}'", shell=True, text=True)
            return jsonify({'data': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/challenge/injection', methods=['GET'])
def injection_challenge():
    """Challenge: Exploit any injection vulnerability to get the flag"""
    payload = request.args.get('payload', '')
    
    # Check various injection patterns
    if any(pattern in payload for pattern in ["' OR '", "1' OR '1", "admin' --", "; DROP TABLE"]):
        return jsonify({'flag': 'FLAG{injection_master}'}), 200
    
    return jsonify({'message': 'Invalid payload'}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5003)
