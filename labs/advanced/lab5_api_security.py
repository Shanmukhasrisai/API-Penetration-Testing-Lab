"""Lab 5: Advanced API Security & Rate Limiting Bypass
Challenge: Exploit advanced API vulnerabilities including:
- API rate limiting bypass
- API key exposure
- IDOR (Insecure Direct Object Reference)
- Mass assignment
- API version exploitation
- Server-Side Template Injection (SSTI)
"""

from flask import Flask, request, jsonify, render_template_string
from functools import wraps
from datetime import datetime, timedelta
from collections import defaultdict
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'weak_api_key_secret'

# Vulnerable rate limiting (can be bypassed)
rate_limit_tracker = defaultdict(lambda: {'count': 0, 'reset_time': datetime.utcnow()})

# API Keys storage (with weak security)
api_keys_db = {
    'public_key_12345': {'user': 'public_user', 'limit': 100},
    'admin_api_key_67890': {'user': 'admin', 'limit': 1000},
    'test_key_abcdef': {'user': 'test', 'limit': 50},
}

# User data (vulnerable to IDOR)
users_data = {
    1: {'id': 1, 'username': 'admin', 'email': 'admin@example.com', 'balance': 10000},
    2: {'id': 2, 'username': 'user1', 'email': 'user1@example.com', 'balance': 1000},
    3: {'id': 3, 'username': 'user2', 'email': 'user2@example.com', 'balance': 500},
}

products_db = {
    1: {'id': 1, 'name': 'Product A', 'price': 100},
    2: {'id': 2, 'name': 'Product B', 'price': 200},
    3: {'id': 3, 'name': 'Product C', 'price': 150},
}

# ==================== RATE LIMITING BYPASS ====================

def vulnerable_rate_limit(f):
    """Vulnerability 1: Rate limiting that can be bypassed"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # VULNERABLE: Rate limit based only on IP, can be bypassed with X-Forwarded-For
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        # Reset rate limit if time has expired
        if datetime.utcnow() > rate_limit_tracker[client_ip]['reset_time']:
            rate_limit_tracker[client_ip] = {'count': 0, 'reset_time': datetime.utcnow() + timedelta(minutes=1)}
        
        # VULNERABLE: Simple counter-based, can be bypassed by changing IP header
        if rate_limit_tracker[client_ip]['count'] > 10:
            return jsonify({'error': 'Rate limited'}), 429
        
        rate_limit_tracker[client_ip]['count'] += 1
        return f(*args, **kwargs)
    return decorated

@app.route('/api/v1/search', methods=['GET'])
@vulnerable_rate_limit
def vulnerable_search_v1():
    """Vulnerable endpoint with bypassable rate limiting"""
    query = request.args.get('q', '')
    return jsonify({'results': f'Search results for {query}'}), 200

@app.route('/api/v1/data', methods=['GET'])
@vulnerable_rate_limit
def vulnerable_data_v1():
    """Rate limited endpoint"""
    return jsonify({'data': 'sensitive data'}), 200

# ==================== API KEY VULNERABILITIES ====================

@app.route('/api/keys/list', methods=['GET'])
def exposed_api_keys():
    """Vulnerability 2: API keys exposed in response"""
    # VULNERABLE: Returning all API keys
    return jsonify({'api_keys': list(api_keys_db.keys())}), 200

@app.route('/api/keys/validate', methods=['POST'])
def vulnerable_key_validation():
    """Vulnerability 3: Weak API key validation"""
    data = request.get_json()
    api_key = data.get('api_key', '')
    
    # VULNERABLE: Key validation too permissive
    if api_key in api_keys_db or len(api_key) > 5:
        return jsonify({'valid': True, 'user': api_keys_db.get(api_key, {}).get('user', 'guest')}), 200
    
    return jsonify({'valid': False}), 401

@app.route('/api/v2/admin/keys', methods=['GET'])
def api_keys_endpoint():
    """Vulnerability 4: Sensitive data exposed via API version"""
    # VULNERABLE: Different API versions have different security
    return jsonify({'api_keys': api_keys_db}), 200

# ==================== IDOR VULNERABILITIES ====================

@app.route('/api/user/<user_id>', methods=['GET'])
def vulnerable_idor_user(user_id):
    """Vulnerability 5: Insecure Direct Object Reference (IDOR)"""
    try:
        uid = int(user_id)
    except ValueError:
        return jsonify({'error': 'Invalid user ID'}), 400
    
    # VULNERABLE: No authorization check, any user can access any profile
    if uid in users_data:
        return jsonify(users_data[uid]), 200
    
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/user/<user_id>/balance', methods=['GET'])
def vulnerable_idor_balance(user_id):
    """Vulnerability 6: IDOR on sensitive financial data"""
    try:
        uid = int(user_id)
    except ValueError:
        return jsonify({'error': 'Invalid user ID'}), 400
    
    # VULNERABLE: Direct object reference without authorization
    if uid in users_data:
        return jsonify({'balance': users_data[uid]['balance'], 'user': users_data[uid]['username']}), 200
    
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/user/<user_id>', methods=['PUT'])
def vulnerable_idor_update(user_id):
    """Vulnerability 7: IDOR with update capability"""
    try:
        uid = int(user_id)
    except ValueError:
        return jsonify({'error': 'Invalid user ID'}), 400
    
    if uid not in users_data:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    # VULNERABLE: No authorization, can update any user
    users_data[uid].update(data)
    
    return jsonify({'message': 'Updated', 'user': users_data[uid]}), 200

# ==================== MASS ASSIGNMENT ====================

@app.route('/api/product/create', methods=['POST'])
def vulnerable_mass_assignment():
    """Vulnerability 8: Mass assignment vulnerability"""
    data = request.get_json()
    
    # VULNERABLE: Accepting all fields without validation
    new_product = {
        'id': max(products_db.keys()) + 1 if products_db else 1,
        'name': data.get('name', 'Unknown'),
        'price': data.get('price', 0),
        'discount': data.get('discount', 0),  # VULNERABLE: Unintended field
        'hidden': data.get('hidden', False),  # VULNERABLE: Unintended field
        'internal_id': data.get('internal_id', 'auto'),  # VULNERABLE: Unintended field
    }
    
    products_db[new_product['id']] = new_product
    return jsonify(new_product), 201

# ==================== SSTI VULNERABILITY ====================

@app.route('/api/template', methods=['POST'])
def vulnerable_ssti():
    """Vulnerability 9: Server-Side Template Injection (SSTI)"""
    data = request.get_json()
    user_input = data.get('template', '')
    
    # VULNERABLE: Rendering user input as template
    try:
        result = render_template_string(user_input)
        return jsonify({'result': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/format', methods=['POST'])
def vulnerable_format_string():
    """Vulnerability 10: Format string in response"""
    data = request.get_json()
    user_input = data.get('message', 'Hello')
    
    # VULNERABLE: Format string vulnerability
    try:
        result = f"Message: {user_input}"
        return jsonify({'result': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== API VERSION EXPLOITATION ====================

@app.route('/api/v1/status', methods=['GET'])
def status_v1():
    """Old API version with fewer security checks"""
    # VULNERABLE: No authentication required
    return jsonify({'status': 'ok', 'version': 'v1', 'debug_mode': True}), 200

@app.route('/api/v2/status', methods=['GET'])
def status_v2():
    """Newer API version"""
    return jsonify({'status': 'ok', 'version': 'v2'}), 200

# ==================== ADVANCED CHALLENGES ====================

@app.route('/api/challenge/idor', methods=['GET'])
def idor_challenge():
    """Challenge: Exploit IDOR to access admin user data"""
    user_id = request.args.get('id', '')
    
    if user_id == '1':
        return jsonify({'flag': 'FLAG{idor_master}', 'admin_data': users_data.get(1)}), 200
    
    return jsonify({'error': 'Not admin'}), 403

@app.route('/api/challenge/ratelimit', methods=['GET'])
def ratelimit_challenge():
    """Challenge: Bypass rate limiting"""
    return jsonify({'flag': 'FLAG{ratelimit_bypass}'}), 200

@app.route('/api/challenge/api-key', methods=['GET'])
def api_key_challenge():
    """Challenge: Exploit API key"""
    api_key = request.headers.get('X-API-Key')
    
    if api_key in api_keys_db:
        if 'admin' in api_key:
            return jsonify({'flag': 'FLAG{api_key_master}'}), 200
    
    return jsonify({'error': 'Invalid or insufficient privileges'}), 401

if __name__ == '__main__':
    app.run(debug=True, port=5005)
