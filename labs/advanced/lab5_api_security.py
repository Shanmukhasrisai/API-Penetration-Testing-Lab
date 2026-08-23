"""Lab 5: Advanced API Security & Rate Limiting Bypass
Challenge: Exploit advanced API vulnerabilities including:
- API rate limiting bypass (X-Forwarded-For header spoofing)
- API key exposure & weak validation
- IDOR (Insecure Direct Object Reference) on data & modification
- Mass assignment on object creation
- Server-Side Template Injection (SSTI)
- Broken API versioning access control
"""

from flask import Flask, request, jsonify, render_template_string
from functools import wraps
from datetime import datetime, timezone, timedelta
from collections import defaultdict

app = Flask(__name__)
app.config['SECRET_KEY'] = 'weak_api_key_secret'

# Track rate limiting per IP dynamically
rate_limit_tracker = defaultdict(dict)

# Vulnerable API Keys database
api_keys_db = {
    'public_key_12345': {'user': 'public_user', 'role': 'user', 'limit': 100},
    'admin_api_key_67890': {'user': 'admin', 'role': 'admin', 'limit': 1000},
    'test_key_abcdef': {'user': 'test', 'role': 'tester', 'limit': 50},
}

# In-memory user data (vulnerable to IDOR)
users_data = {
    1: {'id': 1, 'username': 'admin', 'email': 'admin@example.com', 'role': 'admin', 'balance': 10000},
    2: {'id': 2, 'username': 'user1', 'email': 'user1@example.com', 'role': 'user', 'balance': 1000},
    3: {'id': 3, 'username': 'user2', 'email': 'user2@example.com', 'role': 'user', 'balance': 500},
}

# Products data (vulnerable to mass assignment)
products_db = {
    1: {'id': 1, 'name': 'Standard Subscription', 'price': 100, 'discount': 0, 'is_admin_only': False},
    2: {'id': 2, 'name': 'Enterprise Subscription', 'price': 500, 'discount': 0, 'is_admin_only': False},
}


# ==================== RATE LIMITING BYPASS ====================

def vulnerable_rate_limit(f):
    """Vulnerability 1: Rate limiting using spoofable X-Forwarded-For IP."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Vulnerability: Spoofable header lookup
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1')
        client_ip = client_ip.split(',')[0].strip()
        
        now = datetime.now(timezone.utc)
        record = rate_limit_tracker.get(client_ip)
        
        if not record or now > record.get('reset_time', now):
            rate_limit_tracker[client_ip] = {
                'count': 1,
                'reset_time': now + timedelta(minutes=1)
            }
        else:
            if record['count'] >= 5:
                return jsonify({
                    'error': 'Rate limit exceeded (5 requests/min)',
                    'hint': 'Change your client IP via X-Forwarded-For header to bypass'
                }), 429
            record['count'] += 1

        return f(*args, **kwargs)
    return decorated


@app.route('/api/v1/search', methods=['GET'])
@vulnerable_rate_limit
def vulnerable_search_v1():
    query = request.args.get('q', 'all')
    return jsonify({'results': f'Search records for query: {query}'}), 200


@app.route('/api/v1/data', methods=['GET'])
@vulnerable_rate_limit
def vulnerable_data_v1():
    return jsonify({'data': 'Sensitive analytics payload'}), 200


# ==================== API KEY VULNERABILITIES ====================

@app.route('/api/keys/list', methods=['GET'])
def exposed_api_keys():
    """Vulnerability 2: Unauthenticated exposure of internal API keys."""
    return jsonify({'api_keys': list(api_keys_db.keys())}), 200


@app.route('/api/keys/validate', methods=['POST'])
def vulnerable_key_validation():
    """Vulnerability 3: Permissive validation checking key length or prefix."""
    data = request.get_json(silent=True) or {}
    api_key = data.get('api_key', '')
    
    if api_key in api_keys_db:
        return jsonify({'valid': True, 'user_context': api_keys_db[api_key]}), 200
    
    # Vulnerability: Accepts any string starting with 'admin_'
    if api_key.startswith('admin_'):
        return jsonify({'valid': True, 'user_context': {'user': 'inferred_admin', 'role': 'admin'}}), 200
        
    return jsonify({'valid': False, 'message': 'Invalid API Key'}), 401


@app.route('/api/v2/admin/keys', methods=['GET'])
def api_keys_endpoint():
    """Vulnerability 4: Sensitive key metadata exposed via legacy /v2 route."""
    return jsonify({'api_keys_metadata': api_keys_db}), 200


# ==================== IDOR VULNERABILITIES ====================

@app.route('/api/user/<user_id>', methods=['GET'])
def vulnerable_idor_user(user_id):
    """Vulnerability 5: Insecure Direct Object Reference (read)."""
    try:
        uid = int(user_id)
    except ValueError:
        return jsonify({'error': 'User ID must be an integer'}), 400
    
    if uid in users_data:
        return jsonify(users_data[uid]), 200
    
    return jsonify({'error': 'User not found'}), 404


@app.route('/api/user/<user_id>/balance', methods=['GET'])
def vulnerable_idor_balance(user_id):
    """Vulnerability 6: IDOR on financial balance."""
    try:
        uid = int(user_id)
    except ValueError:
        return jsonify({'error': 'User ID must be an integer'}), 400
    
    if uid in users_data:
        return jsonify({'id': uid, 'balance': users_data[uid]['balance'], 'username': users_data[uid]['username']}), 200
    
    return jsonify({'error': 'User not found'}), 404


@app.route('/api/user/<user_id>', methods=['PUT', 'PATCH'])
def vulnerable_idor_update(user_id):
    """Vulnerability 7: IDOR update with missing authorization."""
    try:
        uid = int(user_id)
    except ValueError:
        return jsonify({'error': 'User ID must be an integer'}), 400
    
    if uid not in users_data:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json(silent=True) or {}
    users_data[uid].update(data)
    
    return jsonify({'message': 'User record updated', 'updated_profile': users_data[uid]}), 200


# ==================== MASS ASSIGNMENT ====================

@app.route('/api/product/create', methods=['POST'])
def vulnerable_mass_assignment():
    """Vulnerability 8: Unfiltered object parameter binding."""
    data = request.get_json(silent=True) or {}
    
    new_id = max(products_db.keys()) + 1 if products_db else 1
    new_product = {
        'id': new_id,
        'name': data.get('name', 'Default Product'),
        'price': data.get('price', 10),
        'discount': data.get('discount', 0),                  # Unintended attribute
        'is_admin_only': data.get('is_admin_only', False),    # Privileged attribute
        'internal_token': data.get('internal_token', 'TOKEN_NONE')
    }
    
    products_db[new_id] = new_product
    return jsonify({'status': 'created', 'product': new_product}), 201


# ==================== SSTI VULNERABILITY ====================

@app.route('/api/template', methods=['POST'])
def vulnerable_ssti():
    """Vulnerability 9: Server-Side Template Injection via Jinja2."""
    data = request.get_json(silent=True) or {}
    user_template = data.get('template', 'Hello {{ name }}')
    
    try:
        rendered = render_template_string(user_template, name="Researcher")
        return jsonify({'status': 'success', 'rendered': rendered}), 200
    except Exception as e:
        return jsonify({'error': f'Template compilation failed: {str(e)}'}), 400


# ==================== CHALLENGE ENDPOINTS ====================

@app.route('/api/challenge/idor', methods=['GET'])
def idor_challenge():
    """Challenge: Access admin profile (ID=1)."""
    user_id = request.args.get('id', '')
    if user_id == '1':
        return jsonify({
            'status': 'solved',
            'flag': 'FLAG{idor_privilege_escalation_master}',
            'admin_data': users_data.get(1)
        }), 200
    
    return jsonify({'error': 'Requires admin record access (id=1)'}), 403


@app.route('/api/challenge/api-key', methods=['GET'])
def api_key_challenge():
    """Challenge: Authenticate with an admin API key."""
    api_key = request.headers.get('X-API-Key', '')
    
    if api_key in api_keys_db and api_keys_db[api_key].get('role') == 'admin':
        return jsonify({'status': 'solved', 'flag': 'FLAG{api_key_leakage_exploited}'}), 200
    
    return jsonify({'error': 'Invalid or non-admin API key'}), 401


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005, debug=True)
