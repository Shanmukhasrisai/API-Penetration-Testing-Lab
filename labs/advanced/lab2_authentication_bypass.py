"""Lab 2: Authentication Bypass Vulnerabilities
Challenge: Identify and exploit various authentication bypass vulnerabilities
Vulnerabilities covered:
- JWT token manipulation
- Weak token generation
- Authentication bypass through header injection
- Default credentials
- Token forgery
"""

from flask import Flask, request, jsonify
from functools import wraps
import jwt
import secrets
import hashlib
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super_secret_key_12345'

# Vulnerable user database
users_db = {
    'admin': {'password': 'admin123', 'role': 'admin'},
    'user': {'password': 'user123', 'role': 'user'},
}

# Token blacklist for logout
token_blacklist = set()

# Vulnerable authentication decorator
def vulnerable_token_auth(f):
    """Vulnerable authentication that can be bypassed"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token required'}), 401
        
        # Vulnerability 1: No proper Bearer scheme validation
        token = token.replace('Bearer ', '')
        
        try:
            # Vulnerability 2: Using the same secret key AND algorithm allows brute force
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256', 'none'])
            request.user = payload
        except jwt.InvalidTokenError as e:
            # Vulnerability 3: Error message leaks information
            return jsonify({'message': f'Invalid token: {str(e)}'}), 401
        
        return f(*args, **kwargs)
    return decorated

# Vulnerable login endpoint
@app.route('/api/login', methods=['POST'])
def vulnerable_login():
    """Vulnerable login with weak token generation"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Vulnerability 4: Username enumeration
    if username not in users_db:
        return jsonify({'message': 'Invalid credentials'}), 401
    
    user = users_db[username]
    
    # Vulnerability 5: Plaintext password comparison (not hashed)
    if user['password'] != password:
        return jsonify({'message': 'Invalid credentials'}), 401
    
    # Vulnerability 6: Weak token generation with predictable claims
    # The token generation uses timestamp which can be predicted
    payload = {
        'user_id': username,
        'username': username,
        'role': user['role'],
        'iat': datetime.utcnow().timestamp(),  # Predictable timestamp
        'exp': (datetime.utcnow() + timedelta(hours=24)).timestamp()
    }
    
    # Vulnerability 7: Algorithm can be set to 'none' and token will be accepted
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    
    return jsonify({'token': token, 'user': username}), 200

# Vulnerable admin endpoint
@app.route('/api/admin', methods=['GET'])
@vulnerable_token_auth
def vulnerable_admin():
    """Vulnerable admin endpoint that only checks token existence"""
    # Vulnerability 8: No role verification, only checks token exists
    return jsonify({'message': 'Admin panel', 'data': 'Sensitive admin data'}), 200

# Vulnerable data endpoint with header injection
@app.route('/api/data', methods=['GET'])
def vulnerable_data():
    """Endpoint vulnerable to header injection bypass"""
    # Vulnerability 9: Accepts X-User-Role header for authentication
    user_role = request.headers.get('X-User-Role', 'guest')
    user_id = request.headers.get('X-User-ID', '')
    
    if user_role == 'admin':
        return jsonify({'message': 'Sensitive data', 'data': 'Internal secrets'}), 200
    
    return jsonify({'message': 'Access denied'}), 403

# Vulnerable endpoint with default credentials
@app.route('/api/backup', methods=['GET'])
def vulnerable_backup():
    """Endpoint vulnerable to default credentials"""
    auth_header = request.headers.get('Authorization', '')
    
    # Vulnerability 10: Default credentials check
    if auth_header == 'Bearer default:backup:12345':
        return jsonify({'backup_data': 'All user passwords: admin123, user123, guest456'}), 200
    
    return jsonify({'message': 'Unauthorized'}), 401

# Vulnerable logout endpoint
@app.route('/api/logout', methods=['POST'])
def logout():
    """Weak logout that doesn't actually invalidate tokens"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    # Vulnerability 11: Token can still be used after logout
    # token_blacklist.add(token)  # This is commented out - not implemented!
    
    return jsonify({'message': 'Logged out'}), 200

# Vulnerable token refresh endpoint
@app.route('/api/refresh', methods=['POST'])
def vulnerable_refresh():
    """Endpoint with weak token refresh logic"""
    old_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    try:
        # Vulnerability 12: No verification of the old token
        payload = jwt.decode(old_token, app.config['SECRET_KEY'], algorithms=['HS256'], options={'verify_exp': False})
        
        # Vulnerability 13: New token uses same claims without updating
        new_token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': new_token}), 200
    except:
        return jsonify({'message': 'Invalid token'}), 401

# Challenge endpoint
@app.route('/api/challenge', methods=['GET'])
@vulnerable_token_auth
def challenge():
    """Challenge endpoint - access this as admin to complete the lab"""
    if request.user.get('role') != 'admin':
        return jsonify({'message': 'Admin access required'}), 403
    
    return jsonify({'flag': 'FLAG{auth_bypass_master}'}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5002)
