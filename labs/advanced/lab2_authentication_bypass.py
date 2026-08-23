"""Lab 2: Authentication Bypass Vulnerabilities
Challenge: Identify and exploit various authentication bypass vulnerabilities.
Vulnerabilities covered:
- JWT 'none' algorithm and weak secret manipulation
- Flawed token verification decorator
- Missing authorization / Role checks
- Authentication bypass via custom headers (X-User-Role)
- Default / hardcoded credentials
- Token expiration handling flaws
"""

from flask import Flask, request, jsonify
from functools import wraps
import jwt
from datetime import datetime, timezone, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super_secret_key_12345'

# Vulnerable user database
users_db = {
    'admin': {'password': 'admin123', 'role': 'admin'},
    'user': {'password': 'user123', 'role': 'user'},
}

# Token blacklist for logout (simulated)
token_blacklist = set()


def vulnerable_token_auth(f):
    """Vulnerable authentication decorator supporting intentional 'none' alg vulnerability."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'message': 'Authorization header required'}), 401
        
        # Vulnerability 1: Naive string replacement without checking scheme format
        token = auth_header.replace('Bearer ', '').strip()
        
        try:
            # Vulnerability 2: Simulating weak validation / 'none' algorithm support
            unverified_headers = jwt.get_unverified_header(token)
            
            if unverified_headers.get('alg', '').lower() == 'none':
                # Vulnerability: Accepts unsigned tokens if alg=none
                payload = jwt.decode(token, options={"verify_signature": False})
            else:
                payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            
            request.user = payload
        except jwt.InvalidTokenError as e:
            # Vulnerability 3: Verbose error messages leaking internals
            return jsonify({'message': f'Invalid token: {str(e)}'}), 401
        except Exception as e:
            return jsonify({'message': f'Token processing error: {str(e)}'}), 401
        
        return f(*args, **kwargs)
    return decorated


@app.route('/api/login', methods=['POST'])
def vulnerable_login():
    """Vulnerable login with weak validation & plaintext credentials."""
    data = request.get_json(silent=True) or {}
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400

    # Vulnerability 4: Username enumeration via distinct error responses
    if username not in users_db:
        return jsonify({'message': 'User does not exist'}), 401
    
    user = users_db[username]
    
    # Vulnerability 5: Plaintext password comparison
    if user['password'] != password:
        return jsonify({'message': 'Incorrect password'}), 401
    
    # Vulnerability 6: Predictable token payload
    now = datetime.now(timezone.utc)
    payload = {
        'user_id': username,
        'username': username,
        'role': user['role'],
        'iat': int(now.timestamp()),
        'exp': int((now + timedelta(hours=24)).timestamp())
    }
    
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return jsonify({'token': token, 'user': username}), 200


@app.route('/api/admin', methods=['GET'])
@vulnerable_token_auth
def vulnerable_admin():
    """Vulnerability 7: Endpoint verifies token existence but forgets role check."""
    return jsonify({
        'message': 'Admin panel accessed',
        'data': 'Sensitive administrative dataset: [CONFIDENTIAL_KEYS]'
    }), 200


@app.route('/api/data', methods=['GET'])
def vulnerable_data():
    """Vulnerability 8: Trusting unauthenticated client headers for privilege escalation."""
    user_role = request.headers.get('X-User-Role', 'guest')
    
    if user_role == 'admin':
        return jsonify({'message': 'Sensitive data', 'data': 'Internal company secrets'}), 200
    
    return jsonify({'message': 'Access denied: Requires admin role header'}), 403


@app.route('/api/backup', methods=['GET'])
def vulnerable_backup():
    """Vulnerability 9: Hardcoded backdoor / default credentials."""
    auth_header = request.headers.get('Authorization', '')
    
    if auth_header == 'Bearer default:backup:12345':
        return jsonify({'backup_data': 'User DB Backup: admin:admin123, user:user123'}), 200
    
    return jsonify({'message': 'Unauthorized'}), 401


@app.route('/api/logout', methods=['POST'])
def logout():
    """Vulnerability 10: Logout does not invalidate token on server."""
    # Blacklist logic intentionally left unexecuted
    return jsonify({'message': 'Successfully logged out'}), 200


@app.route('/api/refresh', methods=['POST'])
def vulnerable_refresh():
    """Vulnerability 11: Refreshes tokens without validating expiration or signatures."""
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '').strip()
    
    try:
        payload = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
        new_token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': new_token}), 200
    except Exception as e:
        return jsonify({'message': f'Refresh failed: {str(e)}'}), 400


@app.route('/api/challenge', methods=['GET'])
@vulnerable_token_auth
def challenge():
    """Challenge completion endpoint."""
    if request.user.get('role') != 'admin':
        return jsonify({'message': 'Admin access required'}), 403
    
    return jsonify({'flag': 'FLAG{auth_bypass_master_jwt_none_header}'}), 200


if __name__ == '__main__':
    # Binds to 0.0.0.0 for Docker & local interoperability
    app.run(host='0.0.0.0', port=5002, debug=True)
