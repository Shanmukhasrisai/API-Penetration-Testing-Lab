"""Lab 4: Session Management Vulnerabilities
Challenge: Identify and exploit session management flaws
Vulnerabilities covered:
- Weak session ID generation
- Session fixation attacks
- CSRF (Cross-Site Request Forgery)
- Insecure session storage
- Session timeout issues
- Cookie manipulation
"""

from flask import Flask, request, jsonify, make_response
from datetime import datetime, timedelta
import hashlib
import secrets
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'weak_secret_key'

# Vulnerable session storage
sessions_db = {}
user_sessions = {}
csrf_tokens = {}  # Vulnerable CSRF token storage

# ==================== WEAK SESSION GENERATION ====================

@app.route('/api/login/weak', methods=['POST'])
def weak_session_login():
    """Vulnerability 1: Weak session ID generation"""
    data = request.get_json()
    username = data.get('username', '')
    
    # VULNERABLE: Predictable session ID using timestamp
    session_id = str(int(time.time() * 1000))
    
    sessions_db[session_id] = {
        'username': username,
        'login_time': datetime.utcnow().timestamp(),
        'expires': (datetime.utcnow() + timedelta(hours=24)).timestamp()
    }
    
    response = make_response(jsonify({'message': 'Logged in'}), 200)
    
    # VULNERABLE: Session ID in cookie without secure/httponly flags
    response.set_cookie('session_id', session_id, httponly=False, secure=False)
    
    return response

@app.route('/api/login/sequential', methods=['POST'])
def sequential_session_login():
    """Vulnerability 2: Sequential session IDs"""
    data = request.get_json()
    username = data.get('username', '')
    
    # VULNERABLE: Sequential session IDs
    session_id = str(len(sessions_db) + 1).zfill(10)
    
    sessions_db[session_id] = {
        'username': username,
        'login_time': datetime.utcnow().timestamp()
    }
    
    response = make_response(jsonify({'message': 'Logged in'}), 200)
    response.set_cookie('session_id', session_id)
    
    return response

# ==================== SESSION FIXATION ====================

@app.route('/api/session/set', methods=['GET'])
def vulnerable_session_fixation():
    """Vulnerability 3: Session Fixation"""
    session_id = request.args.get('session_id', '')
    
    # VULNERABLE: Accept arbitrary session ID without validation
    if session_id:
        sessions_db[session_id] = {
            'username': 'attacker_controlled',
            'login_time': datetime.utcnow().timestamp()
        }
        
        response = make_response(jsonify({'message': 'Session set'}), 200)
        response.set_cookie('session_id', session_id)
        return response
    
    return jsonify({'error': 'No session_id provided'}), 400

# ==================== CSRF VULNERABILITIES ====================

@app.route('/api/csrf/token', methods=['GET'])
def vulnerable_csrf_token():
    """Vulnerability 4: Weak CSRF token generation and storage"""
    # VULNERABLE: CSRF token too short and predictable
    csrf_token = str(int(time.time()))
    
    # VULNERABLE: Storing CSRF token in session (can be reused across requests)
    session_id = request.cookies.get('session_id')
    if session_id:
        csrf_tokens[session_id] = csrf_token
    
    return jsonify({'csrf_token': csrf_token}), 200

@app.route('/api/transfer', methods=['POST'])
def vulnerable_csrf_transfer():
    """Vulnerability 5: No proper CSRF protection"""
    # VULNERABLE: Insufficient CSRF validation
    session_id = request.cookies.get('session_id')
    csrf_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    
    # VULNERABLE: CSRF token validation is weak
    if not csrf_token:
        return jsonify({'message': 'Transfer processed without CSRF check'}), 200
    
    # VULNERABLE: Token stored in session and not regenerated
    if session_id in csrf_tokens:
        if csrf_tokens[session_id] == csrf_token:
            return jsonify({'message': 'Transfer completed'}), 200
    
    return jsonify({'error': 'Invalid CSRF token'}), 403

@app.route('/api/csrf/validation', methods=['POST'])
def weak_csrf_validation():
    """Vulnerability 6: Insecure CSRF validation"""
    # VULNERABLE: CSRF validation bypassed via GET or no token check
    action = request.args.get('action')
    
    if action == 'delete_user':
        # VULNERABLE: No CSRF check on dangerous action
        return jsonify({'message': 'User deleted'}), 200
    
    return jsonify({'error': 'Invalid action'}), 400

# ==================== SESSION TIMEOUT ISSUES ====================

@app.route('/api/user/profile', methods=['GET'])
def vulnerable_session_timeout():
    """Vulnerability 7: No session timeout enforcement"""
    session_id = request.cookies.get('session_id')
    
    if session_id in sessions_db:
        session = sessions_db[session_id]
        
        # VULNERABLE: Expired sessions still accepted
        # Timeout check is commented out
        # if session['expires'] < datetime.utcnow().timestamp():
        #     return jsonify({'error': 'Session expired'}), 401
        
        return jsonify({'profile': f"User profile for {session['username']}"}), 200
    
    return jsonify({'error': 'No session'}), 401

@app.route('/api/session/extend', methods=['POST'])
def automatic_session_extension():
    """Vulnerability 8: Automatic session extension without re-authentication"""
    session_id = request.cookies.get('session_id')
    
    if session_id in sessions_db:
        # VULNERABLE: Session extended indefinitely without any user action
        session = sessions_db[session_id]
        session['expires'] = (datetime.utcnow() + timedelta(hours=24)).timestamp()
        
        return jsonify({'message': 'Session extended'}), 200
    
    return jsonify({'error': 'No session'}), 401

# ==================== INSECURE SESSION STORAGE ====================

@app.route('/api/session/info', methods=['GET'])
def insecure_session_info():
    """Vulnerability 9: Sensitive data stored in session"""
    session_id = request.cookies.get('session_id')
    
    if session_id in sessions_db:
        session = sessions_db[session_id]
        # VULNERABLE: Returning all sensitive session data
        return jsonify(session), 200
    
    return jsonify({'error': 'No session'}), 401

@app.route('/api/session/list', methods=['GET'])
def session_enumeration():
    """Vulnerability 10: Session enumeration"""
    # VULNERABLE: Exposing all active sessions
    all_sessions = {}
    for sid, session in sessions_db.items():
        all_sessions[sid] = session['username']
    
    return jsonify({'sessions': all_sessions}), 200

# ==================== COOKIE MANIPULATION ====================

@app.route('/api/user/role', methods=['GET'])
def cookie_role_manipulation():
    """Vulnerability 11: Role stored in cookie without verification"""
    # VULNERABLE: Role read directly from cookie
    role = request.cookies.get('user_role', 'guest')
    
    if role == 'admin':
        return jsonify({'message': 'Admin access granted'}), 200
    
    return jsonify({'message': f'Access as {role}'}), 200

@app.route('/api/cookie/echo', methods=['GET'])
def cookie_echo():
    """Vulnerability 12: Echoing cookie values back"""
    session_id = request.cookies.get('session_id', '')
    username = request.cookies.get('username', '')
    
    # VULNERABLE: Echoing cookie values without validation
    return jsonify({'session': session_id, 'user': username}), 200

# ==================== ADVANCED CHALLENGES ====================

@app.route('/api/admin/panel', methods=['GET'])
def admin_panel():
    """Challenge endpoint - requires proper session"""
    session_id = request.cookies.get('session_id')
    role = request.cookies.get('user_role')
    
    # Multiple vulnerabilities to exploit
    if session_id in sessions_db or role == 'admin':
        return jsonify({'flag': 'FLAG{session_master}', 'admin_data': 'Sensitive information'}), 200
    
    return jsonify({'error': 'Unauthorized'}), 403

@app.route('/api/challenge/session', methods=['POST'])
def session_challenge():
    """Challenge endpoint for session manipulation"""
    session_id = request.cookies.get('session_id')
    
    # Vulnerable: Accept any valid format session ID
    if session_id and len(session_id) > 5:
        return jsonify({'flag': 'FLAG{session_master}'}), 200
    
    return jsonify({'error': 'Invalid session'}), 401

if __name__ == '__main__':
    app.run(debug=True, port=5004)
