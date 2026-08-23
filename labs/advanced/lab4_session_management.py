"""Lab 4: Session Management Vulnerabilities
Challenge: Identify and exploit session management flaws.
Vulnerabilities covered:
- Weak & predictable session ID generation (Timestamp & Sequential)
- Insecure session cookie attributes (Missing HttpOnly / Secure)
- Session fixation
- Insecure CSRF token validation and reuse
- Missing session expiration / timeout enforcement
- Insecure session data exposure and enumeration
- Client-side cookie role manipulation
"""

from flask import Flask, request, jsonify, make_response
from datetime import datetime, timezone, timedelta
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'weak_secret_key'

# In-memory storage
sessions_db = {}
csrf_tokens = {}


def get_current_timestamp():
    return datetime.now(timezone.utc).timestamp()


# ==================== WEAK SESSION GENERATION ====================

@app.route('/api/login/weak', methods=['POST'])
def weak_session_login():
    """Vulnerability 1: Predictable timestamp-based session ID & missing cookie flags."""
    data = request.get_json(silent=True) or {}
    username = data.get('username', 'guest_user')
    
    # Predictable millisecond timestamp
    session_id = str(int(time.time() * 1000))
    
    sessions_db[session_id] = {
        'username': username,
        'role': 'user',
        'login_time': get_current_timestamp(),
        'expires': get_current_timestamp() + 86400  # 24 hours
    }
    
    response = make_response(jsonify({'message': 'Logged in successfully', 'session_id': session_id}), 200)
    # Missing HttpOnly and Secure flags
    response.set_cookie('session_id', session_id, httponly=False, secure=False, samesite='Lax')
    return response


@app.route('/api/login/sequential', methods=['POST'])
def sequential_session_login():
    """Vulnerability 2: Sequential, enumerable session IDs."""
    data = request.get_json(silent=True) or {}
    username = data.get('username', 'guest_user')
    
    session_id = str(len(sessions_db) + 1).zfill(10)
    
    sessions_db[session_id] = {
        'username': username,
        'role': 'user',
        'login_time': get_current_timestamp(),
        'expires': get_current_timestamp() + 86400
    }
    
    response = make_response(jsonify({'message': 'Logged in with sequential ID', 'session_id': session_id}), 200)
    response.set_cookie('session_id', session_id, httponly=False, secure=False)
    return response


# ==================== SESSION FIXATION ====================

@app.route('/api/session/set', methods=['GET', 'POST'])
def vulnerable_session_fixation():
    """Vulnerability 3: Pre-session adoption without re-issuing ID upon authentication."""
    session_id = request.args.get('session_id') or (request.get_json(silent=True) or {}).get('session_id')
    
    if not session_id:
        return jsonify({'error': 'No session_id parameter provided'}), 400
    
    # Accepts arbitrary attacker-supplied session ID
    sessions_db[session_id] = {
        'username': 'victim_user',
        'role': 'authenticated_user',
        'login_time': get_current_timestamp(),
        'expires': get_current_timestamp() + 86400
    }
    
    response = make_response(jsonify({'message': 'Session adopted', 'session_id': session_id}), 200)
    response.set_cookie('session_id', session_id)
    return response


# ==================== CSRF VULNERABILITIES ====================

@app.route('/api/csrf/token', methods=['GET'])
def vulnerable_csrf_token():
    """Vulnerability 4: Predictable CSRF token linked to static session."""
    session_id = request.cookies.get('session_id') or request.args.get('session_id')
    csrf_token = str(int(time.time()))
    
    if session_id:
        csrf_tokens[session_id] = csrf_token
    
    return jsonify({'csrf_token': csrf_token}), 200


@app.route('/api/transfer', methods=['POST'])
def vulnerable_csrf_transfer():
    """Vulnerability 5: Flawed CSRF validation (reusable tokens & header fallback)."""
    session_id = request.cookies.get('session_id')
    data = request.get_json(silent=True) or {}
    
    csrf_token = (
        request.form.get('csrf_token') 
        or request.headers.get('X-CSRF-Token') 
        or data.get('csrf_token')
    )
    
    # Bypass 1: If no CSRF token sent at all, request still succeeds
    if not csrf_token:
        return jsonify({'status': 'success', 'message': 'Transfer processed (CSRF check omitted)'}), 200
    
    # Bypass 2: Stored token is validated without one-time invalidation (replayable)
    if session_id in csrf_tokens and csrf_tokens[session_id] == csrf_token:
        return jsonify({'status': 'success', 'message': 'Transfer completed with token'}), 200
    
    return jsonify({'error': 'Invalid CSRF token'}), 403


# ==================== SESSION TIMEOUT & STORAGE ====================

@app.route('/api/user/profile', methods=['GET'])
def vulnerable_session_timeout():
    """Vulnerability 6: Missing server-side expiration checks."""
    session_id = request.cookies.get('session_id') or request.headers.get('X-Session-ID')
    
    if session_id in sessions_db:
        session = sessions_db[session_id]
        # Notice: Expiration check intentionally omitted
        return jsonify({'profile': f"Profile of {session['username']}", 'session_meta': session}), 200
    
    return jsonify({'error': 'Unauthorized: Valid session required'}), 401


@app.route('/api/session/list', methods=['GET'])
def session_enumeration():
    """Vulnerability 7: Unauthenticated session table enumeration."""
    return jsonify({
        'active_session_count': len(sessions_db),
        'sessions': {sid: sess['username'] for sid, sess in sessions_db.items()}
    }), 200


# ==================== COOKIE PRIVILEGE ESCALATION ====================

@app.route('/api/user/role', methods=['GET'])
def cookie_role_manipulation():
    """Vulnerability 8: Role read directly from unverified client cookie."""
    role = request.cookies.get('user_role', 'guest')
    
    if role == 'admin':
        return jsonify({'message': 'Admin privilege granted via cookie', 'flag': 'FLAG{cookie_role_tampering_success}'}), 200
    
    return jsonify({'message': f'Active as {role}. Set user_role=admin to escalate.'}), 200


# ==================== CHALLENGE ENDPOINTS ====================

@app.route('/api/challenge/session', methods=['POST', 'GET'])
def session_challenge():
    """Challenge completion endpoint."""
    session_id = request.cookies.get('session_id') or (request.get_json(silent=True) or {}).get('session_id')
    user_role = request.cookies.get('user_role')
    
    if (session_id and session_id in sessions_db) or user_role == 'admin':
        return jsonify({
            'status': 'solved',
            'flag': 'FLAG{session_management_mastery_complete}'
        }), 200
    
    return jsonify({'error': 'Unauthorized: Valid session or admin cookie required'}), 401


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=True)
