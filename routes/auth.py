import logging
from functools import wraps
from datetime import datetime, timedelta

import jwt
from flask import request, jsonify, g, redirect

from config import config
from db.supabase import sb_get_one, sb_patch
from services.activity_log import log_user_activity

logger = logging.getLogger('flinpay.auth')


# ── CSRF ─────────────────────────────────────────
def csrf_protect(f):
    """Décorateur CSRF manuel qui lit le token depuis X-CSRF-Token (header)
    ou _csrf_token (form). Utilisé en complément de csrf_guard global."""
    @wraps(f)
    def decorated(*args, **kwargs):
        from flask_wtf.csrf import validate_csrf
        from flask_wtf.csrf import CSRFError

        token = (
            request.headers.get('X-CSRF-Token')
            or request.headers.get('X-CSRFToken')
            or (request.form.get('_csrf_token') if request.form else None)
            or (request.get_json(silent=True) or {}).get('_csrf_token')
        )
        if not token:
            logger.warning(f"[csrf_protect] jeton CSRF manquant ou invalide sur {request.path}")
            return jsonify({'ok': False, 'error': 'Jeton de sécurité invalide ou expiré'}), 403

        try:
            validate_csrf(token)
        except CSRFError:
            logger.warning(f"[csrf_protect] jeton CSRF invalide sur {request.path}")
            return jsonify({'ok': False, 'error': 'Jeton de sécurité invalide ou expiré'}), 403
        return f(*args, **kwargs)
    return decorated


# ── User helpers ─────────────────────────────────
def get_current_user():
    token = request.cookies.get('fp_user_token')
    if not token:
        return None
    try:
        payload = jwt.decode(token, config.JWT_SECRET, algorithms=['HS256'])
        user_id = payload.get('sub')
        if not user_id:
            return None
        user = sb_get_one('users', 'id', user_id)
        return user
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_current_user_optional():
    return get_current_user()


def user_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.path.startswith('/api/'):
                return jsonify({'ok': False, 'error': 'Non autorisé'}), 401
            return redirect('/login')
        if not user.get('is_active', True):
            return jsonify({'ok': False, 'error': 'Compte désactivé'}), 403
        g.current_user = user
        request.user_id = user['id']
        return f(*args, **kwargs)
    return decorated


# ── Login lockout ────────────────────────────────
def is_locked_out(user):
    locked_until = user.get('locked_until')
    if not locked_until:
        return False
    try:
        dt = datetime.fromisoformat(locked_until.replace('Z', '+00:00')).replace(tzinfo=None)
        return dt > datetime.utcnow()
    except (ValueError, TypeError):
        return False


def register_failed_login(user):
    attempts = (user.get('login_attempts') or 0) + 1
    update = {'login_attempts': attempts}
    if attempts >= config.LOGIN_MAX_ATTEMPTS:
        update['locked_until'] = (datetime.utcnow() + timedelta(minutes=config.LOGIN_LOCKOUT_MINUTES)).isoformat()
    sb_patch('users', 'id', user['id'], update)


def reset_failed_login(user_id):
    sb_patch('users', 'id', user_id, {'login_attempts': 0, 'locked_until': None})


# ── Tokens ───────────────────────────────────────
def _create_token(user_id, token_type, expires_in_hours=24):
    payload = {
        'sub': user_id,
        'type': token_type,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=expires_in_hours),
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm='HS256')


def generate_pending_2fa_token(user_id):
    return _create_token(user_id, 'pending_2fa', expires_in_hours=1)


def generate_session_token(user_id):
    return _create_token(user_id, 'session', expires_in_hours=24)


def verify_token(token):
    try:
        return jwt.decode(token, config.JWT_SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ── Login response ───────────────────────────────
def _login_success_response(user):
    from flask import make_response
    token = generate_session_token(user['id'])
    resp = make_response(jsonify({
        'ok': True,
        'user': {
            'firstname': user['firstname'],
            'lastname': user['lastname'],
            'email': user['email'],
            'plan': user.get('plan', 'starter'),
        }
    }))
    resp.set_cookie(
        'fp_user_token', token,
        max_age=24 * 3600,
        secure=config.IS_PRODUCTION,
        httponly=True,
        samesite='Strict',
    )
    return resp