import logging
from functools import wraps
from datetime import datetime, timedelta

import jwt
from flask import request, jsonify, g, redirect, make_response

from config import config
from db.supabase import sb_get_one, sb_patch
from services.activity_log import log_user_activity

logger = logging.getLogger('flinpay.auth')


# ── CSRF (manuel, compatible X-CSRF-Token) ──────
def csrf_protect(f):
    """Décorateur CSRF qui lit le token depuis le header X-CSRF-Token
    ou depuis le form (_csrf_token). Compatible avec apiFetch() côté client."""
    @wraps(f)
    def decorated(*args, **kwargs):
        from flask_wtf.csrf import validate_csrf, CSRFError

        token = (
            request.headers.get('X-CSRF-Token')
            or request.headers.get('X-CSRFToken')
            or (request.form.get('_csrf_token') if request.form else None)
            or (request.get_json(silent=True) or {}).get('_csrf_token')
        )

        if not token:
            logger.warning(f"[csrf_protect] Jeton manquant sur {request.path}")
            return jsonify({'ok': False, 'error': 'Jeton de sécurité manquant'}), 403

        try:
            validate_csrf(token)
        except CSRFError as e:
            logger.warning(f"[csrf_protect] Jeton invalide sur {request.path}: {e}")
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
        return sb_get_one('users', 'id', user_id)
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
        update['locked_until'] = (
            datetime.utcnow() + timedelta(minutes=config.LOGIN_LOCKOUT_MINUTES)
        ).isoformat()
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


# ── API key generation ───────────────────────────
import secrets
import hashlib

def generate_api_key(environment='live'):
    """Génère une clé API. Retourne (full_key, key_hash, display_prefix)."""
    prefix = 'fp_live_' if environment == 'live' else 'fp_test_'
    random_part = secrets.token_urlsafe(32)
    full_key = f"{prefix}{random_part}"
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    display_prefix = f"{prefix}{random_part[:8]}...{random_part[-4:]}"
    return full_key, key_hash, display_prefix