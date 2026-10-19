import logging
import uuid as uuid_lib
import hashlib
import secrets
from datetime import datetime, timedelta

import bcrypt
import pyotp
from flask import Blueprint, request, jsonify, redirect, url_for, make_response, render_template

from config import config
from extensions import limiter, get_client_ip
from db.supabase import sb_get_eq, sb_get_one, sb_post, sb_patch
from services.auth import (
    generate_pending_2fa_token, verify_token, _login_success_response,
    is_locked_out, register_failed_login, reset_failed_login,
    user_required, get_current_user, csrf_protect,
)
from services.restrictions import is_login_blocked, login_block_message
from services.activity_log import log_user_activity
from services.billing import get_user_by_id, get_balances, get_monthly_transaction_count
from services.email import send_verification_email, send_login_magic_link_email

logger = logging.getLogger('flinpay.routes.auth')
auth_bp = Blueprint('auth', __name__)
DUMMY_HASH = bcrypt.hashpw(b'dummy_password_for_timing', bcrypt.gensalt()).decode()


# ── Connexion classique ─────────────────────────────
@auth_bp.route('/api/login', methods=['POST'])
@limiter.limit('5 per minute')
def api_login():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'ok': False, 'error': 'Email et mot de passe requis'}), 400

    email = data['email'].strip().lower()
    password = data['password']

    user = sb_get_one('users', 'email', email)
    if not user:
        bcrypt.checkpw(password.encode('utf-8'), DUMMY_HASH.encode('utf-8'))
        return jsonify({'ok': False, 'error': 'Identifiants incorrects'}), 401

    if is_locked_out(user):
        return jsonify({'ok': False, 'error': f'Trop de tentatives. Réessayez dans {config.LOGIN_LOCKOUT_MINUTES} minutes.'}), 429

    if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        register_failed_login(user)
        log_user_activity(user['id'], 'login_failed', {'reason': 'wrong_password'})
        return jsonify({'ok': False, 'error': 'Identifiants incorrects'}), 401

    if not user.get('is_active', True):
        return jsonify({'ok': False, 'error': 'Identifiants incorrects'}), 401

    if is_login_blocked(user):
        log_user_activity(user['id'], 'login_blocked', {'level': user.get('restriction_level')})
        return jsonify({'ok': False, 'error': login_block_message(user)}), 403

    if not user.get('email_verified', False):
        return jsonify({
            'ok': False, 'error': "Vérifiez votre adresse email avant de vous connecter.",
            'email_unverified': True
        }), 403

    reset_failed_login(user['id'])

    if user.get('totp_enabled'):
        pending_token = generate_pending_2fa_token(user['id'])
        return jsonify({'ok': True, 'requires_2fa': True, 'pending_token': pending_token})

    log_user_activity(user['id'], 'login_success', {})
    return _login_success_response(user)


# ── Vérification 2FA ────────────────────────────────
@auth_bp.route('/api/login/2fa', methods=['POST'])
@limiter.limit('5 per minute')
def api_login_2fa():
    data = request.get_json() or {}
    pending_token = (data.get('pending_token') or '').strip()
    code = (data.get('code') or '').strip()
    if not pending_token or not code:
        return jsonify({'ok': False, 'error': 'Code requis'}), 400

    payload = verify_token(pending_token)
    if not payload or payload.get('type') != 'pending_2fa':
        return jsonify({'ok': False, 'error': 'Session expirée, reconnectez-vous'}), 401

    user = get_user_by_id(payload.get('sub'))
    if not user or not user.get('totp_enabled') or not user.get('totp_secret'):
        return jsonify({'ok': False, 'error': "2FA non configurée"}), 400

    if is_locked_out(user):
        return jsonify({'ok': False, 'error': 'Trop de tentatives.'}), 429

    totp = pyotp.TOTP((user.get('totp_secret') or '').strip())
    if not totp.verify(code.replace(' ', ''), valid_window=2):
        register_failed_login(user)
        log_user_activity(user['id'], 'login_failed', {'reason': 'wrong_totp'})
        return jsonify({'ok': False, 'error': 'Code invalide'}), 401

    reset_failed_login(user['id'])
    log_user_activity(user['id'], 'login_success', {'via': '2fa'})
    return _login_success_response(user)


# ── Connexion par lien email (Magic Link) ───────────
@auth_bp.route('/api/login/email-link', methods=['POST'])
@limiter.limit('3 per 15 minutes')
def api_login_email_link():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password')

    user = sb_get_one('users', 'email', email)
    if not user:
        bcrypt.checkpw(b'dummy', DUMMY_HASH.encode())
        return jsonify({'ok': True, 'message': 'Si un compte correspond, un lien a été envoyé.'})

    if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        return jsonify({'ok': True, 'message': 'Si un compte correspond, un lien a été envoyé.'})

    if not user.get('email_link_enabled', False):
        return jsonify({'ok': False, 'error': "Cette fonctionnalité n'est pas activée sur votre compte."}), 403

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = (datetime.utcnow() + timedelta(minutes=15)).isoformat()

    code = f"{secrets.randbelow(900000) + 100000}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    sb_patch('users', 'id', user['id'], {
        'login_link_token_hash': token_hash,
        'login_link_code_hash': code_hash,
        'login_link_expires_at': expires_at
    })

    magic_url = f"https://www.flinpay.cfd/login?link_token={raw_token}"
    send_login_magic_link_email(email, user['firstname'], magic_url, code)

    log_user_activity(user['id'], 'login_magic_link_sent', {})
    return jsonify({'ok': True, 'message': 'Lien envoyé par email.'})


@auth_bp.route('/api/login/verify-link', methods=['POST'])
@limiter.limit('5 per minute')
def api_login_verify_link():
    data = request.get_json() or {}
    raw_token = data.get('token')
    code = data.get('code')

    if not raw_token or not code:
        return jsonify({'ok': False, 'error': 'Données manquantes'}), 400

    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    user = sb_get_one('users', 'login_link_token_hash', token_hash)

    if not user:
        return jsonify({'ok': False, 'error': 'Lien invalide ou déjà utilisé'}), 401

    expires_at = user.get('login_link_expires_at')
    if not expires_at or datetime.fromisoformat(expires_at.replace('Z', '+00:00')).replace(tzinfo=None) < datetime.utcnow():
        return jsonify({'ok': False, 'error': 'Lien expiré'}), 401

    code_hash = hashlib.sha256(code.encode()).hexdigest()
    if code_hash != user.get('login_link_code_hash'):
        return jsonify({'ok': False, 'error': 'Code invalide'}), 401

    sb_patch('users', 'id', user['id'], {
        'login_link_token_hash': None,
        'login_link_code_hash': None,
        'login_link_expires_at': None
    })

    log_user_activity(user['id'], 'login_success', {'via': 'magic_link'})
    return _login_success_response(user)


@auth_bp.route('/api/settings/toggle-email-link', methods=['POST'])
@user_required
@csrf_protect
def api_toggle_email_link():
    data = request.get_json() or {}
    enabled = bool(data.get('enabled'))
    sb_patch('users', 'id', request.user_id, {'email_link_enabled': enabled})
    log_user_activity(request.user_id, 'settings_updated', {'email_link_enabled': enabled})
    return jsonify({'ok': True, 'enabled': enabled})


# ── Logout et compte ────────────────────────────────
@auth_bp.route('/api/logout')
def api_logout():
    resp = make_response(redirect(url_for('public.login_page')))
    resp.delete_cookie('__Host-fp_session')
    resp.delete_cookie('fp_csrf_token')
    return resp


@auth_bp.route('/api/me')
@user_required
def api_me():
    user = get_current_user()
    if not user:
        return jsonify({'ok': False}), 404
    balances = get_balances(user)
    total_balance = sum(balances.values()) if balances else user.get('available_balance', 0)
    return jsonify({'ok': True, 'user': {
        'firstname': user['firstname'], 'lastname': user['lastname'],
        'email': user['email'], 'company': user.get('company', ''),
        'phone': user.get('phone', ''), 'country': user.get('country', ''),
        'plan': user.get('plan', 'starter'), 'plan_expires_at': user.get('plan_expires_at'),
        'kyc_status': user.get('kyc_status', 'unverified'), 'kyc_rejection_reason': user.get('kyc_rejection_reason'),
        'usage_this_month': get_monthly_transaction_count(request.user_id),
        'monthly_limit': config.FREE_PLAN_MONTHLY_LIMIT,
        'available_balance': total_balance, 'balances': balances,
        'totp_enabled': user.get('totp_enabled', False),
        'email_link_enabled': user.get('email_link_enabled', False)
    }})


# ── Inscription et vérification ─────────────────────
@auth_bp.route('/api/register', methods=['POST'])
@limiter.limit('3 per hour')
def api_register():
    data = request.get_json()
    if not data:
        return jsonify({'ok': False, 'error': 'Données manquantes'}), 400

    for field in ['firstname', 'lastname', 'email', 'country', 'phone', 'password']:
        if not data.get(field):
            return jsonify({'ok': False, 'error': f'Champ manquant: {field}'}), 400
    email = data['email'].strip().lower()
    if len(data['password']) < 8:
        return jsonify({'ok': False, 'error': 'Mot de passe trop court'}), 400
    if data['country'] not in {c['code'] for c in config.COUNTRIES}:
        return jsonify({'ok': False, 'error': 'Pays non pris en charge'}), 400
    if sb_get_eq('users', 'email', email):
        return jsonify({'ok': False, 'error': 'Email déjà utilisé'}), 409

    referred_by = None
    ref_code = (data.get('referral_code') or '').strip().upper()
    if ref_code:
        referrers = sb_get_eq('users', 'referral_code', ref_code)
        if referrers:
            referred_by = referrers[0]['id']

    hashed = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    verify_token_raw = uuid_lib.uuid4().hex
    verify_token_hash = hashlib.sha256(verify_token_raw.encode()).hexdigest()

    user = sb_post('users', {
        'firstname': data['firstname'].strip()[:80],
        'lastname': data['lastname'].strip()[:80],
        'email': email, 'company': data.get('company', '').strip()[:120],
        'country': data['country'], 'phone': data['phone'].strip()[:30],
        'password_hash': hashed, 'plan': 'starter',
        'is_active': True, 'email_verified': False,
        'email_verify_token_hash': verify_token_hash,
        'email_verify_token_expires_at': (datetime.utcnow() + timedelta(hours=24)).isoformat(),
        'referred_by': referred_by, 'created_at': datetime.utcnow().isoformat()
    })
    if not user or (isinstance(user, dict) and user.get('_error')):
        return jsonify({'ok': False, 'error': 'Erreur lors de la création du compte'}), 500

    ip = get_client_ip()
    sb_post('registration_ips', {'ip_address': ip, 'created_at': datetime.utcnow().isoformat()})

    send_verification_email(email, data['firstname'].strip(), verify_token_raw)
    return jsonify({'ok': True, 'message': "Compte créé ! Vérifiez votre email."})


@auth_bp.route('/verify-email/<token>')
@limiter.limit('10 per minute')
def verify_email(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    user = sb_get_one('users', 'email_verify_token_hash', token_hash)

    if not user:
        return render_template('verify_result.html', success=False, message="Lien invalide ou déjà utilisé.")

    expires_at = user.get('email_verify_token_expires_at')
    if not expires_at or datetime.fromisoformat(expires_at.replace('Z', '+00:00')).replace(tzinfo=None) < datetime.utcnow():
        return render_template('verify_result.html', success=False, message="Ce lien a expiré.")

    sb_patch('users', 'id', user['id'], {
        'email_verified': True,
        'email_verify_token_hash': None,
        'email_verify_token_expires_at': None
    })
    return render_template('verify_result.html', success=True, message="Votre adresse email est confirmée.")


@auth_bp.route('/api/resend-verification', methods=['POST'])
@limiter.limit('3 per hour')
def api_resend_verification():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    user = sb_get_one('users', 'email', email)
    if not user or user.get('email_verified'):
        return jsonify({'ok': True})

    token_raw = uuid_lib.uuid4().hex
    token_hash = hashlib.sha256(token_raw.encode()).hexdigest()

    sb_patch('users', 'id', user['id'], {
        'email_verify_token_hash': token_hash,
        'email_verify_token_expires_at': (datetime.utcnow() + timedelta(hours=24)).isoformat()
    })
    send_verification_email(email, user.get('firstname', ''), token_raw)
    return jsonify({'ok': True})


# ── 2FA ─────────────────────────────────────────────
@auth_bp.route('/api/2fa/setup', methods=['POST'])
@user_required
@csrf_protect
def api_2fa_setup():
    user = get_current_user()
    if user.get('totp_enabled'):
        return jsonify({'ok': False, 'error': 'Le 2FA est déjà activé'}), 400

    secret = pyotp.random_base32()
    ok = sb_patch('users', 'id', request.user_id, {'totp_secret': secret, 'totp_enabled': False})
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la génération du secret'}), 500

    otpauth_url = pyotp.totp.TOTP(secret).provisioning_uri(name=user.get('email', ''), issuer_name='Flinpay')
    return jsonify({'ok': True, 'secret': secret, 'otpauth_url': otpauth_url})


@auth_bp.route('/api/2fa/verify', methods=['POST'])
@user_required
@csrf_protect
def api_2fa_verify():
    data = request.get_json() or {}
    code = (data.get('code') or '').strip()
    if not code:
        return jsonify({'ok': False, 'error': 'Code requis'}), 400

    user = get_current_user()
    secret = user.get('totp_secret')
    if not secret:
        return jsonify({'ok': False, 'error': "Relancez l'activation."}), 400

    totp = pyotp.TOTP((secret or '').strip())
    if not totp.verify((code or '').replace(' ', ''), valid_window=2):
        return jsonify({'ok': False, 'error': 'Code invalide'}), 401

    ok = sb_patch('users', 'id', request.user_id, {'totp_enabled': True})
    if not ok:
        return jsonify({'ok': False, 'error': "Erreur lors de l'activation"}), 500
    return jsonify({'ok': True, 'message': '2FA activée'})


@auth_bp.route('/api/2fa/disable', methods=['POST'])
@user_required
@csrf_protect
@limiter.limit('5 per hour')
def api_2fa_disable():
    data = request.get_json() or {}
    password = data.get('password') or ''
    code = (data.get('code') or '').strip()
    if not password or not code:
        return jsonify({'ok': False, 'error': 'Mot de passe et code requis'}), 400

    user = get_current_user()
    if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        return jsonify({'ok': False, 'error': 'Mot de passe incorrect'}), 401

    secret = user.get('totp_secret')
    if not secret or not user.get('totp_enabled'):
        return jsonify({'ok': False, 'error': "Le 2FA n'est pas activé"}), 400

    totp = pyotp.TOTP((secret or '').strip())
    if not totp.verify((code or '').replace(' ', ''), valid_window=2):
        register_failed_login(user)
        return jsonify({'ok': False, 'error': 'Code invalide'}), 401

    ok = sb_patch('users', 'id', request.user_id, {'totp_enabled': False, 'totp_secret': None})
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la désactivation'}), 500
    return jsonify({'ok': True, 'message': '2FA désactivée'})