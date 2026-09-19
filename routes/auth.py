"""
routes/auth.py — tout ce qui touche à l'identité : connexion (+ 2FA),
inscription, vérification d'email, déconnexion, `/api/me`.

Le rate-limiting posé ici (via @limiter.limit) est une deuxième ligne de
défense en plus du verrouillage de compte (services/auth.is_locked_out) : le
verrouillage protège UN compte contre le bruteforce, le rate-limiting protège
le SERVEUR contre quelqu'un qui tenterait de se connecter sur des centaines
de comptes différents depuis la même IP (ce que le verrouillage par compte ne
voit pas).
"""
import logging
import uuid as uuid_lib
from datetime import datetime, timedelta

import bcrypt
import pyotp
from flask import Blueprint, request, jsonify, redirect, url_for, make_response

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
from services.email import send_verification_email

logger = logging.getLogger('flinpay.routes.auth')

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/api/login', methods=['POST'])
@limiter.limit('10 per minute')
def api_login():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'ok': False, 'error': 'Email et mot de passe requis'}), 400

    email = data['email'].strip().lower()
    password = data['password']

    user = sb_get_one('users', 'email', email)
    if not user:
        # Message générique volontaire : ne jamais révéler si c'est l'email ou
        # le mot de passe qui est incorrect (ça faciliterait l'énumération
        # de comptes existants).
        return jsonify({'ok': False, 'error': 'Identifiants incorrects'}), 401

    if is_locked_out(user):
        return jsonify({'ok': False, 'error': f'Trop de tentatives échouées. Réessayez dans {config.LOGIN_LOCKOUT_MINUTES} minutes.'}), 429

    if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        register_failed_login(user)
        log_user_activity(user['id'], 'login_failed', {'reason': 'wrong_password'})
        return jsonify({'ok': False, 'error': 'Identifiants incorrects'}), 401

    if not user.get('is_active', True):
        return jsonify({'ok': False, 'error': 'Compte désactivé'}), 403

    if is_login_blocked(user):
        log_user_activity(user['id'], 'login_blocked', {'level': user.get('restriction_level')})
        return jsonify({'ok': False, 'error': login_block_message(user)}), 403

    if not user.get('email_verified', False):
        return jsonify({
            'ok': False,
            'error': "Vérifiez votre adresse email avant de vous connecter (lien envoyé à l'inscription).",
            'email_unverified': True
        }), 403

    reset_failed_login(user['id'])

    if user.get('totp_enabled'):
        pending_token = generate_pending_2fa_token(user['id'])
        return jsonify({'ok': True, 'requires_2fa': True, 'pending_token': pending_token})

    log_user_activity(user['id'], 'login_success', {})
    return _login_success_response(user)


@auth_bp.route('/api/login/2fa', methods=['POST'])
@limiter.limit('10 per minute')
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
        return jsonify({'ok': False, 'error': "2FA non configurée pour ce compte"}), 400

    if not user.get('is_active', True):
        return jsonify({'ok': False, 'error': 'Compte désactivé'}), 403

    if is_login_blocked(user):
        log_user_activity(user['id'], 'login_blocked', {'level': user.get('restriction_level'), 'stage': '2fa'})
        return jsonify({'ok': False, 'error': login_block_message(user)}), 403

    if is_locked_out(user):
        return jsonify({'ok': False, 'error': f'Trop de tentatives échouées. Réessayez dans {config.LOGIN_LOCKOUT_MINUTES} minutes.'}), 429

    totp = pyotp.TOTP((user.get('totp_secret') or '').strip())
    if not totp.verify(code.replace(' ', ''), valid_window=2):
        register_failed_login(user)
        log_user_activity(user['id'], 'login_failed', {'reason': 'wrong_totp'})
        return jsonify({'ok': False, 'error': 'Code invalide'}), 401

    reset_failed_login(user['id'])
    log_user_activity(user['id'], 'login_success', {'via': '2fa'})
    return _login_success_response(user)


@auth_bp.route('/api/logout')
def api_logout():
    resp = make_response(redirect(url_for('public.login_page')))
    resp.delete_cookie('fp_user_token')
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
        'firstname': user['firstname'],
        'lastname': user['lastname'],
        'email': user['email'],
        'company': user.get('company', ''),
        'phone': user.get('phone', ''),
        'country': user.get('country', ''),
        'plan': user.get('plan', 'starter'),
        'plan_expires_at': user.get('plan_expires_at'),
        'kyc_status': user.get('kyc_status', 'unverified'),
        'kyc_rejection_reason': user.get('kyc_rejection_reason'),
        'usage_this_month': get_monthly_transaction_count(request.user_id),
        'monthly_limit': config.FREE_PLAN_MONTHLY_LIMIT,
        'available_balance': total_balance,
        'balances': balances,
        'totp_enabled': user.get('totp_enabled', False)
    }})


# ── Inscription ──────────────────────────────────────
@auth_bp.route('/api/register', methods=['POST'])
@limiter.limit('5 per hour')
def api_register():
    data = request.get_json()
    if not data:
        return jsonify({'ok': False, 'error': 'Données manquantes'}), 400

    ip = get_client_ip()
    one_hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat()
    recent = sb_get_eq('registration_ips', 'ip_address', ip, extra_query=f'created_at=gte.{one_hour_ago}')
    if len(recent) >= 3:
        return jsonify({'ok': False, 'error': 'Trop de comptes créés depuis cette adresse. Réessayez plus tard.'}), 429

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
    verify_token_value = uuid_lib.uuid4().hex
    user = sb_post('users', {
        'firstname': data['firstname'].strip()[:80],
        'lastname': data['lastname'].strip()[:80],
        'email': email,
        'company': data.get('company', '').strip()[:120],
        'country': data['country'],
        'phone': data['phone'].strip()[:30],
        'password_hash': hashed,
        'plan': 'starter',
        'is_active': True,
        'email_verified': False,
        'email_verify_token': verify_token_value,
        'referred_by': referred_by,
        'created_at': datetime.utcnow().isoformat()
    })
    if not user or (isinstance(user, dict) and user.get('_error')):
        detail = user.get('_detail') if isinstance(user, dict) else 'inconnue'
        logger.error(f"[api_register] échec création compte: {detail}")
        return jsonify({'ok': False, 'error': 'Erreur lors de la création du compte'}), 500

    sb_post('registration_ips', {'ip_address': ip, 'created_at': datetime.utcnow().isoformat()})
    send_verification_email(email, data['firstname'].strip(), verify_token_value)
    return jsonify({'ok': True, 'message': "Compte créé ! Vérifiez votre email pour l'activer."})


@auth_bp.route('/verify-email/<token>')
def verify_email(token):
    from flask import render_template
    user = sb_get_one('users', 'email_verify_token', token)
    if not user:
        return render_template('verify_result.html', success=False, message="Lien de vérification invalide ou déjà utilisé.")
    sb_patch('users', 'id', user['id'], {'email_verified': True, 'email_verify_token': None})
    return render_template('verify_result.html', success=True, message="Votre adresse email est confirmée. Vous pouvez vous connecter.")


@auth_bp.route('/api/resend-verification', methods=['POST'])
@limiter.limit('5 per hour')
def api_resend_verification():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    user = sb_get_one('users', 'email', email)
    if not user:
        # Réponse identique que l'email existe ou non : ne pas permettre
        # à un attaquant de vérifier quelles adresses ont un compte Flinpay.
        return jsonify({'ok': True})
    if user.get('email_verified'):
        return jsonify({'ok': True})
    token = user.get('email_verify_token') or uuid_lib.uuid4().hex
    sb_patch('users', 'id', user['id'], {'email_verify_token': token})
    send_verification_email(email, user.get('firstname', ''), token)
    return jsonify({'ok': True})


# ── 2FA (Google Authenticator / TOTP) ────────────────
@auth_bp.route('/api/2fa/setup', methods=['POST'])
@user_required
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
def api_2fa_verify():
    data = request.get_json() or {}
    code = (data.get('code') or '').strip()
    if not code:
        return jsonify({'ok': False, 'error': 'Code requis'}), 400

    user = get_current_user()
    secret = user.get('totp_secret')
    if not secret:
        return jsonify({'ok': False, 'error': "Aucune configuration 2FA en cours. Relancez l'activation."}), 400

    totp = pyotp.TOTP((secret or '').strip())
    if not totp.verify((code or '').replace(' ', ''), valid_window=2):
        return jsonify({'ok': False, 'error': 'Code invalide'}), 401

    ok = sb_patch('users', 'id', request.user_id, {'totp_enabled': True})
    if not ok:
        return jsonify({'ok': False, 'error': "Erreur lors de l'activation"}), 500
    return jsonify({'ok': True, 'message': 'Authentification à deux facteurs activée'})


@auth_bp.route('/api/2fa/disable', methods=['POST'])
@user_required
@csrf_protect  # désactiver le 2FA affaiblit la sécurité du compte : protection CSRF en plus
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
        return jsonify({'ok': False, 'error': 'Code invalide'}), 401

    ok = sb_patch('users', 'id', request.user_id, {'totp_enabled': False, 'totp_secret': None})
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la désactivation'}), 500
    return jsonify({'ok': True, 'message': 'Authentification à deux facteurs désactivée'})
