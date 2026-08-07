import os
import re
import jwt
import bcrypt
import hashlib
import hmac
import secrets
import pyotp
import requests
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
ALLOWED_ORIGINS = [
    'https://www.flinpay.cfd',
    'https://flinpay.cfd',
    'https://flinpay.vercel.app',
]
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    # Les pages de paiement et de facture doivent pouvoir être intégrées en iframe par le
    # widget "Payer avec Flinpay" (voir /widget.js) — on ne restreint donc pas leur
    # frame-ancestors. Tout le reste du site refuse d'être affiché dans une iframe externe.
    if request.path.startswith('/pay/') or request.path.startswith('/invoice/'):
        response.headers['Content-Security-Policy'] = "frame-ancestors *"
    else:
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "frame-ancestors 'self'"
    return response

@app.context_processor
def inject_globals():
    return {'current_year': datetime.utcnow().year}

@app.template_filter('split')
def split_filter(value, sep=','):
    return (value or '').split(sep)

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
JWT_SECRET = os.getenv('JWT_SECRET')

LEEKPAY_SECRET_KEY = os.getenv('LEEKPAY_SECRET_KEY')
LEEKPAY_PUBLIC_KEY = os.getenv('LEEKPAY_PUBLIC_KEY')
LEEKPAY_API_BASE = 'https://leekpay.fr/api/v1'

SOLEASPAY_API_KEY = os.getenv('SOLEASPAY_API_KEY')
SOLEASPAY_CALLBACK_SECRET = os.getenv('SOLEASPAY_CALLBACK_SECRET')
SOLEASPAY_BASE = 'https://soleaspay.com'
SOLEASPAY_MIN_AMOUNT = 100  # XAF/XOF — en dessous, SoleasPay refuse la transaction

EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_APP_PASSWORD = os.getenv('EMAIL_APP_PASSWORD')

# Services réellement actifs chez SoleasPay par pays (vérifié via /api/services-list).
# format : code_pays -> { clé_opérateur: (service_id, libellé) }
SOLEASPAY_SERVICES = {
    'CM': {'momo': (1, 'MTN Mobile Money'), 'om': (2, 'Orange Money')},
    'CI': {'om': (29, 'Orange Money'), 'momo': (30, 'MTN Money'), 'moov': (31, 'Moov Money'), 'wave': (32, 'Wave')},
    'BF': {'moov': (33, 'Moov Money'), 'om': (34, 'Orange Money')},
    'BJ': {'momo': (35, 'MTN Money'), 'moov': (36, 'Moov Money')},
    'TG': {'tmoney': (37, 'T-Money'), 'moov': (38, 'Moov Money')},
    'CD': {'vodacom': (52, 'Vodacom M-Pesa'), 'airtel': (53, 'Airtel Money'), 'om': (54, 'Orange Money')},
    'GA': {'airtel': (57, 'Airtel Money')},
}

def get_country_operators(country_code):
    return SOLEASPAY_SERVICES.get(country_code, {})

def get_service_id(country_code, operator_key):
    ops = SOLEASPAY_SERVICES.get(country_code, {})
    entry = ops.get(operator_key)
    return entry[0] if entry else None

SUPA_HEADERS = {
    'apikey': SUPABASE_KEY,
    'Authorization': f'Bearer {SUPABASE_KEY}',
    'Content-Type': 'application/json',
    'Prefer': 'return=representation'
}

# Uniquement les pays réellement couverts par SoleasPay (services actifs vérifiés).
COUNTRIES = [
    {'code':'CM','name':'Cameroun','flag':'🇨🇲','currency':'XAF'},
    {'code':'CI','name':"Côte d'Ivoire",'flag':'🇨🇮','currency':'XOF'},
    {'code':'BF','name':'Burkina Faso','flag':'🇧🇫','currency':'XOF'},
    {'code':'BJ','name':'Bénin','flag':'🇧🇯','currency':'XOF'},
    {'code':'TG','name':'Togo','flag':'🇹🇬','currency':'XOF'},
    {'code':'CD','name':'RDC','flag':'🇨🇩','currency':'CDF'},
    {'code':'GA','name':'Gabon','flag':'🇬🇦','currency':'XAF'},
]

def sb_get(table, query=''):
    try:
        r = requests.get(f'{SUPABASE_URL}/rest/v1/{table}?{query}', headers=SUPA_HEADERS, timeout=10)
        return r.json() if r.ok else []
    except:
        return []

def sb_post(table, data):
    try:
        r = requests.post(f'{SUPABASE_URL}/rest/v1/{table}', headers=SUPA_HEADERS, json=data, timeout=10)
        print(f'[sb_post] {table} status={r.status_code} body={r.text[:300]}')
        if r.ok:
            return r.json()
        return {'_error': True, '_status': r.status_code, '_detail': r.text[:300]}
    except Exception as e:
        print(f'[sb_post] error: {e}')
        return {'_error': True, '_status': 0, '_detail': str(e)}

def sb_patch(table, field, value, data):
    try:
        r = requests.patch(f'{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}', headers=SUPA_HEADERS, json=data, timeout=10)
        return r.ok
    except:
        return False

def sb_delete(table, field, value):
    try:
        r = requests.delete(f'{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}', headers=SUPA_HEADERS, timeout=10)
        return r.ok
    except:
        return False

def sb_patch_multi(table, filters, data):
    try:
        qs = '&'.join([f'{k}=eq.{v}' for k, v in filters.items()])
        r = requests.patch(f'{SUPABASE_URL}/rest/v1/{table}?{qs}', headers=SUPA_HEADERS, json=data, timeout=10)
        return r.ok
    except:
        return False

def sb_patch_if_pending(table, token_field, token_value, data):
    """Met à jour une ligne UNIQUEMENT si elle est encore status='pending', de façon
    atomique côté base de données. Retourne True seulement si CETTE requête a
    réellement effectué la transition — protège contre le double crédit quand le
    webhook SoleasPay et la vérification automatique du navigateur se chevauchent."""
    try:
        qs = f'{token_field}=eq.{token_value}&status=eq.pending'
        r = requests.patch(f'{SUPABASE_URL}/rest/v1/{table}?{qs}', headers=SUPA_HEADERS, json=data, timeout=10)
        if not r.ok:
            return False
        updated = r.json()
        return bool(updated)
    except Exception:
        return False

def sb_delete_multi(table, filters):
    try:
        qs = '&'.join([f'{k}=eq.{v}' for k, v in filters.items()])
        r = requests.delete(f'{SUPABASE_URL}/rest/v1/{table}?{qs}', headers=SUPA_HEADERS, timeout=10)
        return r.ok
    except:
        return False

def get_config():
    data = sb_get('site_config')
    return {item['key']: item['value'] for item in data}

def generate_token(username):
    payload = {'sub': username, 'iat': datetime.utcnow(), 'exp': datetime.utcnow() + timedelta(hours=8)}
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except:
        return None

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('fp_user_token')
        if not token:
            return redirect(url_for('login_page'))
        payload = verify_token(token)
        if not payload or payload.get('type') != 'user':
            return redirect(url_for('login_page'))
        users = sb_get('users', f"id=eq.{payload.get('sub')}")
        if not users or not users[0].get('is_admin'):
            return redirect(url_for('login_page'))
        request.user_id = payload.get('sub')
        request.user_email = payload.get('email')
        return f(*args, **kwargs)
    return decorated


# ── AUTH UTILISATEUR ──────────────────────────────
def generate_user_token(user_id, email):
    payload = {
        'sub': str(user_id),
        'email': email,
        'type': 'user',
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def generate_pending_2fa_token(user_id):
    payload = {
        'sub': str(user_id),
        'type': 'pending_2fa',
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(minutes=10)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def user_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('fp_user_token')
        if not token:
            return redirect(url_for('login_page'))
        payload = verify_token(token)
        if not payload or payload.get('type') != 'user':
            return redirect(url_for('login_page'))
        request.user_id = payload.get('sub')
        request.user_email = payload.get('email')
        touch_last_seen(request.user_id)
        return f(*args, **kwargs)
    return decorated

def touch_last_seen(user_id):
    """Met à jour la dernière activité de l'utilisateur, utilisé pour le statut 'en ligne' côté admin."""
    try:
        sb_patch('users', 'id', user_id, {'last_seen_at': datetime.utcnow().isoformat()})
    except Exception:
        pass

def _login_success_response(user):
    """Construit la réponse de connexion réussie (cookie + payload utilisateur)."""
    token = generate_user_token(user['id'], user['email'])
    resp = make_response(jsonify({'ok': True, 'user': {
        'firstname': user['firstname'],
        'lastname': user['lastname'],
        'email': user['email'],
        'company': user.get('company',''),
        'phone': user.get('phone',''),
        'country': user.get('country',''),
        'plan': user.get('plan','starter')
    }}))
    resp.set_cookie('fp_user_token', token, httponly=True, samesite='Lax', max_age=7*24*3600)
    return resp

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'ok': False, 'error': 'Email et mot de passe requis'}), 400

    email = data['email'].strip().lower()
    password = data['password']

    users = sb_get('users', f'email=eq.{email}')
    if not users:
        return jsonify({'ok': False, 'error': 'Identifiants incorrects'}), 401

    user = users[0]
    if is_locked_out(user):
        return jsonify({'ok': False, 'error': f'Trop de tentatives échouées. Réessayez dans {LOGIN_LOCKOUT_MINUTES} minutes.'}), 429

    if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        register_failed_login(user)
        return jsonify({'ok': False, 'error': 'Identifiants incorrects'}), 401

    if not user.get('is_active', True):
        return jsonify({'ok': False, 'error': 'Compte désactivé'}), 403

    reset_failed_login(user['id'])

    # Si le 2FA est activé, on ne connecte pas tout de suite : on renvoie un
    # token temporaire (10 min) que le front doit renvoyer avec le code TOTP
    # via /api/login/2fa pour obtenir la vraie session.
    if user.get('totp_enabled'):
        pending_token = generate_pending_2fa_token(user['id'])
        return jsonify({'ok': True, 'requires_2fa': True, 'pending_token': pending_token})

    return _login_success_response(user)

@app.route('/api/login/2fa', methods=['POST'])
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

    if is_locked_out(user):
        return jsonify({'ok': False, 'error': f'Trop de tentatives échouées. Réessayez dans {LOGIN_LOCKOUT_MINUTES} minutes.'}), 429

    totp = pyotp.TOTP((user.get('totp_secret') or '').strip())
    if not totp.verify(code.replace(' ', ''), valid_window=2):
        register_failed_login(user)
        return jsonify({'ok': False, 'error': 'Code invalide'}), 401

    reset_failed_login(user['id'])
    return _login_success_response(user)

@app.route('/api/logout')
def api_logout():
    resp = make_response(redirect(url_for('login_page')))
    resp.delete_cookie('fp_user_token')
    return resp

@app.route('/api/me')
@user_required
def api_me():
    users = sb_get('users', f"id=eq.{request.user_id}")
    if not users:
        return jsonify({'ok': False}), 404
    user = users[0]
    balances = get_balances(user)
    total_balance = sum(balances.values()) if balances else user.get('available_balance', 0)
    return jsonify({'ok': True, 'user': {
        'firstname': user['firstname'],
        'lastname': user['lastname'],
        'email': user['email'],
        'company': user.get('company',''),
        'phone': user.get('phone',''),
        'country': user.get('country',''),
        'plan': user.get('plan','starter'),
        'plan_expires_at': user.get('plan_expires_at'),
        'kyc_status': user.get('kyc_status', 'unverified'),
        'kyc_rejection_reason': user.get('kyc_rejection_reason'),
        'usage_this_month': get_monthly_transaction_count(request.user_id),
        'monthly_limit': FREE_PLAN_MONTHLY_LIMIT,
        'available_balance': total_balance,
        'balances': balances,
        'totp_enabled': user.get('totp_enabled', False)
    }})

@app.route('/convert')
@user_required
def convert_page():
    return render_template('convert.html', user=get_current_user())

@app.route('/api/fx-preview', methods=['GET'])
@user_required
def api_fx_preview():
    from_currency = (request.args.get('from') or '').strip().upper()
    to_currency = (request.args.get('to') or '').strip().upper()
    try:
        amount = float(request.args.get('amount', 0))
    except (TypeError, ValueError):
        amount = 0
    if not from_currency or not to_currency or from_currency == to_currency or amount <= 0:
        return jsonify({'ok': False, 'error': 'Paramètres invalides'}), 400

    fee = round(amount * CONVERSION_FEE_PERCENT / 100, 2)
    amount_after_fee = round(amount - fee, 2)
    converted = soleaspay_convert(amount_after_fee, from_currency, to_currency)
    try:
        converted = round(float(converted), 2)
    except (TypeError, ValueError):
        converted = 0
    return jsonify({'ok': True, 'fee': fee, 'amount_after_fee': amount_after_fee, 'converted_amount': converted})

@app.route('/api/convert-balance', methods=['POST'])
@user_required
def api_convert_balance():
    data = request.get_json() or {}
    from_currency = (data.get('from_currency') or '').strip().upper()
    to_currency = (data.get('to_currency') or '').strip().upper()
    try:
        amount = float(data.get('amount'))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'Montant invalide'}), 400

    if not from_currency or not to_currency or from_currency == to_currency:
        return jsonify({'ok': False, 'error': 'Sélectionnez deux devises différentes'}), 400
    if amount <= 0:
        return jsonify({'ok': False, 'error': 'Montant invalide'}), 400

    user = get_current_user()
    available = get_balance_for_currency(user, from_currency)
    if amount > available:
        return jsonify({'ok': False, 'error': f'Solde insuffisant en {from_currency} (disponible : {available:,.0f} {from_currency})'}), 400

    fee = round(amount * CONVERSION_FEE_PERCENT / 100, 2)
    amount_after_fee = round(amount - fee, 2)
    converted_amount = soleaspay_convert(amount_after_fee, from_currency, to_currency)
    try:
        converted_amount = round(float(converted_amount), 2)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'Erreur lors de la conversion. Réessayez.'}), 502

    debit_user_balance(request.user_id, from_currency, amount)
    credit_user_balance(request.user_id, to_currency, converted_amount)

    return jsonify({
        'ok': True,
        'from_currency': from_currency,
        'to_currency': to_currency,
        'amount': amount,
        'fee': fee,
        'converted_amount': converted_amount,
        'message': f'{amount:,.0f} {from_currency} converti en {converted_amount:,.0f} {to_currency}'
    })

@app.route('/api/billing/subscribe', methods=['POST'])
@user_required
def api_billing_subscribe():
    user = get_current_user()
    data = request.get_json() or {}
    phone = (data.get('phone') or user.get('phone') or '').strip()
    operator = data.get('operator', '')
    if not phone:
        return jsonify({'ok': False, 'error': 'Numéro de téléphone requis'}), 400

    service_id = get_service_id(user.get('country', ''), operator)
    if not service_id:
        return jsonify({'ok': False, 'error': "Opérateur non disponible pour votre pays"}), 400

    price = get_subscription_price()
    total = amount_with_markup(price)
    merchant_currency = next((c['currency'] for c in COUNTRIES if c['code'] == user.get('country')), 'XOF')
    xaf_total = soleaspay_convert(total, merchant_currency, 'XAF')

    import uuid
    checkout_ref = 'sub_' + uuid.uuid4().hex[:16]

    collect = soleaspay_collect(
        wallet=phone,
        amount=xaf_total,
        currency='XAF',
        order_id=checkout_ref,
        description='Abonnement Flinpay Pro (mensuel)',
        payer=f"{user.get('firstname','')} {user.get('lastname','')}".strip(),
        payer_email=user.get('email', ''),
        success_url='https://www.flinpay.cfd/billing?upgraded=1',
        failure_url='https://www.flinpay.cfd/billing',
        service_id=service_id
    )
    if not collect['ok']:
        return jsonify({'ok': False, 'error': f"Erreur SoleasPay: {collect['detail']}"}), 502

    sb_patch('users', 'id', request.user_id, {'pending_upgrade_checkout_id': checkout_ref})
    return jsonify({'ok': True, 'message': 'Une confirmation de paiement a été envoyée sur votre téléphone.'})

@app.route('/api/referral')
@user_required
def api_referral():
    user = get_current_user()
    code = ensure_referral_code(user)

    referred = sb_get('users', f'referred_by=eq.{request.user_id}&order=created_at.desc')
    referred_list = [{
        'firstname': u.get('firstname', ''),
        'lastname': u.get('lastname', ''),
        'plan': u.get('plan', 'starter'),
        'created_at': u.get('created_at')
    } for u in referred]

    earnings = sb_get('referral_earnings', f'referrer_id=eq.{request.user_id}&order=created_at.desc&limit=50')

    return jsonify({
        'ok': True,
        'referral_code': code,
        'referral_link': f'https://www.flinpay.cfd/register?ref={code}',
        'referred_count': len(referred_list),
        'referred_users': referred_list,
        'balance': user.get('referral_balance', 0),
        'earnings_history': earnings,
        'commission_rate': REFERRAL_COMMISSION_RATE
    })

@app.route('/api/payouts/mine', methods=['GET'])
@user_required
def api_my_payouts():
    payouts = sb_get('payouts', f'user_id=eq.{request.user_id}&order=created_at.desc')
    return jsonify({'ok': True, 'payouts': payouts})

@app.route('/api/payouts/mine', methods=['POST'])
@user_required
def api_request_payout():
    user = get_current_user()
    if user.get('kyc_status') != 'verified':
        return jsonify({'ok': False, 'error': 'Vérifiez votre identité avant de demander un retrait'}), 403

    data = request.get_json() or {}
    try:
        amount = float(data.get('amount'))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'Montant invalide'}), 400
    phone = (data.get('phone') or '').strip()
    if amount <= 0 or not phone:
        return jsonify({'ok': False, 'error': 'Montant et numéro de téléphone requis'}), 400
    if amount < PAYOUT_MIN_AMOUNT:
        return jsonify({'ok': False, 'error': f'Le montant minimum de retrait est de {PAYOUT_MIN_AMOUNT} (dans la devise choisie)'}), 400

    # Le pays choisi pour le retrait détermine la devise dans laquelle le mobile money
    # sera crédité. On ne retire que depuis la poche de solde correspondante, pour ne
    # jamais subir de conversion XAF/XOF imposée par SoleasPay au moment du retrait.
    withdraw_country = (data.get('country') or user.get('country') or '').strip()
    withdraw_currency = get_currency_for_country(withdraw_country)

    balances = get_balances(user)
    available_in_currency = get_balance_for_currency(user, withdraw_currency)

    if amount > available_in_currency:
        other_currencies = {c: v for c, v in balances.items() if c != withdraw_currency and v and v > 0}
        if other_currencies:
            other_desc = ', '.join(f'{v:,.0f} {c}' for c, v in other_currencies.items())
            return jsonify({
                'ok': False,
                'error': (f"Solde insuffisant en {withdraw_currency} "
                          f"(disponible : {available_in_currency:,.0f} {withdraw_currency}). "
                          f"Vous avez {other_desc} sur une autre devise — convertissez-le "
                          f"via l'E-Change de SoleasPay avant de retirer en {withdraw_currency}.")
            }), 400
        return jsonify({'ok': False, 'error': f'Solde insuffisant (disponible : {available_in_currency:,.0f} {withdraw_currency})'}), 400

    # Frais de retrait manuel : 3.5% du montant demandé, déduits du solde du marchand.
    # Le montant net (envoyé sur son mobile money) est amount - fee.
    fee = round(amount * PAYOUT_FEE_PERCENT / 100, 2)
    net_amount = round(amount - fee, 2)

    row = sb_post('payouts', {
        'user_id': request.user_id,
        'amount': amount,
        'fee': fee,
        'net_amount': net_amount,
        'currency': withdraw_currency,
        'phone': phone,
        'operator': (data.get('operator') or '').strip(),
        'country': withdraw_country,
        'status': 'pending',
        'note': (data.get('note') or '').strip(),
        'created_at': datetime.utcnow().isoformat()
    })
    if not row or (isinstance(row, dict) and row.get('_error')):
        detail = row.get('_detail') if isinstance(row, dict) else 'inconnue'
        return jsonify({'ok': False, 'error': f'Erreur Supabase: {detail}'}), 500

    debit_user_balance(request.user_id, withdraw_currency, amount)
    return jsonify({'ok': True, 'payout': row[0] if isinstance(row, list) else row})

@app.route('/api/payouts/mine/<int:pid>', methods=['DELETE'])
@user_required
def api_cancel_payout(pid):
    matches = sb_get('payouts', f'id=eq.{pid}&user_id=eq.{request.user_id}')
    if not matches:
        return jsonify({'ok': False, 'error': 'Introuvable'}), 404
    payout = matches[0]
    if payout['status'] != 'pending':
        return jsonify({'ok': False, 'error': 'Seuls les retraits en attente peuvent être annulés'}), 400

    ok = sb_delete_multi('payouts', {'id': pid, 'user_id': request.user_id})
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de l\'annulation'}), 500

    refund_currency = payout.get('currency') or get_currency_for_country(payout.get('country', ''))
    credit_user_balance(request.user_id, refund_currency, payout['amount'])
    return jsonify({'ok': True})


@app.route('/api/profile', methods=['PUT'])
@user_required
def api_update_profile():
    data = request.get_json()
    if not data:
        return jsonify({'ok': False, 'error': 'Données manquantes'}), 400
    allowed = {}
    for field in ['firstname', 'lastname', 'company', 'phone']:
        if field in data and isinstance(data[field], str):
            allowed[field] = data[field].strip()
    if not allowed:
        return jsonify({'ok': False, 'error': 'Aucun champ à mettre à jour'}), 400
    ok = sb_patch('users', 'id', request.user_id, allowed)
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la mise à jour du profil'}), 500
    return jsonify({'ok': True, 'message': 'Profil mis à jour'})

@app.route('/api/password', methods=['PUT'])
@user_required
def api_change_password():
    data = request.get_json()
    if not data or not data.get('old_password') or not data.get('new_password'):
        return jsonify({'ok': False, 'error': 'Champs manquants'}), 400
    if len(data['new_password']) < 8:
        return jsonify({'ok': False, 'error': 'Le nouveau mot de passe doit contenir au moins 8 caractères'}), 400
    users = sb_get('users', f"id=eq.{request.user_id}")
    if not users:
        return jsonify({'ok': False, 'error': 'Utilisateur introuvable'}), 404
    user = users[0]
    if not bcrypt.checkpw(data['old_password'].encode('utf-8'), user['password_hash'].encode('utf-8')):
        return jsonify({'ok': False, 'error': 'Mot de passe actuel incorrect'}), 401
    new_hash = bcrypt.hashpw(data['new_password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    ok = sb_patch('users', 'id', request.user_id, {'password_hash': new_hash})
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la mise à jour du mot de passe'}), 500
    return jsonify({'ok': True, 'message': 'Mot de passe mis à jour'})

@app.route('/api/account', methods=['DELETE'])
@user_required
def api_delete_account():
    ok = sb_delete('users', 'id', request.user_id)
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la suppression du compte'}), 500
    resp = make_response(jsonify({'ok': True}))
    resp.delete_cookie('fp_user_token')
    return resp

# ── 2FA (Google Authenticator / TOTP) ─────────────
@app.route('/api/2fa/setup', methods=['POST'])
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

@app.route('/api/2fa/verify', methods=['POST'])
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

@app.route('/api/2fa/disable', methods=['POST'])
@user_required
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

# ── API TRANSACTIONS ──────────────────────────────
@app.route('/api/transactions', methods=['GET'])
@user_required
def api_get_transactions():
    txs = sb_get('transactions', f"user_id=eq.{request.user_id}&order=created_at.desc&limit=100")
    return jsonify({'ok': True, 'transactions': txs})

@app.route('/api/transactions/<token>/sync', methods=['POST'])
@user_required
def api_sync_transaction(token):
    matches = sb_get('transactions', f'token=eq.{token}&user_id=eq.{request.user_id}')
    if not matches:
        return jsonify({'ok': False, 'error': 'Introuvable'}), 404
    tx = matches[0]
    if not tx.get('gateway_reference'):
        return jsonify({'ok': False, 'error': "Pas de paiement associé à cette transaction"}), 400

    check = soleaspay_verify(tx['token'], tx['gateway_reference'])
    if not check['ok']:
        return jsonify({'ok': False, 'error': f"Erreur SoleasPay: {check['detail']}"}), 502

    remote_status = check.get('status')
    status_map = {'SUCCESS': 'paid', 'REFUND': 'failed'}
    new_status = status_map.get(remote_status, tx['status'])

    if new_status != tx['status']:
        update = {'status': new_status}
        if new_status == 'paid':
            update['paid_at'] = datetime.utcnow().isoformat()
        # Mise à jour atomique : seule la requête qui fait réellement basculer le statut
        # depuis 'pending' déclenche les effets ci-dessous (crédit, webhook, email...).
        # Empêche le double crédit si le webhook SoleasPay traite la même transaction
        # en même temps que cette vérification manuelle.
        won_race = sb_patch_if_pending('transactions', 'token', token, update)
        if won_race:
            if new_status == 'paid' and tx.get('payment_link_token'):
                links = sb_get('payment_links', f"token=eq.{tx['payment_link_token']}")
                if links:
                    sb_patch_multi('payment_links', {'token': tx['payment_link_token']}, {'paid_count': (links[0].get('paid_count') or 0) + 1})
            if new_status == 'paid':
                mark_invoice_paid_if_applicable(tx)
            if new_status == 'paid' and tx.get('user_id'):
                merchant = get_user_by_id(tx['user_id'])
                tx_currency = tx.get('currency') or 'XOF'
                credit_user_balance(tx['user_id'], tx_currency, tx.get('amount') or 0)
                send_payment_notification_email(merchant, tx)
            if new_status in ('paid', 'failed') and tx.get('user_id'):
                dispatch_merchant_webhooks(tx['user_id'], 'payment.success' if new_status == 'paid' else 'payment.failed', {
                    'token': tx.get('token'), 'order_id': tx.get('order_id'), 'amount': tx.get('amount'),
                    'status': new_status, 'client_name': tx.get('client_name'), 'client_phone': tx.get('client_phone')
                })

    return jsonify({'ok': True, 'status': new_status})

@app.route('/api/pay', methods=['POST'])
def api_pay():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'ok': False, 'error': 'Clé API requise'}), 401
    provided_key = auth.replace('Bearer ', '', 1).strip()
    key_hash = hashlib.sha256(provided_key.encode()).hexdigest()

    matches = sb_get('api_keys', f'key_hash=eq.{key_hash}&active=eq.true')
    if not matches:
        return jsonify({'ok': False, 'error': 'Clé API invalide ou révoquée'}), 401
    key_row = matches[0]
    user_id = key_row['user_id']
    environment = key_row.get('environment', 'live')
    sb_patch('api_keys', 'id', key_row['id'], {'last_used_at': datetime.utcnow().isoformat()})

    data = request.get_json()
    if not data:
        return jsonify({'ok': False, 'error': 'Données manquantes'}), 400

    required = ['amount', 'phone', 'client_name', 'order_id']
    for field in required:
        if not data.get(field):
            return jsonify({'ok': False, 'error': f'Champ manquant: {field}'}), 400

    if environment != 'sandbox':
        allowed, quota_error = check_quota(user_id)
        if not allowed:
            return jsonify({'ok': False, 'error': quota_error}), 403

    import uuid
    token = 'fp_tx_' + uuid.uuid4().hex[:20]
    env_label = 'sandbox' if environment == 'sandbox' else 'production'

    country_code = data.get('country', '')
    merchant_currency = next((c['currency'] for c in COUNTRIES if c['code'] == country_code), 'XOF')
    operator = data.get('operator', '')

    tx_payload = {
        'token': token,
        'order_id': data['order_id'],
        'amount': data['amount'],
        'client_name': data['client_name'],
        'client_phone': data['phone'],
        'country': country_code,
        'currency': merchant_currency,
        'status': 'pending',
        'environment': env_label,
        'user_id': user_id,
        'operator': operator,
        # Si le marchand transmet les infos de SON client (navigateur/IP côté client), on les
        # garde ; sinon on capture ce qu'on voit nous-mêmes (souvent le serveur du marchand).
        'user_agent': (data.get('customer_user_agent') or request.headers.get('User-Agent') or '')[:500],
        'ip_address': (data.get('customer_ip') or request.headers.get('x-forwarded-for', request.remote_addr or ''))[:100],
        'referer_url': (data.get('customer_referrer') or request.headers.get('Referer') or '')[:500],
        'created_at': datetime.utcnow().isoformat()
    }

    # En production, on déclenche une vraie collecte SoleasPay (confirmation directe sur le
    # téléphone du client). En sandbox, on garde une simulation locale sans argent réel.
    if env_label == 'production':
        service_id = get_service_id(country_code, operator)
        if not service_id:
            return jsonify({'ok': False, 'error': f"Opérateur '{operator}' non disponible pour le pays '{country_code}'"}), 400
        # On collecte directement dans la devise réelle du portefeuille du client (celle de
        # son pays), sans détour artificiel par le XAF — ce détour causait une double
        # conversion (la nôtre + celle, silencieuse, de SoleasPay au moment du débit réel du
        # portefeuille), donc une double perte à chaque transaction hors zone XAF.
        collect_amount = api_amount_with_markup(data['amount'], operator)
        if collect_amount < SOLEASPAY_MIN_AMOUNT:
            return jsonify({'ok': False, 'error': f"Montant trop faible (minimum {SOLEASPAY_MIN_AMOUNT} {merchant_currency})"}), 400
        collect = soleaspay_collect(
            wallet=data['phone'],
            amount=collect_amount,
            currency=merchant_currency,
            order_id=token,
            description=f"Commande {data['order_id']}",
            payer=data['client_name'],
            payer_email=data.get('email', ''),
            success_url=f'https://www.flinpay.cfd/pay-status/{token}',
            failure_url=f'https://www.flinpay.cfd/pay-status/{token}',
            service_id=service_id
        )
        if not collect['ok']:
            return jsonify({'ok': False, 'error': f"Erreur SoleasPay: {collect['detail']}"}), 502
        tx_payload['gateway_reference'] = collect['data'].get('reference')
        tx_payload['client_amount'] = collect_amount
        tx_payload['fee_amount'] = round(collect_amount - data['amount'], 2)

    tx = sb_post('transactions', tx_payload)

    if not tx or (isinstance(tx, dict) and tx.get('_error')):
        return jsonify({'ok': False, 'error': 'Erreur lors de la création de la transaction'}), 500

    return jsonify({
        'ok': True,
        'token': token,
        'order_id': data['order_id'],
        'amount': data['amount'],
        'status': 'pending',
        'message': 'Une notification a été envoyée sur le téléphone du client pour confirmer le paiement.'
    })

@app.route('/api/transactions/export', methods=['GET'])
@user_required
def api_export_transactions():
    txs = sb_get('transactions', f"user_id=eq.{request.user_id}&order=created_at.desc")
    import io, csv
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Client', 'Montant', 'Statut', 'Pays', 'Date'])
    for tx in txs:
        writer.writerow([tx.get('token',''), tx.get('client_name',''), tx.get('amount',''), tx.get('status',''), tx.get('country',''), tx.get('created_at','')])
    from flask import Response
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=transactions_flinpay.csv'})

# ── KYC (vérification d'identité) ─────────────────
@app.route('/kyc')
@user_required
def kyc_page():
    return render_template('kyc.html', user=get_current_user())

@app.route('/api/kyc/submit', methods=['POST'])
@user_required
def api_kyc_submit():
    full_name = (request.form.get('full_name') or '').strip()
    id_type = (request.form.get('id_type') or '').strip()
    id_number = (request.form.get('id_number') or '').strip()
    file_front = request.files.get('document_front')
    file_back = request.files.get('document_back')
    file_selfie = request.files.get('selfie')

    if not full_name or not id_type or not id_number \
            or not file_front or not file_front.filename \
            or not file_back or not file_back.filename \
            or not file_selfie or not file_selfie.filename:
        return jsonify({'ok': False, 'error': 'Tous les champs, le recto, le verso et la photo sont requis'}), 400

    def _upload(file, allowed_ext, max_bytes, subfolder):
        ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
        if ext not in allowed_ext:
            return None, f'Format non supporté pour {subfolder} ({", ".join(allowed_ext)} uniquement)'
        file_bytes = file.read()
        if len(file_bytes) > max_bytes:
            return None, f'Fichier {subfolder} trop volumineux ({max_bytes // (1024*1024)} Mo max)'
        path = f"{request.user_id}/{subfolder}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.{ext}"
        uploaded = sb_storage_upload('kyc-documents', path, file_bytes, file.mimetype or 'application/octet-stream')
        if not uploaded['ok']:
            return None, f"Erreur upload {subfolder}: {uploaded['detail']}"
        return path, None

    front_path, err = _upload(file_front, ('jpg', 'jpeg', 'png', 'pdf'), 8 * 1024 * 1024, 'recto')
    if err:
        return jsonify({'ok': False, 'error': err}), 400

    back_path, err = _upload(file_back, ('jpg', 'jpeg', 'png', 'pdf'), 8 * 1024 * 1024, 'verso')
    if err:
        return jsonify({'ok': False, 'error': err}), 400

    selfie_path, err = _upload(file_selfie, ('jpg', 'jpeg', 'png'), 8 * 1024 * 1024, 'selfie')
    if err:
        return jsonify({'ok': False, 'error': err}), 400

    updated = sb_patch('users', 'id', request.user_id, {
        'kyc_status': 'pending',
        'kyc_full_name': full_name,
        'kyc_id_type': id_type,
        'kyc_id_number': id_number,
        'kyc_document_front_path': front_path,
        'kyc_document_back_path': back_path,
        'kyc_selfie_path': selfie_path,
        'kyc_submitted_at': datetime.utcnow().isoformat(),
        'kyc_rejection_reason': None
    })
    if not updated:
        return jsonify({'ok': False, 'error': 'Erreur lors de la mise à jour du profil'}), 500
    return jsonify({'ok': True, 'message': 'Documents envoyés. Vérification sous 24-48h.'})

# ── ADMIN : REVUE KYC ─────────────────────────────
@app.route('/admin/kyc')
@admin_required
def admin_kyc_page():
    pending = sb_get('users', 'kyc_status=eq.pending&order=kyc_submitted_at.asc')
    return render_template('admin_kyc.html', pending=pending)

@app.route('/api/admin/kyc/<user_id>/document')
@admin_required
def api_admin_kyc_document(user_id):
    users = sb_get('users', f'id=eq.{user_id}')
    if not users:
        return jsonify({'ok': False, 'error': 'Utilisateur introuvable'}), 404
    u = users[0]
    urls = {}
    for key, path_field in [
        ('front', 'kyc_document_front_path'),
        ('back', 'kyc_document_back_path'),
        ('selfie', 'kyc_selfie_path'),
    ]:
        if u.get(path_field):
            signed = sb_storage_sign('kyc-documents', u[path_field])
            if signed:
                urls[key] = signed
    if not urls:
        return jsonify({'ok': False, 'error': 'Aucun document trouvé'}), 404
    return jsonify({'ok': True, 'urls': urls})

@app.route('/api/admin/kyc/<user_id>/approve', methods=['POST'])
@admin_required
def api_admin_kyc_approve(user_id):
    ok = sb_patch('users', 'id', user_id, {
        'kyc_status': 'verified',
        'kyc_reviewed_at': datetime.utcnow().isoformat(),
        'kyc_rejection_reason': None
    })
    if ok:
        log_admin_action('kyc_approve', {'target_user_id': user_id})
    return jsonify({'ok': ok})

@app.route('/api/admin/kyc/<user_id>/reject', methods=['POST'])
@admin_required
def api_admin_kyc_reject(user_id):
    data = request.get_json() or {}
    reason = (data.get('reason') or 'Document invalide ou illisible').strip()
    ok = sb_patch('users', 'id', user_id, {
        'kyc_status': 'rejected',
        'kyc_reviewed_at': datetime.utcnow().isoformat(),
        'kyc_rejection_reason': reason
    })
    if ok:
        log_admin_action('kyc_reject', {'target_user_id': user_id, 'reason': reason})
    return jsonify({'ok': ok})

# ── API KEYS (réelles, hashées) ───────────────────
@app.route('/api/keys', methods=['GET'])
@user_required
def api_list_keys():
    keys = sb_get('api_keys', f"user_id=eq.{request.user_id}&order=created_at.desc")
    safe = [{
        'id': k['id'],
        'key_prefix': k['key_prefix'],
        'environment': k.get('environment', 'live'),
        'label': k.get('label') or '',
        'active': k.get('active', True),
        'created_at': k.get('created_at'),
        'last_used_at': k.get('last_used_at')
    } for k in keys]
    return jsonify({'ok': True, 'keys': safe})

@app.route('/api/keys', methods=['POST'])
@user_required
def api_create_key():
    user = get_current_user()
    if user.get('kyc_status') != 'verified':
        return jsonify({'ok': False, 'error': "Vérifiez votre identité avant de générer une clé API"}), 403

    data = request.get_json() or {}
    environment = data.get('environment') if data.get('environment') in ('live', 'sandbox') else 'live'
    label = (data.get('label') or '').strip()[:60]

    full_key, key_hash, display_prefix = generate_api_key(environment)
    row = sb_post('api_keys', {
        'user_id': request.user_id,
        'key_prefix': display_prefix,
        'key_hash': key_hash,
        'environment': environment,
        'label': label,
        'active': True,
        'created_at': datetime.utcnow().isoformat()
    })
    if not row or (isinstance(row, dict) and row.get('_error')):
        detail = row.get('_detail') if isinstance(row, dict) else 'inconnue'
        return jsonify({'ok': False, 'error': f'Erreur Supabase: {detail}'}), 500
    return jsonify({'ok': True, 'key': full_key, 'key_prefix': display_prefix, 'environment': environment})

@app.route('/api/keys/<int:key_id>', methods=['DELETE'])
@user_required
def api_delete_key(key_id):
    ok = sb_delete_multi('api_keys', {'id': key_id, 'user_id': request.user_id})
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la révocation'}), 500
    return jsonify({'ok': True})

# ── API WEBHOOKS (marchand) ────────────────────────
@app.route('/api/webhooks', methods=['GET'])
@user_required
def api_get_webhooks():
    return jsonify({'ok': True, 'webhooks': sb_get('webhooks', f'user_id=eq.{request.user_id}&order=created_at.desc')})

@app.route('/api/webhooks', methods=['POST'])
@user_required
def api_create_webhook():
    data = request.get_json() or {}
    url = (data.get('url') or '').strip()
    if not url or not url.startswith('http'):
        return jsonify({'ok': False, 'error': 'URL valide requise'}), 400
    events = data.get('events') or []
    if not events:
        return jsonify({'ok': False, 'error': 'Sélectionnez au moins un événement'}), 400

    row = sb_post('webhooks', {
        'user_id': request.user_id,
        'url': url,
        'description': (data.get('description') or '').strip(),
        'events': events,
        'active': True,
        'created_at': datetime.utcnow().isoformat()
    })
    if not row or (isinstance(row, dict) and row.get('_error')):
        detail = row.get('_detail') if isinstance(row, dict) else 'inconnue'
        return jsonify({'ok': False, 'error': f'Erreur Supabase: {detail}'}), 500
    return jsonify({'ok': True, 'webhook': row[0] if isinstance(row, list) else row})

@app.route('/api/webhooks/<int:wid>', methods=['DELETE'])
@user_required
def api_delete_webhook(wid):
    ok = sb_delete_multi('webhooks', {'id': wid, 'user_id': request.user_id})
    return jsonify({'ok': ok})

@app.route('/api/webhooks/<int:wid>/test', methods=['POST'])
@user_required
def api_test_webhook(wid):
    matches = sb_get('webhooks', f'id=eq.{wid}&user_id=eq.{request.user_id}')
    if not matches:
        return jsonify({'ok': False, 'error': 'Introuvable'}), 404
    hook = matches[0]
    try:
        r = requests.post(hook['url'], json={
            'event': 'test',
            'data': {'message': 'Ceci est un test envoyé depuis Flinpay'}
        }, timeout=8)
        return jsonify({'ok': True, 'status_code': r.status_code})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 502

# ── FACTURATION ────────────────────────────────────
def generate_invoice_number(user_id):
    """Numérotation simple et séquentielle par marchand : INV-0001, INV-0002, ..."""
    existing = sb_get('invoices', f'user_id=eq.{user_id}&order=id.desc&limit=1')
    next_num = 1
    if existing:
        last_num = existing[0].get('invoice_number', '')
        try:
            next_num = int(last_num.split('-')[-1]) + 1
        except (ValueError, IndexError):
            next_num = len(sb_get('invoices', f'user_id=eq.{user_id}')) + 1
    return f'INV-{next_num:04d}'

def mark_invoice_paid_if_applicable(tx):
    """Si la transaction est liée à une facture et vient de passer à 'paid',
    marque la facture correspondante comme payée."""
    invoice_token = tx.get('invoice_token')
    if not invoice_token:
        return
    invoices = sb_get('invoices', f'token=eq.{invoice_token}')
    if invoices and invoices[0].get('status') != 'paid':
        sb_patch_multi('invoices', {'token': invoice_token}, {
            'status': 'paid',
            'paid_at': datetime.utcnow().isoformat()
        })

def _compute_invoice_amount(items):
    total = 0.0
    for it in items:
        try:
            total += float(it.get('quantity', 1)) * float(it.get('unit_price', 0))
        except (TypeError, ValueError):
            continue
    return round(total, 2)

@app.route('/api/invoices', methods=['GET'])
@user_required
def api_get_invoices():
    invoices = sb_get('invoices', f'user_id=eq.{request.user_id}&order=created_at.desc')
    return jsonify({'ok': True, 'invoices': invoices})

@app.route('/api/invoices', methods=['POST'])
@user_required
def api_create_invoice():
    data = request.get_json() or {}
    client_name = (data.get('client_name') or '').strip()
    if not client_name:
        return jsonify({'ok': False, 'error': 'Le nom du client est requis'}), 400

    items = data.get('items') or []
    if not isinstance(items, list) or not items:
        return jsonify({'ok': False, 'error': 'Ajoutez au moins un article'}), 400
    cleaned_items = []
    for it in items:
        desc = (it.get('description') or '').strip()
        try:
            qty = float(it.get('quantity', 1))
            price = float(it.get('unit_price', 0))
        except (TypeError, ValueError):
            return jsonify({'ok': False, 'error': 'Quantité ou prix invalide'}), 400
        if not desc or qty <= 0 or price < 0:
            return jsonify({'ok': False, 'error': 'Article invalide (description, quantité ou prix)'}), 400
        cleaned_items.append({'description': desc, 'quantity': qty, 'unit_price': price})

    amount = _compute_invoice_amount(cleaned_items)
    if amount < SOLEASPAY_MIN_AMOUNT:
        return jsonify({'ok': False, 'error': f'Montant total minimum : {SOLEASPAY_MIN_AMOUNT} XOF'}), 400

    import uuid
    token = 'inv_' + uuid.uuid4().hex[:12]

    row = sb_post('invoices', {
        'token': token,
        'user_id': request.user_id,
        'invoice_number': generate_invoice_number(request.user_id),
        'client_name': client_name,
        'client_email': (data.get('client_email') or '').strip() or None,
        'client_phone': (data.get('client_phone') or '').strip() or None,
        'items': cleaned_items,
        'currency': 'XOF',
        'amount': amount,
        'status': 'draft',
        'due_date': data.get('due_date') or None,
        'notes': (data.get('notes') or '').strip() or None,
        'created_at': datetime.utcnow().isoformat()
    })
    if not row or (isinstance(row, dict) and row.get('_error')):
        detail = row.get('_detail') if isinstance(row, dict) else 'inconnue'
        return jsonify({'ok': False, 'error': f'Erreur Supabase: {detail}'}), 500
    return jsonify({'ok': True, 'invoice': row[0] if isinstance(row, list) else row})

@app.route('/api/invoices/<token>', methods=['PUT'])
@user_required
def api_update_invoice(token):
    matches = sb_get('invoices', f'token=eq.{token}&user_id=eq.{request.user_id}')
    if not matches:
        return jsonify({'ok': False, 'error': 'Introuvable'}), 404
    invoice = matches[0]
    if invoice.get('status') == 'paid':
        return jsonify({'ok': False, 'error': 'Une facture payée ne peut plus être modifiée'}), 400

    data = request.get_json() or {}
    allowed = {}
    if 'status' in data and data['status'] in ('draft', 'sent', 'cancelled'):
        allowed['status'] = data['status']
        if data['status'] == 'sent' and not invoice.get('sent_at'):
            allowed['sent_at'] = datetime.utcnow().isoformat()
    if 'client_name' in data and (data.get('client_name') or '').strip():
        allowed['client_name'] = data['client_name'].strip()
    if 'client_email' in data:
        allowed['client_email'] = (data.get('client_email') or '').strip() or None
    if 'client_phone' in data:
        allowed['client_phone'] = (data.get('client_phone') or '').strip() or None
    if 'due_date' in data:
        allowed['due_date'] = data.get('due_date') or None
    if 'notes' in data:
        allowed['notes'] = (data.get('notes') or '').strip() or None
    if 'items' in data:
        items = data.get('items') or []
        cleaned_items = []
        for it in items:
            desc = (it.get('description') or '').strip()
            try:
                qty = float(it.get('quantity', 1))
                price = float(it.get('unit_price', 0))
            except (TypeError, ValueError):
                return jsonify({'ok': False, 'error': 'Quantité ou prix invalide'}), 400
            if not desc or qty <= 0 or price < 0:
                return jsonify({'ok': False, 'error': 'Article invalide'}), 400
            cleaned_items.append({'description': desc, 'quantity': qty, 'unit_price': price})
        if not cleaned_items:
            return jsonify({'ok': False, 'error': 'Ajoutez au moins un article'}), 400
        allowed['items'] = cleaned_items
        allowed['amount'] = _compute_invoice_amount(cleaned_items)

    if not allowed:
        return jsonify({'ok': False, 'error': 'Aucun champ à mettre à jour'}), 400

    ok = sb_patch_multi('invoices', {'token': token, 'user_id': request.user_id}, allowed)
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la mise à jour'}), 500
    return jsonify({'ok': True})

@app.route('/api/invoices/<token>', methods=['DELETE'])
@user_required
def api_delete_invoice(token):
    ok = sb_delete_multi('invoices', {'token': token, 'user_id': request.user_id})
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la suppression'}), 500
    return jsonify({'ok': True})

@app.route('/invoices')
@user_required
def invoices_page():
    return render_template('invoices.html', user=get_current_user())

# ── PAGE PUBLIQUE : FACTURE ────────────────────────
@app.route('/invoice/<token>')
def invoice_view(token):
    matches = sb_get('invoices', f'token=eq.{token}')
    invoice = matches[0] if matches else None
    merchant = get_user_by_id(invoice['user_id']) if invoice else {}
    return render_template('invoice_view.html', invoice=invoice, merchant=merchant, token=token,
                            countries_operators=SOLEASPAY_SERVICES, available_countries=COUNTRIES)

@app.route('/api/invoice-pay/<token>', methods=['POST'])
def api_invoice_pay(token):
    matches = sb_get('invoices', f'token=eq.{token}')
    invoice = matches[0] if matches else None
    if not invoice:
        return jsonify({'ok': False, 'error': 'Facture introuvable'}), 404
    if invoice.get('status') == 'paid':
        return jsonify({'ok': False, 'error': 'Cette facture est déjà payée'}), 400
    if invoice.get('status') == 'cancelled':
        return jsonify({'ok': False, 'error': 'Cette facture a été annulée'}), 400

    allowed, quota_error = check_quota(invoice['user_id'])
    if not allowed:
        return jsonify({'ok': False, 'error': quota_error}), 403

    data = request.get_json() or {}
    phone = (data.get('phone') or invoice.get('client_phone') or '').strip()
    operator = data.get('operator', '')
    customer_country = data.get('country', '')
    if not phone:
        return jsonify({'ok': False, 'error': 'Numéro de téléphone requis'}), 400

    amount = invoice['amount']
    merchant = get_user_by_id(invoice['user_id'])
    merchant_currency = next((c['currency'] for c in COUNTRIES if c['code'] == merchant.get('country')), 'XOF')

    service_id = get_service_id(customer_country, operator)
    if not service_id:
        return jsonify({'ok': False, 'error': "Opérateur indisponible pour ce pays"}), 400

    # Même correction que pour les liens de paiement : collecte directe dans la devise
    # réelle du client, sans détour XAF systématique.
    customer_currency = get_currency_for_country(customer_country) or merchant_currency
    markup_amount = amount_with_markup(amount)
    collect_amount = soleaspay_convert(markup_amount, merchant_currency, customer_currency)
    if collect_amount < SOLEASPAY_MIN_AMOUNT:
        return jsonify({'ok': False, 'error': f"Montant trop faible (minimum {SOLEASPAY_MIN_AMOUNT} {customer_currency})"}), 400

    import uuid
    tx_token = 'fp_tx_' + uuid.uuid4().hex[:20]
    customer_name = invoice.get('client_name') or 'Client'

    collect = soleaspay_collect(
        wallet=phone,
        amount=collect_amount,
        currency=customer_currency,
        order_id=tx_token,
        description=f"Facture {invoice['invoice_number']}",
        payer=customer_name,
        payer_email=invoice.get('client_email') or '',
        success_url=f'https://www.flinpay.cfd/invoice/{token}',
        failure_url=f'https://www.flinpay.cfd/invoice/{token}',
        service_id=service_id
    )
    if not collect['ok']:
        return jsonify({'ok': False, 'error': f"Erreur SoleasPay: {collect['detail']}"}), 502

    credited_amount = amount if customer_currency == merchant_currency else soleaspay_convert(amount, merchant_currency, customer_currency)

    tx = sb_post('transactions', {
        'token': tx_token,
        'order_id': invoice['invoice_number'],
        'amount': credited_amount,
        'client_amount': collect_amount,
        'fee_amount': round(collect_amount - credited_amount, 2),
        'client_name': customer_name,
        'client_phone': phone,
        'country': merchant.get('country', ''),
        'currency': customer_currency,
        'status': 'pending',
        'environment': 'production',
        'user_id': invoice['user_id'],
        'operator': operator,
        'gateway_reference': collect['data'].get('reference'),
        'invoice_token': token,
        **get_request_client_info(),
        'created_at': datetime.utcnow().isoformat()
    })
    if not tx or (isinstance(tx, dict) and tx.get('_error')):
        return jsonify({'ok': False, 'error': 'Erreur lors de la création du paiement'}), 500

    return jsonify({
        'ok': True,
        'tx_token': tx_token,
        'message': 'Une confirmation de paiement a été envoyée sur le téléphone du client.'
    })

@app.route('/api/payment-links', methods=['GET'])
@user_required
def api_get_payment_links():
    links = sb_get('payment_links', f"user_id=eq.{request.user_id}&order=created_at.desc")
    for l in links:
        if l.get('image_path'):
            l['image_url'] = sb_storage_public_url('payment-link-images', l['image_path'])
    return jsonify({'ok': True, 'links': links})

@app.route('/api/payment-links', methods=['POST'])
@user_required
def api_create_payment_link():
    data = request.form
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'ok': False, 'error': 'Le nom est requis'}), 400

    amount_type = data.get('amount_type') if data.get('amount_type') in ('fixed', 'flexible') else 'fixed'

    amount = None
    min_amount = None
    if amount_type == 'fixed':
        try:
            amount = float(data.get('amount'))
        except (TypeError, ValueError):
            return jsonify({'ok': False, 'error': 'Montant invalide'}), 400
        if amount < SOLEASPAY_MIN_AMOUNT:
            return jsonify({'ok': False, 'error': f'Montant minimum : {SOLEASPAY_MIN_AMOUNT} XOF'}), 400
    else:
        raw_min = data.get('min_amount')
        if raw_min:
            try:
                min_amount = float(raw_min)
            except (TypeError, ValueError):
                return jsonify({'ok': False, 'error': 'Montant minimum invalide'}), 400
            if min_amount < SOLEASPAY_MIN_AMOUNT:
                return jsonify({'ok': False, 'error': f'Montant minimum : {SOLEASPAY_MIN_AMOUNT} XOF'}), 400

    image_path = None
    file = request.files.get('image')
    if file and file.filename:
        ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
        if ext not in ('jpg', 'jpeg', 'png', 'webp'):
            return jsonify({'ok': False, 'error': 'Image: formats acceptés jpg, png, webp'}), 400
        file_bytes = file.read()
        if len(file_bytes) > 5 * 1024 * 1024:
            return jsonify({'ok': False, 'error': 'Image trop volumineuse (5 Mo max)'}), 400
        import uuid as _uuid
        image_path = f"{request.user_id}/{_uuid.uuid4().hex[:12]}.{ext}"
        uploaded = sb_storage_upload('payment-link-images', image_path, file_bytes, file.mimetype or 'image/jpeg')
        if not uploaded['ok']:
            return jsonify({'ok': False, 'error': f"Erreur upload image: {uploaded['detail']}"}), 500

    import uuid
    token = 'pay_' + uuid.uuid4().hex[:12]

    payload = {
        'token': token,
        'user_id': request.user_id,
        'name': name,
        'amount': amount,
        'amount_type': amount_type,
        'min_amount': min_amount,
        'description': (data.get('description') or '').strip(),
        'usage_limit': int(data['usage_limit']) if data.get('usage_limit') else None,
        'expires_at': data.get('expires_at') or None,
        'redirect_url': (data.get('redirect_url') or '').strip() or None,
        'thank_you_message': (data.get('thank_you_message') or '').strip() or None,
        'image_path': image_path,
        'active': True,
        'views': 0,
        'paid_count': 0,
        'created_at': datetime.utcnow().isoformat()
    }
    link = sb_post('payment_links', payload)
    if not link or (isinstance(link, dict) and link.get('_error')):
        detail = link.get('_detail') if isinstance(link, dict) else 'inconnue'
        return jsonify({'ok': False, 'error': f'Erreur Supabase: {detail}'}), 500
    return jsonify({'ok': True, 'link': link[0] if isinstance(link, list) else link})

@app.route('/api/payment-links/<token>', methods=['PUT'])
@user_required
def api_update_payment_link(token):
    data = request.get_json() or {}
    allowed = {}

    if 'active' in data:
        allowed['active'] = bool(data['active'])
    if 'name' in data and isinstance(data['name'], str) and data['name'].strip():
        allowed['name'] = data['name'].strip()
    if 'description' in data:
        allowed['description'] = (data.get('description') or '').strip()
    if 'redirect_url' in data:
        allowed['redirect_url'] = (data.get('redirect_url') or '').strip() or None
    if 'thank_you_message' in data:
        allowed['thank_you_message'] = (data.get('thank_you_message') or '').strip() or None
    if 'expires_at' in data:
        allowed['expires_at'] = data.get('expires_at') or None
    if 'usage_limit' in data:
        raw_limit = data.get('usage_limit')
        allowed['usage_limit'] = int(raw_limit) if raw_limit else None
    if 'amount_type' in data and data['amount_type'] in ('fixed', 'flexible'):
        allowed['amount_type'] = data['amount_type']
        if data['amount_type'] == 'fixed':
            if 'amount' in data:
                try:
                    amt = float(data.get('amount'))
                except (TypeError, ValueError):
                    return jsonify({'ok': False, 'error': 'Montant invalide'}), 400
                if amt < SOLEASPAY_MIN_AMOUNT:
                    return jsonify({'ok': False, 'error': f'Montant minimum : {SOLEASPAY_MIN_AMOUNT} XOF'}), 400
                allowed['amount'] = amt
            allowed['min_amount'] = None
        else:
            raw_min = data.get('min_amount')
            if raw_min:
                try:
                    min_amt = float(raw_min)
                except (TypeError, ValueError):
                    return jsonify({'ok': False, 'error': 'Montant minimum invalide'}), 400
                if min_amt < SOLEASPAY_MIN_AMOUNT:
                    return jsonify({'ok': False, 'error': f'Montant minimum : {SOLEASPAY_MIN_AMOUNT} XOF'}), 400
                allowed['min_amount'] = min_amt
            else:
                allowed['min_amount'] = None
            allowed['amount'] = None

    if not allowed:
        return jsonify({'ok': False, 'error': 'Aucun champ à mettre à jour'}), 400

    ok = sb_patch_multi('payment_links', {'token': token, 'user_id': request.user_id}, allowed)
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la mise à jour'}), 500
    return jsonify({'ok': True})

@app.route('/api/payment-links/<token>', methods=['DELETE'])
@user_required
def api_delete_payment_link(token):
    ok = sb_delete_multi('payment_links', {'token': token, 'user_id': request.user_id})
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la suppression'}), 500
    return jsonify({'ok': True})

# ── ROUTES PUBLIQUES ──────────────────────────────
@app.route('/')
def index():
    cfg = get_config()
    stats = sb_get('stats', 'order=order_index.asc')
    features = sb_get('features', 'is_visible=eq.true&order=order_index.asc')
    plans = sb_get('pricing_plans', 'is_visible=eq.true&order=order_index.asc')
    testimonials = sb_get('testimonials', 'is_visible=eq.true&order=order_index.asc')
    return render_template('index.html', cfg=cfg, stats=stats, features=features, plans=plans, testimonials=testimonials, countries=COUNTRIES)

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

def sb_storage_upload(bucket, path, file_bytes, content_type):
    try:
        url = f'{SUPABASE_URL}/storage/v1/object/{bucket}/{path}'
        headers = {
            'apikey': SUPABASE_KEY,
            'Authorization': f'Bearer {SUPABASE_KEY}',
            'Content-Type': content_type or 'application/octet-stream',
            'x-upsert': 'true'
        }
        r = requests.post(url, headers=headers, data=file_bytes, timeout=20)
        if r.ok:
            return {'ok': True}
        print(f'[sb_storage_upload] status={r.status_code} body={r.text[:300]}')
        return {'ok': False, 'detail': r.text[:300]}
    except Exception as e:
        print(f'[sb_storage_upload] error: {e}')
        return {'ok': False, 'detail': str(e)}

def sb_storage_sign(bucket, path, expires_in=3600):
    try:
        url = f'{SUPABASE_URL}/storage/v1/object/sign/{bucket}/{path}'
        r = requests.post(url, headers=SUPA_HEADERS, json={'expiresIn': expires_in}, timeout=10)
        if not r.ok:
            return None
        signed_path = r.json().get('signedURL')
        return f'{SUPABASE_URL}/storage/v1{signed_path}' if signed_path else None
    except Exception as e:
        print(f'[sb_storage_sign] error: {e}')
        return None

def sb_storage_public_url(bucket, path):
    return f'{SUPABASE_URL}/storage/v1/object/public/{bucket}/{path}'

def generate_api_key(environment):
    raw = secrets.token_hex(24)
    prefix = 'fp_live_' if environment == 'live' else 'fp_test_'
    full_key = prefix + raw
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    display_prefix = full_key[:14] + '…'
    return full_key, key_hash, display_prefix

def sb_count(table, query=''):
    try:
        headers = dict(SUPA_HEADERS)
        headers['Prefer'] = 'count=exact'
        sep = '&' if query else ''
        r = requests.get(f'{SUPABASE_URL}/rest/v1/{table}?{query}{sep}limit=1', headers=headers, timeout=10)
        cr = r.headers.get('Content-Range', '')
        return int(cr.split('/')[-1]) if '/' in cr else 0
    except:
        return 0

def soleaspay_convert(amount, from_currency, to_currency='XAF'):
    if from_currency == to_currency:
        return float(amount)
    try:
        r = requests.get(f'{SOLEASPAY_BASE}/api/convert',
                          params={'amount': amount, 'from': from_currency, 'to': to_currency}, timeout=10)
        data = r.json()
        if data.get('success'):
            return float(data['data']['value'])
    except Exception as e:
        print(f'[soleaspay_convert] error: {e}')
    return float(amount)  # repli : XOF/XAF sont à parité de toute façon

def soleaspay_collect(wallet, amount, currency, order_id, description, payer, payer_email,
                       success_url, failure_url, service_id):
    try:
        headers = {
            'x-api-key': SOLEASPAY_API_KEY,
            'operation': '2',
            'service': str(service_id),
            'Content-Type': 'application/json'
        }
        payload = {
            'wallet': wallet,
            'amount': amount,
            'currency': currency,
            'order_id': order_id,
            'description': description,
            'payer': payer,
            'payerEmail': payer_email or '',
            'successUrl': success_url,
            'failureUrl': failure_url
        }
        r = requests.post(f'{SOLEASPAY_BASE}/api/agent/bills/v3', headers=headers, json=payload, timeout=20)
        data = r.json()
        print(f'[soleaspay_collect] RAW RESPONSE status={r.status_code} body={r.text[:800]}')  # TEMPORAIRE — à retirer après debug
        if data.get('success'):
            return {'ok': True, 'data': data.get('data', {})}
        print(f'[soleaspay_collect] status={r.status_code} body={r.text[:300]}')
        return {'ok': False, 'detail': data.get('message', 'Erreur inconnue')}
    except Exception as e:
        print(f'[soleaspay_collect] error: {e}')
        return {'ok': False, 'detail': str(e)}

def soleaspay_verify(order_id, pay_id):
    try:
        headers = {'x-api-key': SOLEASPAY_API_KEY, 'Content-Type': 'application/json'}
        params = {'orderId': order_id, 'payId': pay_id}
        print(f'[soleaspay_verify] SENDING params={params}')  # TEMPORAIRE — à retirer après debug
        r = requests.get(f'{SOLEASPAY_BASE}/api/agent/verif-pay',
                          headers=headers, params=params, timeout=15)
        data = r.json()
        print(f'[soleaspay_verify] RAW RESPONSE status={r.status_code} body={r.text[:800]}')  # TEMPORAIRE — à retirer après debug
        if data.get('success'):
            return {'ok': True, 'status': data.get('status'), 'data': data.get('data', {})}
        return {'ok': False, 'detail': data.get('message', 'Erreur inconnue')}
    except Exception as e:
        print(f'[soleaspay_verify] error: {e}')  # TEMPORAIRE — à retirer après debug
        return {'ok': False, 'detail': str(e)}

def soleaspay_verify_callback_signature(header_value):
    if not header_value or not SOLEASPAY_CALLBACK_SECRET:
        return False
    expected = hashlib.sha512(SOLEASPAY_CALLBACK_SECRET.encode()).hexdigest()
    return hmac.compare_digest(expected, header_value)

def leekpay_create_checkout(amount, description, return_url=None, cancel_url=None,
                             customer_name=None, customer_phone=None, customer_email=None,
                             webhook_url=None, metadata=None):
    try:
        payload = {
            'amount': amount,
            'currency': 'XOF',
            'description': (description or '')[:500]
        }
        if return_url: payload['return_url'] = return_url
        if cancel_url: payload['cancel_url'] = cancel_url
        if customer_name: payload['customer_name'] = customer_name
        if customer_phone: payload['customer_phone'] = customer_phone
        if customer_email: payload['customer_email'] = customer_email
        if webhook_url: payload['webhook_url'] = webhook_url
        if metadata: payload['metadata'] = metadata

        r = requests.post(
            f'{LEEKPAY_API_BASE}/checkout',
            headers={
                'Authorization': f'Bearer {LEEKPAY_SECRET_KEY}',
                'Content-Type': 'application/json'
            },
            json=payload, timeout=15
        )
        if r.status_code == 201 and r.json().get('success'):
            return {'ok': True, 'data': r.json()['data']}
        print(f'[leekpay_create_checkout] status={r.status_code} body={r.text[:300]}')
        return {'ok': False, 'detail': r.text[:300]}
    except Exception as e:
        print(f'[leekpay_create_checkout] error: {e}')
        return {'ok': False, 'detail': str(e)}

def leekpay_get_checkout(checkout_id):
    try:
        r = requests.get(
            f'{LEEKPAY_API_BASE}/checkout/{checkout_id}',
            headers={'Authorization': f'Bearer {LEEKPAY_SECRET_KEY}'},
            timeout=10
        )
        if r.ok:
            return {'ok': True, 'data': r.json().get('data', {})}
        return {'ok': False, 'detail': r.text[:300]}
    except Exception as e:
        return {'ok': False, 'detail': str(e)}

def leekpay_verify_signature(raw_body, signature):
    if not signature or not LEEKPAY_PUBLIC_KEY:
        return False
    expected = hmac.new(LEEKPAY_PUBLIC_KEY.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

FREE_PLAN_MONTHLY_LIMIT = 300

PAYOUT_FEE_PERCENT = 3.5  # frais prélevés sur chaque retrait manuel

LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15

def is_locked_out(user):
    locked_until = user.get('locked_until')
    if not locked_until:
        return False
    try:
        lu = datetime.fromisoformat(locked_until.replace('Z', '+00:00')).replace(tzinfo=None)
        return datetime.utcnow() < lu
    except (ValueError, AttributeError):
        return False

def register_failed_login(user):
    """Compte les tentatives échouées (mot de passe ou code 2FA) et verrouille le
    compte temporairement après trop d'échecs, pour bloquer le brute-force."""
    attempts = (user.get('failed_login_attempts') or 0) + 1
    update = {'failed_login_attempts': attempts}
    if attempts >= LOGIN_MAX_ATTEMPTS:
        update['locked_until'] = (datetime.utcnow() + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)).isoformat()
    sb_patch('users', 'id', user['id'], update)

def reset_failed_login(user_id):
    sb_patch('users', 'id', user_id, {'failed_login_attempts': 0, 'locked_until': None})

def log_admin_action(action, details=None):
    """Journal d'audit des actions admin sensibles (KYC, comptes, retraits, config...).
    Best-effort : n'interrompt jamais l'action elle-même si l'écriture du log échoue."""
    try:
        ip = request.headers.get('x-forwarded-for', request.remote_addr or '')
        if ip and ',' in ip:
            ip = ip.split(',')[0].strip()
        sb_post('admin_audit_log', {
            'admin_id': getattr(request, 'user_id', None),
            'action': action,
            'details': details or {},
            'ip_address': ip,
            'created_at': datetime.utcnow().isoformat()
        })
    except Exception as e:
        print(f'[log_admin_action] error: {e}')
PAYOUT_MIN_AMOUNT = 600   # minimum de retrait, toutes devises confondues
CONVERSION_FEE_PERCENT = 5.5  # frais prélevés sur chaque conversion de devise entre poches
                               # (SoleasPay prend réellement ~5.36% sur ses conversions de devise
                               # via "Vendre une devise" — on s'aligne au-dessus pour ne jamais
                               # perdre d'argent quand une conversion réelle devient nécessaire)

REFERRAL_COMMISSION_RATE = 0.10  # 10% de l'abonnement du filleul

def generate_referral_code():
    return 'FP' + secrets.token_hex(3).upper()

def ensure_referral_code(user):
    if user.get('referral_code'):
        return user['referral_code']
    code = generate_referral_code()
    # évite les collisions improbables
    for _ in range(5):
        if not sb_get('users', f'referral_code=eq.{code}'):
            break
        code = generate_referral_code()
    sb_patch('users', 'id', user['id'], {'referral_code': code})
    return code

def get_markup_percent():
    rows = sb_get('site_config', 'key=eq.markup_percent')
    if rows:
        try:
            return float(rows[0]['value'])
        except (TypeError, ValueError):
            pass
    return 2.5

def get_subscription_price():
    rows = sb_get('site_config', 'key=eq.subscription_price')
    if rows:
        try:
            return float(rows[0]['value'])
        except (TypeError, ValueError):
            pass
    return 8500.0

def amount_with_markup(base_amount):
    """Montant à envoyer à LeekPay : le prix du marchand + notre marge, pour que le
    client final paie le surplus au lieu que ce soit déduit du solde du marchand."""
    return round(float(base_amount) * (1 + get_markup_percent() / 100), 2)

# ── Marge spécifique aux liens de paiement ────────
# Ajoutée directement au client au moment du prélèvement (pas déduite du marchand),
# pour que le marchand reçoive toujours son montant plein — évite qu'il aille voir
# ailleurs à cause de frais qui rognent ce qu'il reçoit.
LINK_MARKUP_DEFAULT_PERCENT = 5.0

# Frais fixe ajouté EN PLUS du pourcentage, sur chaque transaction. Nécessaire car
# SoleasPay prélève ses propres frais internes à chaque collecte (indépendamment de
# toute conversion de devise) — un pourcentage seul ne suffit pas à couvrir ce coût,
# surtout sur les petits montants.
LINK_MARKUP_DEFAULT_FLAT_FEE = 150

# Permet d'ajuster la marge par opérateur (portefeuille) si leurs coûts réels chez
# SoleasPay diffèrent. Clé = code opérateur (voir SOLEASPAY_SERVICES : 'om', 'momo',
# 'moov', 'wave', 'tmoney', 'vodacom', 'airtel'...). Laisser vide = valeur par défaut.
LINK_MARKUP_BY_OPERATOR = {
    # 'wave': 2.5,
    # 'om': 3.5,
}
LINK_MARKUP_FLAT_FEE_BY_OPERATOR = {
    # 'wave': 30,
    # 'om': 60,
}

def get_link_markup_percent(operator_key):
    return LINK_MARKUP_BY_OPERATOR.get(operator_key, LINK_MARKUP_DEFAULT_PERCENT)

def get_link_markup_flat_fee(operator_key):
    return LINK_MARKUP_FLAT_FEE_BY_OPERATOR.get(operator_key, LINK_MARKUP_DEFAULT_FLAT_FEE)

def link_amount_with_markup(base_amount, operator_key):
    pct = get_link_markup_percent(operator_key)
    flat = get_link_markup_flat_fee(operator_key)
    return round(float(base_amount) * (1 + pct / 100) + flat, 2)

# ── Marge spécifique à l'API directe ──────────────
# Même principe que les liens de paiement : ajoutée au client au moment du prélèvement,
# le marchand reçoit toujours son montant plein. Valeurs différentes des liens car le
# profil d'usage (intégrations techniques) diffère.
API_MARKUP_DEFAULT_PERCENT = 5.0
API_MARKUP_DEFAULT_FLAT_FEE = 150

API_MARKUP_BY_OPERATOR = {
    # 'wave': 4.0,
    # 'om': 5.5,
}
API_MARKUP_FLAT_FEE_BY_OPERATOR = {
    # 'wave': 60,
    # 'om': 120,
}

def get_api_markup_percent(operator_key):
    return API_MARKUP_BY_OPERATOR.get(operator_key, API_MARKUP_DEFAULT_PERCENT)

def get_api_markup_flat_fee(operator_key):
    return API_MARKUP_FLAT_FEE_BY_OPERATOR.get(operator_key, API_MARKUP_DEFAULT_FLAT_FEE)

def api_amount_with_markup(base_amount, operator_key):
    pct = get_api_markup_percent(operator_key)
    flat = get_api_markup_flat_fee(operator_key)
    return round(float(base_amount) * (1 + pct / 100) + flat, 2)

def get_user_by_id(user_id):
    users = sb_get('users', f'id=eq.{user_id}')
    return users[0] if users else {}

def get_currency_for_country(country_code):
    return next((c['currency'] for c in COUNTRIES if c['code'] == country_code), 'XOF')

def get_balances(user):
    """Retourne le dict des soldes par devise, ex: {'XAF': 1200, 'XOF': 500}."""
    return user.get('balances') or {}

def get_balance_for_currency(user, currency):
    return float(get_balances(user).get(currency) or 0)

def credit_user_balance(user_id, currency, amount):
    """Crédite la poche de solde correspondant à une devise précise, sans toucher aux autres."""
    user = get_user_by_id(user_id)
    balances = get_balances(user)
    balances[currency] = round(float(balances.get(currency) or 0) + float(amount), 2)
    sb_patch('users', 'id', user_id, {'balances': balances})

def debit_user_balance(user_id, currency, amount):
    user = get_user_by_id(user_id)
    balances = get_balances(user)
    balances[currency] = round(float(balances.get(currency) or 0) - float(amount), 2)
    sb_patch('users', 'id', user_id, {'balances': balances})

def send_payment_notification_email(merchant, tx):
    """Envoie un email au marchand quand il reçoit un paiement. Best-effort : ne bloque
    jamais le traitement du paiement si l'email échoue."""
    if not EMAIL_ADDRESS or not EMAIL_APP_PASSWORD:
        return
    to_email = (merchant or {}).get('email')
    if not to_email:
        return
    try:
        amount = tx.get('amount')
        currency = tx.get('currency') or 'XOF'
        firstname = (merchant.get('firstname') or '').strip()
        body = (
            f"Bonjour {firstname},\n\n"
            f"Vous venez de recevoir un paiement sur Flinpay :\n\n"
            f"Montant : {amount} {currency}\n"
            f"Client : {tx.get('client_name', '—')}\n"
            f"Téléphone : {tx.get('client_phone', '—')}\n"
            f"Référence : {tx.get('token', '—')}\n"
            f"Date : {datetime.utcnow().strftime('%d/%m/%Y %H:%M')} UTC\n\n"
            f"Connectez-vous à votre dashboard Flinpay pour voir le détail complet.\n\n"
            f"— L'équipe Flinpay"
        )
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = f"Nouveau paiement reçu — {amount} {currency}"
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email
        with smtplib.SMTP('smtp.gmail.com', 587, timeout=10) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_APP_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print(f'[send_payment_notification_email] error: {e}')

def get_request_client_info():
    """Capture les infos du visiteur qui déclenche le paiement (navigateur, IP, page d'origine),
    pour affichage dans l'historique des transactions."""
    ip = request.headers.get('x-forwarded-for', request.remote_addr or '')
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()
    return {
        'user_agent': (request.headers.get('User-Agent') or '')[:500],
        'ip_address': (ip or '')[:100],
        'referer_url': (request.headers.get('Referer') or '')[:500]
    }

def get_monthly_transaction_count(user_id):
    first_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    return sb_count('transactions', f'user_id=eq.{user_id}&created_at=gte.{first_of_month}')

def check_quota(user_id):
    """Retourne (autorisé, message_erreur_ou_None)."""
    user = get_user_by_id(user_id)
    if user.get('plan') == 'pro':
        return True, None
    count = get_monthly_transaction_count(user_id)
    if count >= FREE_PLAN_MONTHLY_LIMIT:
        return False, f"Limite de {FREE_PLAN_MONTHLY_LIMIT} transactions/mois atteinte sur le plan Starter. Passez au plan Pro pour un accès illimité."
    return True, None

def dispatch_merchant_webhooks(user_id, event, payload):
    hooks = sb_get('webhooks', f'user_id=eq.{user_id}&active=eq.true')
    for h in hooks:
        if event not in (h.get('events') or []):
            continue
        try:
            requests.post(h['url'], json={'event': event, 'data': payload}, timeout=8)
        except Exception as e:
            print(f"[dispatch_merchant_webhooks] error posting to {h.get('url')}: {e}")

def get_current_user():
    users = sb_get('users', f"id=eq.{request.user_id}")
    return users[0] if users else {}

@app.route('/dashboard')
@user_required
def dashboard():
    users = sb_get('users', f"id=eq.{request.user_id}")
    user = users[0] if users else {}
    return render_template('dashboard.html', user=user)

@app.route('/docs')
def docs():
    return render_template('docs.html')

# ── WIDGET : bouton "Payer avec Flinpay" à intégrer en 1 ligne ──
FLINPAY_WIDGET_JS = r"""
(function(){
  var ORIGIN = "https://www.flinpay.cfd";

  function injectStyles(){
    if(document.getElementById('flinpay-widget-styles')) return;
    var css = `
      .flinpay-btn{
        display:inline-flex;align-items:center;gap:8px;
        background:#1A3CFF;color:#fff;border:none;border-radius:10px;
        padding:12px 20px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Inter,sans-serif;
        font-weight:700;font-size:0.95rem;cursor:pointer;transition:all .15s;
        box-shadow:0 4px 14px rgba(26,60,255,0.25);
      }
      .flinpay-btn:hover{background:#1430e0;transform:translateY(-1px)}
      .flinpay-btn:active{transform:translateY(0)}
      .flinpay-btn svg{width:18px;height:18px;flex-shrink:0}
      .flinpay-overlay{
        position:fixed;inset:0;background:rgba(8,9,16,0.6);z-index:999998;
        display:flex;align-items:center;justify-content:center;padding:20px;
        opacity:0;transition:opacity .2s;backdrop-filter:blur(3px)
      }
      .flinpay-overlay.show{opacity:1}
      .flinpay-modal{
        position:relative;width:100%;max-width:460px;height:min(680px,90vh);
        border-radius:20px;overflow:hidden;box-shadow:0 30px 80px rgba(0,0,0,0.4);
        transform:translateY(16px) scale(.98);transition:transform .25s cubic-bezier(.16,1,.3,1)
      }
      .flinpay-overlay.show .flinpay-modal{transform:translateY(0) scale(1)}
      .flinpay-modal iframe{width:100%;height:100%;border:none;background:#141420}
      .flinpay-close{
        position:absolute;top:10px;right:10px;z-index:2;
        width:34px;height:34px;border-radius:50%;border:none;
        background:rgba(0,0,0,0.35);color:#fff;font-size:18px;cursor:pointer;
        display:flex;align-items:center;justify-content:center;line-height:1
      }
      .flinpay-close:hover{background:rgba(0,0,0,0.55)}
      .flinpay-loading{
        position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
        background:#141420;color:rgba(255,255,255,.5);font-family:sans-serif;font-size:.85rem
      }
    `;
    var style=document.createElement('style');
    style.id='flinpay-widget-styles';
    style.textContent=css;
    document.head.appendChild(style);
  }

  function openCheckout(linkToken){
    var overlay=document.createElement('div');
    overlay.className='flinpay-overlay';
    overlay.innerHTML=
      '<div class="flinpay-modal">'+
        '<div class="flinpay-loading">Chargement du paiement…</div>'+
        '<button class="flinpay-close" aria-label="Fermer">✕</button>'+
        '<iframe src="'+ORIGIN+'/pay/'+encodeURIComponent(linkToken)+'?embed=1" allow="clipboard-write"></iframe>'+
      '</div>';
    document.body.appendChild(overlay);
    document.body.style.overflow='hidden';
    requestAnimationFrame(function(){ overlay.classList.add('show'); });

    var iframe=overlay.querySelector('iframe');
    var loading=overlay.querySelector('.flinpay-loading');
    iframe.addEventListener('load', function(){ loading.style.display='none'; });

    function close(){
      overlay.classList.remove('show');
      document.body.style.overflow='';
      setTimeout(function(){ overlay.remove(); }, 200);
      document.removeEventListener('keydown', onKey);
    }
    function onKey(e){ if(e.key==='Escape') close(); }
    document.addEventListener('keydown', onKey);
    overlay.querySelector('.flinpay-close').addEventListener('click', close);
    overlay.addEventListener('click', function(e){ if(e.target===overlay) close(); });

    window.addEventListener('message', function(e){
      if(e.origin!==ORIGIN) return;
      if(e.data && e.data.flinpay==='payment_success'){
        setTimeout(close, 1500);
      }
    });
  }

  function renderButtons(){
    var nodes=document.querySelectorAll('[data-flinpay-link]:not([data-flinpay-ready])');
    nodes.forEach(function(el){
      el.setAttribute('data-flinpay-ready','1');
      var linkToken=el.getAttribute('data-flinpay-link');
      var label=el.getAttribute('data-flinpay-label') || 'Payer avec Flinpay';
      el.classList.add('flinpay-btn');
      el.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="5" width="20" height="14" rx="2"/><line x1="2" y1="10" x2="22" y2="10"/></svg><span>'+label+'</span>';
      el.addEventListener('click', function(ev){
        ev.preventDefault();
        openCheckout(linkToken);
      });
    });
  }

  injectStyles();
  if(document.readyState==='loading'){
    document.addEventListener('DOMContentLoaded', renderButtons);
  }else{
    renderButtons();
  }
  // Pour les sites qui injectent le bouton dynamiquement après coup.
  window.FlinpayWidget = { render: renderButtons };
})();
"""

@app.route('/widget.js')
def flinpay_widget_js():
    from flask import Response
    resp = Response(FLINPAY_WIDGET_JS, mimetype='application/javascript')
    resp.headers['Cache-Control'] = 'public, max-age=3600'
    return resp

@app.route('/favicon.ico')
def favicon():
    return '', 204

# ── API REGISTER ──────────────────────────────────
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    if not data:
        return jsonify({'ok': False, 'error': 'Données manquantes'}), 400
    for field in ['firstname','lastname','email','country','phone','password']:
        if not data.get(field):
            return jsonify({'ok': False, 'error': f'Champ manquant: {field}'}), 400
    email = data['email'].strip().lower()
    if len(data['password']) < 8:
        return jsonify({'ok': False, 'error': 'Mot de passe trop court'}), 400
    existing = sb_get('users', f'email=eq.{email}')
    if existing:
        return jsonify({'ok': False, 'error': 'Email déjà utilisé'}), 409

    referred_by = None
    ref_code = (data.get('referral_code') or '').strip().upper()
    if ref_code:
        referrers = sb_get('users', f'referral_code=eq.{ref_code}')
        if referrers:
            referred_by = referrers[0]['id']

    hashed = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user = sb_post('users', {
        'firstname': data['firstname'].strip(),
        'lastname': data['lastname'].strip(),
        'email': email,
        'company': data.get('company','').strip(),
        'country': data['country'],
        'phone': data['phone'].strip(),
        'password_hash': hashed,
        'plan': 'starter',
        'is_active': True,
        'referred_by': referred_by,
        'created_at': datetime.utcnow().isoformat()
    })
    if not user or (isinstance(user, dict) and user.get('_error')):
        detail = user.get('_detail') if isinstance(user, dict) else 'inconnue'
        return jsonify({'ok': False, 'error': f'Erreur Supabase: {detail}'}), 500
    return jsonify({'ok': True, 'message': 'Compte créé avec succès'})

# ── PAGE PUBLIQUE : LIEN DE PAIEMENT ──────────────
def _link_status(link):
    """Retourne (valide, raison) pour un lien de paiement."""
    if not link:
        return False, 'introuvable'
    if not link.get('active', True):
        return False, 'inactif'
    if link.get('expires_at'):
        try:
            if datetime.utcnow().date() > datetime.fromisoformat(link['expires_at']).date():
                return False, 'expire'
        except Exception:
            pass
    if link.get('usage_limit') and (link.get('paid_count') or 0) >= link['usage_limit']:
        return False, 'limite'
    return True, ''

@app.route('/pay/<token>')
def pay_page(token):
    links = sb_get('payment_links', f'token=eq.{token}')
    link = links[0] if links else None
    valid, reason = _link_status(link)
    if link and valid:
        sb_patch_multi('payment_links', {'token': token}, {'views': (link.get('views') or 0) + 1})
    image_url = sb_storage_public_url('payment-link-images', link['image_path']) if (link and link.get('image_path')) else None
    return render_template('pay.html', link=link, valid=valid, reason=reason, token=token, image_url=image_url,
                            countries_operators=SOLEASPAY_SERVICES, available_countries=COUNTRIES)

@app.route('/api/pay-link/<token>', methods=['POST'])
def api_pay_link(token):
    links = sb_get('payment_links', f'token=eq.{token}')
    link = links[0] if links else None
    valid, reason = _link_status(link)
    if not valid:
        messages = {
            'introuvable': 'Lien introuvable',
            'inactif': 'Ce lien est désactivé',
            'expire': 'Ce lien a expiré',
            'limite': "Ce lien a atteint sa limite d'utilisation"
        }
        return jsonify({'ok': False, 'error': messages.get(reason, 'Lien invalide')}), 400

    allowed, quota_error = check_quota(link['user_id'])
    if not allowed:
        return jsonify({'ok': False, 'error': quota_error}), 403

    data = request.get_json() or {}
    phone = (data.get('phone') or '').strip()
    operator = data.get('operator', '')
    customer_country = data.get('country', '')
    if not phone:
        return jsonify({'ok': False, 'error': 'Numéro de téléphone requis'}), 400

    if link.get('amount_type') == 'flexible':
        try:
            amount = float(data.get('amount'))
        except (TypeError, ValueError):
            return jsonify({'ok': False, 'error': 'Montant invalide'}), 400
        if amount <= 0:
            return jsonify({'ok': False, 'error': 'Montant invalide'}), 400
        if link.get('min_amount') and amount < link['min_amount']:
            return jsonify({'ok': False, 'error': f"Le montant minimum est de {link['min_amount']} XOF"}), 400
    else:
        amount = link['amount']

    import uuid
    tx_token = 'fp_tx_' + uuid.uuid4().hex[:20]
    customer_name = (data.get('name') or '').strip() or 'Client'

    merchant = get_user_by_id(link['user_id'])
    merchant_currency = next((c['currency'] for c in COUNTRIES if c['code'] == merchant.get('country')), 'XOF')

    # L'opérateur mobile money dépend du pays du CLIENT qui paie, pas du marchand.
    service_id = get_service_id(customer_country, operator)
    if not service_id:
        return jsonify({'ok': False, 'error': "Opérateur indisponible pour ce pays"}), 400

    # On collecte directement dans la devise réelle du portefeuille du client (celle de
    # son pays), en convertissant une seule fois depuis la devise d'affichage du marchand
    # si elles diffèrent — jamais via un détour XAF systématique, qui causait une double
    # conversion (la nôtre + celle, silencieuse, de SoleasPay au débit réel du portefeuille)
    # et donc une perte à chaque transaction hors zone du marchand.
    customer_currency = get_currency_for_country(customer_country) or merchant_currency
    markup_amount = link_amount_with_markup(amount, operator)
    collect_amount = soleaspay_convert(markup_amount, merchant_currency, customer_currency)
    if collect_amount < SOLEASPAY_MIN_AMOUNT:
        return jsonify({'ok': False, 'error': f"Montant trop faible (minimum {SOLEASPAY_MIN_AMOUNT} {customer_currency})"}), 400

    collect = soleaspay_collect(
        wallet=phone,
        amount=collect_amount,
        currency=customer_currency,
        order_id=tx_token,
        description=link.get('description') or link['name'],
        payer=customer_name,
        payer_email='',
        success_url=f'https://www.flinpay.cfd/pay/{token}/merci',
        failure_url=f'https://www.flinpay.cfd/pay/{token}',
        service_id=service_id
    )
    if not collect['ok']:
        return jsonify({'ok': False, 'error': f"Erreur SoleasPay: {collect['detail']}"}), 502

    # Le marchand est crédité dans la devise réellement collectée (customer_currency).
    # Si elle diffère de sa devise d'affichage, on convertit le montant de base pour que
    # le solde crédité reste financièrement équivalent à son prix d'origine.
    credited_amount = amount if customer_currency == merchant_currency else soleaspay_convert(amount, merchant_currency, customer_currency)

    tx = sb_post('transactions', {
        'token': tx_token,
        'order_id': 'link_' + uuid.uuid4().hex[:10],
        'amount': credited_amount,
        'client_amount': collect_amount,
        'fee_amount': round(collect_amount - credited_amount, 2),
        'client_name': customer_name,
        'client_phone': phone,
        'country': merchant.get('country', ''),
        'currency': customer_currency,
        'status': 'pending',
        'environment': 'production',
        'user_id': link['user_id'],
        'operator': operator,
        'gateway_reference': collect['data'].get('reference'),
        'payment_link_token': token,
        **get_request_client_info(),
        'created_at': datetime.utcnow().isoformat()
    })
    if not tx or (isinstance(tx, dict) and tx.get('_error')):
        return jsonify({'ok': False, 'error': 'Erreur lors de la création du paiement'}), 500

    return jsonify({
        'ok': True,
        'tx_token': tx_token,
        'message': 'Une confirmation de paiement a été envoyée sur le téléphone du client.'
    })

@app.route('/api/pay-status/<tx_token>')
def api_pay_status(tx_token):
    matches = sb_get('transactions', f'token=eq.{tx_token}')
    if not matches:
        return jsonify({'ok': False, 'error': 'Introuvable'}), 404
    tx = matches[0]

    if tx['status'] == 'pending' and tx.get('gateway_reference'):
        check = soleaspay_verify(tx['token'], tx['gateway_reference'])
        if check['ok']:
            status_map = {'SUCCESS': 'paid', 'REFUND': 'failed'}
            new_status = status_map.get(check.get('status'), tx['status'])
            if new_status != tx['status']:
                update = {'status': new_status}
                if new_status == 'paid':
                    update['paid_at'] = datetime.utcnow().isoformat()
                # Mise à jour atomique : seule la requête qui fait réellement basculer le
                # statut depuis 'pending' déclenche les effets ci-dessous. Empêche le
                # double crédit si le webhook SoleasPay traite la même transaction en
                # même temps que ce polling automatique du navigateur.
                won_race = sb_patch_if_pending('transactions', 'token', tx_token, update)
                if won_race:
                    tx['status'] = new_status
                    if new_status == 'paid' and tx.get('payment_link_token'):
                        links = sb_get('payment_links', f"token=eq.{tx['payment_link_token']}")
                        if links:
                            sb_patch_multi('payment_links', {'token': tx['payment_link_token']}, {'paid_count': (links[0].get('paid_count') or 0) + 1})
                    if new_status == 'paid':
                        mark_invoice_paid_if_applicable(tx)
                    if new_status == 'paid' and tx.get('user_id'):
                        merchant = get_user_by_id(tx['user_id'])
                        tx_currency = tx.get('currency') or 'XOF'
                        credit_user_balance(tx['user_id'], tx_currency, tx.get('amount') or 0)
                        send_payment_notification_email(merchant, tx)
                    if new_status in ('paid', 'failed') and tx.get('user_id'):
                        dispatch_merchant_webhooks(tx['user_id'], 'payment.success' if new_status == 'paid' else 'payment.failed', {
                            'token': tx.get('token'), 'order_id': tx.get('order_id'), 'amount': tx.get('amount'),
                            'status': new_status, 'client_name': tx.get('client_name'), 'client_phone': tx.get('client_phone')
                        })
                else:
                    # Un autre process (webhook) a déjà traité cette transition entre-temps :
                    # on relit son état final pour renvoyer une réponse cohérente au client.
                    refreshed = sb_get('transactions', f'token=eq.{tx_token}')
                    if refreshed:
                        tx = refreshed[0]

    link = None
    if tx.get('payment_link_token'):
        links = sb_get('payment_links', f"token=eq.{tx['payment_link_token']}")
        link = links[0] if links else None

    return jsonify({
        'ok': True,
        'status': tx['status'],
        'message': (link.get('thank_you_message') if link and link.get('thank_you_message') else None) or 'Merci pour votre paiement !',
        'redirect_url': link.get('redirect_url') if link else None
    })

@app.route('/pay/<token>/merci')
def pay_thank_you(token):
    links = sb_get('payment_links', f'token=eq.{token}')
    link = links[0] if links else None
    message = (link.get('thank_you_message') if link and link.get('thank_you_message') else None) or 'Merci pour votre paiement !'
    return render_template('pay_thanks.html', message=message)

# ── WEBHOOK SOLEASPAY ─────────────────────────────
@app.route('/webhook/soleaspay', methods=['POST'])
def webhook_soleaspay():
    signature = request.headers.get('x-private-key', '')
    print(f'[webhook_soleaspay] headers={dict(request.headers)}')  # TEMPORAIRE — à retirer après debug
    payload = request.get_json(silent=True) or {}
    print(f'[webhook_soleaspay] payload={payload}')  # TEMPORAIRE — à retirer après debug
    if not soleaspay_verify_callback_signature(signature):
        return jsonify({'ok': False, 'error': 'Signature invalide'}), 401

    remote_status = payload.get('status')  # SUCCESS | RECEIVED | REFUND
    tx_data = payload.get('data', {})
    external_reference = tx_data.get('external_reference')  # notre order_id = notre token

    if not external_reference or not remote_status:
        return jsonify({'ok': False, 'error': 'Payload incomplet'}), 400

    status_map = {'SUCCESS': 'paid', 'REFUND': 'failed'}

    # Abonnement Pro ?
    pending_users = sb_get('users', f'pending_upgrade_checkout_id=eq.{external_reference}')
    if pending_users:
        if status_map.get(remote_status) == 'paid':
            u = pending_users[0]
            sb_patch('users', 'id', u['id'], {
                'plan': 'pro',
                'plan_expires_at': (datetime.utcnow() + timedelta(days=30)).isoformat(),
                'pending_upgrade_checkout_id': None
            })
            if u.get('referred_by'):
                commission = round(get_subscription_price() * REFERRAL_COMMISSION_RATE, 2)
                sb_post('referral_earnings', {
                    'referrer_id': u['referred_by'],
                    'referred_id': u['id'],
                    'amount': commission,
                    'source': 'subscription',
                    'created_at': datetime.utcnow().isoformat()
                })
                referrer = get_user_by_id(u['referred_by'])
                new_balance = (referrer.get('referral_balance') or 0) + commission
                sb_patch('users', 'id', u['referred_by'], {'referral_balance': new_balance})
        return jsonify({'ok': True, 'note': 'abonnement traité'}), 200

    matches = sb_get('transactions', f'token=eq.{external_reference}')
    if not matches:
        return jsonify({'ok': True, 'note': 'transaction inconnue'}), 200
    tx = matches[0]

    new_status = status_map.get(remote_status, tx.get('status'))
    update = {'status': new_status}
    if new_status == 'paid':
        update['paid_at'] = datetime.utcnow().isoformat()

    # Mise à jour atomique : seule la requête qui fait réellement basculer le statut
    # depuis 'pending' déclenche les effets ci-dessous. Empêche le double crédit si la
    # vérification automatique du navigateur traite la même transaction en même temps
    # que ce webhook.
    won_race = sb_patch_if_pending('transactions', 'token', tx['token'], update)
    if not won_race:
        return jsonify({'ok': True, 'note': 'déjà traitée'}), 200

    if new_status == 'paid' and tx.get('payment_link_token'):
        links = sb_get('payment_links', f"token=eq.{tx['payment_link_token']}")
        if links:
            sb_patch_multi('payment_links', {'token': tx['payment_link_token']}, {'paid_count': (links[0].get('paid_count') or 0) + 1})

    if new_status == 'paid':
        mark_invoice_paid_if_applicable(tx)

    if new_status == 'paid' and tx.get('user_id'):
        # Le marchand reçoit le montant plein : notre marge a déjà été prise en
        # majorant ce que le client final a payé (voir amount_with_markup).
        merchant = get_user_by_id(tx['user_id'])
        tx_currency = tx.get('currency') or 'XOF'
        credit_user_balance(tx['user_id'], tx_currency, tx.get('amount') or 0)
        send_payment_notification_email(merchant, tx)

    if new_status in ('paid', 'failed') and tx.get('user_id'):
        dispatch_merchant_webhooks(tx['user_id'], 'payment.success' if new_status == 'paid' else 'payment.failed', {
            'token': tx.get('token'), 'order_id': tx.get('order_id'), 'amount': tx.get('amount'),
            'status': new_status, 'client_name': tx.get('client_name'), 'client_phone': tx.get('client_phone')
        })

    return jsonify({'ok': True}), 200

# ── ADMIN LOGIN (obsolète — redirige vers le login normal) ──
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    return redirect(url_for('login_page'))

@app.route('/admin/logout')
def admin_logout():
    resp = make_response(redirect(url_for('login_page')))
    resp.delete_cookie('fp_user_token')
    return resp

@app.route('/admin')
@admin_required
def admin():
    return render_template('admin.html', user=get_current_user())

@app.route('/admin/payments')
@admin_required
def admin_payments_page():
    return render_template('admin_payments.html', user=get_current_user())

@app.route('/api/admin/payments', methods=['GET'])
@admin_required
def api_admin_payments():
    txs = sb_get('transactions', 'order=created_at.desc&limit=500')
    all_users = sb_get('users', 'limit=1000')
    users_map = {u['id']: u for u in all_users}

    items = []
    total_fees_paid = 0.0
    for t in txs:
        merchant = users_map.get(t.get('user_id'), {})
        fee = t.get('fee_amount')
        if fee is not None and t.get('status') == 'paid':
            try:
                total_fees_paid += float(fee)
            except (TypeError, ValueError):
                pass
        source = 'Lien' if t.get('payment_link_token') else ('Facture' if t.get('invoice_token') else 'API')
        items.append({
            'token': t.get('token'),
            'merchant_name': f"{merchant.get('firstname','')} {merchant.get('lastname','')}".strip(),
            'merchant_email': merchant.get('email'),
            'client_name': t.get('client_name'),
            'client_amount': t.get('client_amount'),
            'merchant_amount': t.get('amount'),
            'fee_amount': t.get('fee_amount'),
            'currency': t.get('currency') or 'XOF',
            'status': t.get('status'),
            'source': source,
            'operator': t.get('operator'),
            'created_at': t.get('created_at')
        })

    return jsonify({'ok': True, 'items': items, 'total_fees_paid': round(total_fees_paid, 2)})

# ── ADMIN : TRANSACTIONS (tous les utilisateurs) ──
@app.route('/api/admin/transactions', methods=['GET'])
@admin_required
def api_admin_get_transactions():
    return jsonify({'ok': True, 'items': sb_get('transactions', 'order=created_at.desc&limit=500')})

@app.route('/api/admin/transactions/<token>', methods=['PUT'])
@admin_required
def api_admin_update_transaction(token):
    ok = sb_patch_multi('transactions', {'token': token}, request.get_json())
    return jsonify({'ok': ok})

@app.route('/api/admin/transactions/<token>', methods=['DELETE'])
@admin_required
def api_admin_delete_transaction(token):
    ok = sb_delete_multi('transactions', {'token': token})
    return jsonify({'ok': ok})

# ── ADMIN : PAYOUTS ────────────────────────────────
@app.route('/api/admin/payouts', methods=['GET'])
@admin_required
def api_admin_get_payouts():
    return jsonify({'ok': True, 'items': sb_get('payouts', 'order=created_at.desc')})

@app.route('/api/admin/payouts', methods=['POST'])
@admin_required
def api_admin_create_payout():
    data = request.get_json() or {}
    if not data.get('user_id') or not data.get('amount') or not data.get('phone'):
        return jsonify({'ok': False, 'error': 'user_id, amount et phone sont requis'}), 400

    target_user_id = data.get('user_id')
    try:
        amount = float(data.get('amount'))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'Montant invalide'}), 400

    target_user = get_user_by_id(target_user_id)
    withdraw_country = (data.get('country') or target_user.get('country') or '').strip()
    withdraw_currency = get_currency_for_country(withdraw_country)
    available_in_currency = get_balance_for_currency(target_user, withdraw_currency)

    if amount > available_in_currency and not data.get('force'):
        balances = get_balances(target_user)
        other_currencies = {c: v for c, v in balances.items() if c != withdraw_currency and v and v > 0}
        other_desc = (', '.join(f'{v:,.0f} {c}' for c, v in other_currencies.items())
                      if other_currencies else 'aucun autre solde')
        return jsonify({
            'ok': False,
            'error': (f"Solde insuffisant en {withdraw_currency} pour ce marchand "
                      f"(disponible : {available_in_currency:,.0f} {withdraw_currency} — "
                      f"autres devises : {other_desc}). Convertissez via /convert avant de "
                      f"lancer ce retrait, ou passez explicitement 'force': true pour outrepasser.")
        }), 400

    fee = round(amount * PAYOUT_FEE_PERCENT / 100, 2)
    net_amount = round(amount - fee, 2)

    payload = {
        'user_id': target_user_id,
        'amount': amount,
        'fee': fee,
        'net_amount': net_amount,
        'currency': withdraw_currency,
        'phone': data.get('phone'),
        'operator': data.get('operator', ''),
        'country': withdraw_country,
        'status': data.get('status', 'pending'),
        'note': data.get('note', ''),
        'created_at': datetime.utcnow().isoformat()
    }
    row = sb_post('payouts', payload)
    if not row or (isinstance(row, dict) and row.get('_error')):
        detail = row.get('_detail') if isinstance(row, dict) else 'inconnue'
        return jsonify({'ok': False, 'error': f'Erreur Supabase: {detail}'}), 500

    debit_user_balance(target_user_id, withdraw_currency, amount)
    log_admin_action('payout_create', {'target_user_id': target_user_id, 'amount': amount, 'currency': withdraw_currency})
    return jsonify({'ok': True, 'item': row[0] if isinstance(row, list) else row})

@app.route('/api/admin/payouts/<int:pid>', methods=['PUT'])
@admin_required
def api_admin_update_payout(pid):
    data = request.get_json() or {}
    matches = sb_get('payouts', f'id=eq.{pid}')
    if not matches:
        return jsonify({'ok': False, 'error': 'Introuvable'}), 404
    payout = matches[0]

    ok = sb_patch('payouts', 'id', pid, data)

    if data.get('status') == 'failed' and payout.get('status') != 'failed':
        # Corrige le même bug que celui trouvé sur les autres flux : le remboursement doit
        # aller dans la bonne poche de devise, pas dans l'ancien champ available_balance
        # qui n'est plus tenu à jour.
        refund_currency = payout.get('currency') or get_currency_for_country(payout.get('country', ''))
        credit_user_balance(payout['user_id'], refund_currency, payout['amount'])
    elif data.get('status') == 'paid' and not payout.get('processed_at'):
        sb_patch('payouts', 'id', pid, {'processed_at': datetime.utcnow().isoformat()})

    if ok:
        log_admin_action('payout_update', {'payout_id': pid, 'changes': data})
    return jsonify({'ok': ok})

@app.route('/api/admin/payouts/<int:pid>', methods=['DELETE'])
@admin_required
def api_admin_delete_payout(pid):
    ok = sb_delete('payouts', 'id', pid)
    if ok:
        log_admin_action('payout_delete', {'payout_id': pid})
    return jsonify({'ok': ok})

# ── ADMIN : UTILISATEURS (voir/modifier/supprimer tout) ──
@app.route('/api/admin/users', methods=['GET'])
@admin_required
def api_admin_get_users():
    users = sb_get('users', 'order=created_at.desc&limit=500')
    now = datetime.utcnow()
    safe = []
    for u in users:
        u2 = {k: v for k, v in u.items() if k != 'password_hash'}
        u2['is_online'] = _is_user_online(u.get('last_seen_at'), now)
        u_balances = get_balances(u)
        u2['total_balance'] = sum(u_balances.values()) if u_balances else u.get('available_balance', 0)
        safe.append(u2)
    return jsonify({'ok': True, 'items': safe})

def _is_user_online(last_seen_at, now=None):
    if not last_seen_at:
        return False
    now = now or datetime.utcnow()
    try:
        last_seen = datetime.fromisoformat(last_seen_at.replace('Z', '+00:00')).replace(tzinfo=None)
        return (now - last_seen).total_seconds() < 120
    except (ValueError, AttributeError):
        return False

@app.route('/admin/users/<user_id>')
@admin_required
def admin_user_detail_page(user_id):
    return render_template('admin_user_detail.html', user=get_current_user(), target_user_id=user_id)

@app.route('/api/admin/users/<user_id>/full', methods=['GET'])
@admin_required
def api_admin_get_user_full(user_id):
    users = sb_get('users', f'id=eq.{user_id}')
    if not users:
        return jsonify({'ok': False, 'error': 'Utilisateur introuvable'}), 404
    target = {k: v for k, v in users[0].items() if k != 'password_hash'}
    target['is_online'] = _is_user_online(target.get('last_seen_at'))
    target_balances = get_balances(target)
    target['total_balance'] = sum(target_balances.values()) if target_balances else target.get('available_balance', 0)

    payment_links = sb_get('payment_links', f'user_id=eq.{user_id}&order=created_at.desc')
    for l in payment_links:
        if l.get('image_path'):
            l['image_url'] = sb_storage_public_url('payment-link-images', l['image_path'])

    invoices = sb_get('invoices', f'user_id=eq.{user_id}&order=created_at.desc')

    api_keys = sb_get('api_keys', f'user_id=eq.{user_id}&order=created_at.desc')
    safe_keys = [{
        'id': k['id'], 'key_prefix': k['key_prefix'], 'environment': k.get('environment', 'live'),
        'label': k.get('label') or '', 'active': k.get('active', True),
        'created_at': k.get('created_at'), 'last_used_at': k.get('last_used_at')
    } for k in api_keys]

    webhooks = sb_get('webhooks', f'user_id=eq.{user_id}&order=created_at.desc')
    transactions = sb_get('transactions', f'user_id=eq.{user_id}&order=created_at.desc&limit=100')
    payouts = sb_get('payouts', f'user_id=eq.{user_id}&order=created_at.desc')
    referred_users = sb_get('users', f'referred_by=eq.{user_id}&order=created_at.desc')
    referred_safe = [{'firstname': u.get('firstname'), 'lastname': u.get('lastname'),
                       'email': u.get('email'), 'plan': u.get('plan'), 'created_at': u.get('created_at')} for u in referred_users]

    return jsonify({
        'ok': True,
        'user': target,
        'payment_links': payment_links,
        'invoices': invoices,
        'api_keys': safe_keys,
        'webhooks': webhooks,
        'transactions': transactions,
        'payouts': payouts,
        'referred_users': referred_safe
    })

@app.route('/api/admin/users/<user_id>', methods=['PUT'])
@admin_required
def api_admin_update_user(user_id):
    data = request.get_json() or {}
    data.pop('password_hash', None)
    data.pop('id', None)
    ok = sb_patch('users', 'id', user_id, data)
    if ok:
        log_admin_action('user_update', {'target_user_id': user_id, 'fields': list(data.keys())})
    return jsonify({'ok': ok})

@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@admin_required
def api_admin_delete_user(user_id):
    ok = sb_delete('users', 'id', user_id)
    if ok:
        log_admin_action('user_delete', {'target_user_id': user_id})
    return jsonify({'ok': ok})

@app.route('/api/admin/overview')
@admin_required
def api_admin_overview():
    return jsonify({
        'ok': True,
        'users': sb_count('users'),
        'transactions': sb_count('transactions'),
        'pending_kyc': sb_count('users', 'kyc_status=eq.pending'),
        'payment_links': sb_count('payment_links')
    })

# ── API ADMIN CONFIG ──────────────────────────────
@app.route('/api/admin/config', methods=['GET'])
@admin_required
def api_get_config():
    return jsonify({'ok': True, 'items': sb_get('site_config')})

@app.route('/api/admin/config', methods=['PUT'])
@admin_required
def api_update_config():
    body = request.get_json()
    ok = sb_patch('site_config', 'key', body.get('key'), {'value': body.get('value'), 'updated_at': datetime.utcnow().isoformat()})
    return jsonify({'ok': ok})

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def api_get_stats():
    return jsonify({'ok': True, 'items': sb_get('stats', 'order=order_index.asc')})

@app.route('/api/admin/stats', methods=['POST'])
@admin_required
def api_create_stat():
    row = sb_post('stats', request.get_json())
    if not row or (isinstance(row, dict) and row.get('_error')):
        detail = row.get('_detail') if isinstance(row, dict) else 'inconnue'
        return jsonify({'ok': False, 'error': f'Erreur Supabase: {detail}'}), 500
    return jsonify({'ok': True, 'item': row[0] if isinstance(row, list) else row})

@app.route('/api/admin/stats/<int:sid>', methods=['PUT'])
@admin_required
def api_update_stat(sid):
    return jsonify({'ok': sb_patch('stats', 'id', sid, request.get_json())})

@app.route('/api/admin/stats/<int:sid>', methods=['DELETE'])
@admin_required
def api_delete_stat(sid):
    return jsonify({'ok': sb_delete('stats', 'id', sid)})

@app.route('/api/admin/features', methods=['GET'])
@admin_required
def api_get_features():
    return jsonify({'ok': True, 'items': sb_get('features', 'order=order_index.asc')})

@app.route('/api/admin/features', methods=['POST'])
@admin_required
def api_create_feature():
    row = sb_post('features', request.get_json())
    if not row or (isinstance(row, dict) and row.get('_error')):
        detail = row.get('_detail') if isinstance(row, dict) else 'inconnue'
        return jsonify({'ok': False, 'error': f'Erreur Supabase: {detail}'}), 500
    return jsonify({'ok': True, 'item': row[0] if isinstance(row, list) else row})

@app.route('/api/admin/features/<int:fid>', methods=['PUT'])
@admin_required
def api_update_feature(fid):
    return jsonify({'ok': sb_patch('features', 'id', fid, request.get_json())})

@app.route('/api/admin/features/<int:fid>', methods=['DELETE'])
@admin_required
def api_delete_feature(fid):
    return jsonify({'ok': sb_delete('features', 'id', fid)})

@app.route('/api/admin/pricing', methods=['GET'])
@admin_required
def api_get_pricing():
    return jsonify({'ok': True, 'items': sb_get('pricing_plans', 'order=order_index.asc')})

@app.route('/api/admin/pricing', methods=['POST'])
@admin_required
def api_create_plan():
    row = sb_post('pricing_plans', request.get_json())
    if not row or (isinstance(row, dict) and row.get('_error')):
        detail = row.get('_detail') if isinstance(row, dict) else 'inconnue'
        return jsonify({'ok': False, 'error': f'Erreur Supabase: {detail}'}), 500
    return jsonify({'ok': True, 'item': row[0] if isinstance(row, list) else row})

@app.route('/api/admin/pricing/<int:pid>', methods=['PUT'])
@admin_required
def api_update_plan(pid):
    return jsonify({'ok': sb_patch('pricing_plans', 'id', pid, request.get_json())})

@app.route('/api/admin/pricing/<int:pid>', methods=['DELETE'])
@admin_required
def api_delete_plan(pid):
    return jsonify({'ok': sb_delete('pricing_plans', 'id', pid)})

@app.route('/api/admin/testimonials', methods=['GET'])
@admin_required
def api_get_testimonials():
    return jsonify({'ok': True, 'items': sb_get('testimonials', 'order=order_index.asc')})

@app.route('/api/admin/testimonials', methods=['POST'])
@admin_required
def api_create_testimonial():
    row = sb_post('testimonials', request.get_json())
    if not row or (isinstance(row, dict) and row.get('_error')):
        detail = row.get('_detail') if isinstance(row, dict) else 'inconnue'
        return jsonify({'ok': False, 'error': f'Erreur Supabase: {detail}'}), 500
    return jsonify({'ok': True, 'item': row[0] if isinstance(row, list) else row})

@app.route('/api/admin/testimonials/<int:tid>', methods=['PUT'])
@admin_required
def api_update_testimonial(tid):
    return jsonify({'ok': sb_patch('testimonials', 'id', tid, request.get_json())})

@app.route('/api/admin/testimonials/<int:tid>', methods=['DELETE'])
@admin_required
def api_delete_testimonial(tid):
    return jsonify({'ok': sb_delete('testimonials', 'id', tid)})

# ── ERREURS ───────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    import traceback
    orig = getattr(e, 'original_exception', e)
    traceback.print_exc()
    return jsonify({'error': str(orig), 'type': type(orig).__name__}), 500


@app.route('/transactions')
@user_required
def transactions():
    return render_template('transactions.html', user=get_current_user())

@app.route('/payouts')
@user_required
def payouts():
    return render_template('payouts.html', user=get_current_user())

@app.route('/api-keys')
@user_required
def api_keys_page():
    return render_template('api_keys.html', user=get_current_user())

@app.route('/webhooks')
@user_required
def webhooks_page():
    return render_template('webhooks.html', user=get_current_user())

@app.route('/sandbox')
@user_required
def sandbox():
    return render_template('sandbox.html', user=get_current_user())

@app.route('/profile')
@user_required
def profile():
    return render_template('profile.html', user=get_current_user())

@app.route('/billing')
@user_required
def billing():
    return render_template('billing.html', user=get_current_user())

@app.route('/payment-links')
@user_required
def payment_links():
    return render_template('payment_links.html', user=get_current_user())

@app.route('/referral')
@user_required
def referral():
    return render_template('referral.html', user=get_current_user())

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
