import logging
import uuid as uuid_lib
from datetime import datetime

import bcrypt
from flask import Blueprint, request, jsonify, render_template, make_response

from config import config
from extensions import limiter
from db.supabase import sb_patch, sb_patch_multi, sb_get_eq
from services.auth import user_required, get_current_user, csrf_protect
from services.billing import (
    get_balance_for_currency, credit_user_balance, debit_user_balance,
    amount_with_markup, get_subscription_price, ensure_referral_code,
)
from services.restrictions import is_login_blocked
from services.activity_log import log_user_activity
from services import gateway
from services import fx

logger = logging.getLogger('flinpay.routes.dashboard')

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
@user_required
def dashboard():
    return render_template('dashboard.html', user=get_current_user())

@dashboard_bp.route('/api/profile', methods=['PUT'])
@user_required
@csrf_protect
def api_update_profile():
    data = request.get_json()
    if not data:
        return jsonify({'ok': False, 'error': 'Données manquantes'}), 400
    allowed = {}
    for field in ['firstname', 'lastname', 'company', 'phone']:
        if field in data and isinstance(data[field], str):
            allowed[field] = data[field].strip()[:120]
    if not allowed:
        return jsonify({'ok': False, 'error': 'Aucun champ à mettre à jour'}), 400
    ok = sb_patch('users', 'id', request.user_id, allowed)
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la mise à jour du profil'}), 500
    return jsonify({'ok': True, 'message': 'Profil mis à jour'})

@dashboard_bp.route('/api/password', methods=['PUT'])
@user_required
@csrf_protect
@limiter.limit('10 per hour')
def api_change_password():
    data = request.get_json()
    if not data or not data.get('old_password') or not data.get('new_password'):
        return jsonify({'ok': False, 'error': 'Champs manquants'}), 400
    if len(data['new_password']) < 8:
        return jsonify({'ok': False, 'error': 'Le nouveau mot de passe doit contenir au moins 8 caractères'}), 400

    user = get_current_user()
    if not user:
        return jsonify({'ok': False, 'error': 'Utilisateur introuvable'}), 404
    if not bcrypt.checkpw(data['old_password'].encode('utf-8'), user['password_hash'].encode('utf-8')):
        return jsonify({'ok': False, 'error': 'Mot de passe actuel incorrect'}), 401

    new_hash = bcrypt.hashpw(data['new_password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    ok = sb_patch('users', 'id', request.user_id, {'password_hash': new_hash})
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la mise à jour'}), 500
    return jsonify({'ok': True, 'message': 'Mot de passe mis à jour'})

@dashboard_bp.route('/api/account', methods=['DELETE'])
@user_required
@csrf_protect
@limiter.limit('3 per hour')
def api_delete_account():
    data = request.get_json() or {}
    password = data.get('password')
    if not password:
        return jsonify({'ok': False, 'error': 'Mot de passe requis pour confirmer la suppression'}), 400
    
    user = get_current_user()
    if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        return jsonify({'ok': False, 'error': 'Mot de passe incorrect'}), 401

    # Soft delete : on ne supprime jamais les données financières
    ok = sb_patch('users', 'id', request.user_id, {
        'is_active': False, 
        'deleted_at': datetime.utcnow().isoformat()
    })
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la suppression du compte'}), 500
        
    resp = make_response(jsonify({'ok': True}))
    resp.delete_cookie('__Host-fp_session')
    resp.delete_cookie('fp_csrf_token')
    return resp

# ── Conversion entre devises ──────────────────────────
@dashboard_bp.route('/convert')
@user_required
def convert_page():
    return render_template('convert.html', user=get_current_user())

@dashboard_bp.route('/api/fx-preview', methods=['GET'])
@user_required
def api_fx_preview():
    from_currency = (request.args.get('from') or '').strip().upper()
    to_currency = (request.args.get('to') or '').strip().upper()
    try:
        amount = float(request.args.get('amount', 0))
    except (TypeError, ValueError):
        amount = 0
    valid_currencies = {c['currency'] for c in config.COUNTRIES}
    if (from_currency not in valid_currencies or to_currency not in valid_currencies
            or from_currency == to_currency or amount <= 0):
        return jsonify({'ok': False, 'error': 'Paramètres invalides'}), 400

    fee = round(amount * config.CONVERSION_FEE_PERCENT / 100, 2)
    amount_after_fee = round(amount - fee, 2)
    converted = fx.convert(amount_after_fee, from_currency, to_currency)
    if converted is None:
        return jsonify({'ok': False, 'error': f'Conversion non disponible'}), 400
    return jsonify({'ok': True, 'fee': fee, 'amount_after_fee': amount_after_fee, 'converted_amount': converted})

@dashboard_bp.route('/api/convert-balance', methods=['POST'])
@user_required
@csrf_protect
@limiter.limit('20 per hour')
def api_convert_balance():
    data = request.get_json() or {}
    from_currency = (data.get('from_currency') or '').strip().upper()
    to_currency = (data.get('to_currency') or '').strip().upper()
    try:
        amount = float(data.get('amount'))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'Montant invalide'}), 400

    valid_currencies = {c['currency'] for c in config.COUNTRIES}
    if from_currency not in valid_currencies or to_currency not in valid_currencies or from_currency == to_currency:
        return jsonify({'ok': False, 'error': 'Sélectionnez deux devises différentes'}), 400
    if amount <= 0:
        return jsonify({'ok': False, 'error': 'Montant invalide'}), 400

    user = get_current_user()
    available = get_balance_for_currency(user, from_currency)
    if amount > available:
        return jsonify({'ok': False, 'error': f'Solde insuffisant (disponible : {available:,.0f})'}), 400

    fee = round(amount * config.CONVERSION_FEE_PERCENT / 100, 2)
    amount_after_fee = round(amount - fee, 2)
    converted_amount = fx.convert(amount_after_fee, from_currency, to_currency)
    if converted_amount is None:
        return jsonify({'ok': False, 'error': f'Conversion non disponible'}), 400

    # ATTENTION : Idéalement, ces deux opérations doivent être dans une seule transaction SQL atomique.
    # Avec PostgREST, si le serveur crash entre les deux, l'argent est perdu.
    debit_user_balance(request.user_id, from_currency, amount)
    credit_user_balance(request.user_id, to_currency, converted_amount)
    
    log_user_activity(request.user_id, 'balance_converted', {
        'from_currency': from_currency, 'to_currency': to_currency, 'amount': amount
    })

    return jsonify({
        'ok': True, 'from_currency': from_currency, 'to_currency': to_currency,
        'amount': amount, 'fee': fee, 'converted_amount': converted_amount,
        'message': f'{amount:,.0f} {from_currency} converti en {converted_amount:,.0f} {to_currency}'
    })

@dashboard_bp.route('/api/billing/subscribe', methods=['POST'])
@user_required
@csrf_protect
@limiter.limit('10 per hour')
def api_billing_subscribe():
    user = get_current_user()
    if is_login_blocked(user):
        return jsonify({'ok': False, 'error': 'Ce compte est actuellement restreint'}), 403
    if user.get('plan') == 'pro':
        return jsonify({'ok': False, 'error': 'Vous êtes déjà abonné au plan Pro'}), 400

    data = request.get_json() or {}
    phone = (data.get('phone') or user.get('phone') or '').strip()
    operator = data.get('operator', '')
    if not phone:
        return jsonify({'ok': False, 'error': 'Numéro de téléphone requis'}), 400

    service = gateway.find_service(user.get('country', ''), operator, for_operation='collect')
    if not service:
        return jsonify({'ok': False, 'error': "Opérateur non disponible pour votre pays"}), 400

    price = get_subscription_price()
    merchant_currency = next((c['currency'] for c in config.COUNTRIES if c['code'] == user.get('country')), 'XOF')
    base_price = price if merchant_currency == service['currency'] else fx.convert(price, merchant_currency, service['currency'])
    if base_price is None:
        return jsonify({'ok': False, 'error': f"Opérateur incompatible avec votre devise"}), 400
    total = amount_with_markup(base_price)

    idempotency_key = f"sub-{request.user_id}-{uuid_lib.uuid4().hex[:10]}"
    try:
        sub = gateway.subscription_create(
            customer_email=user.get('email', ''), customer_phone=phone, amount=total,
            currency=service['currency'], frequency='MONTHLY',
            description='Abonnement Flinpay Pro (mensuel)',
            metadata={'user_id': request.user_id, 'plan': 'pro'},
            idempotency_key=idempotency_key,
        )
    except gateway.GatewayError as e:
        return jsonify({'ok': False, 'error': f"Impossible de créer l'abonnement: {e}"}), 502

    subscription_reference = sub.get('reference') or sub.get('subscription_reference')
    if not subscription_reference:
        return jsonify({'ok': False, 'error': "Réponse inattendue de la passerelle"}), 502

    sb_patch('users', 'id', request.user_id, {
        'pending_upgrade_checkout_id': subscription_reference,
        'pending_upgrade_currency': service['currency'],
    })
    log_user_activity(request.user_id, 'subscription_requested', {'reference': subscription_reference})
    return jsonify({'ok': True, 'message': 'Une confirmation a été envoyée.'})

@dashboard_bp.route('/billing')
@user_required
def billing():
    return render_template('billing.html', user=get_current_user())

@dashboard_bp.route('/api/referral')
@user_required
def api_referral():
    user = get_current_user()
    code = ensure_referral_code(user)
    referred = sb_get_eq('users', 'referred_by', request.user_id, extra_query='order=created_at.desc')
    referred_list = [{'firstname': u.get('firstname', ''), 'lastname': u.get('lastname', ''), 'plan': u.get('plan', 'starter'), 'created_at': u.get('created_at')} for u in referred]
    earnings = sb_get_eq('referral_earnings', 'referrer_id', request.user_id, extra_query='order=created_at.desc&limit=50')

    return jsonify({
        'ok': True, 'referral_code': code,
        'referral_link': f'https://www.flinpay.cfd/register?ref={code}',
        'referred_count': len(referred_list), 'referred_users': referred_list,
        'balance': user.get('referral_balance', 0), 'earnings_history': earnings,
        'commission_rate': config.REFERRAL_COMMISSION_RATE
    })

@dashboard_bp.route('/referral')
@user_required
def referral():
    return render_template('referral.html', user=get_current_user())

@dashboard_bp.route('/profile')
@user_required
def profile_page():
    return render_template('profile.html', user=get_current_user())