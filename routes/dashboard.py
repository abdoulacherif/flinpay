"""
routes/dashboard.py — espace connecté du marchand : dashboard, profil, mot de
passe, suppression de compte, conversion entre devises, abonnement Pro,
parrainage.

Toutes les routes qui déplacent de l'argent ou affaiblissent la sécurité du
compte (mot de passe, suppression de compte, conversion de solde) sont
protégées par @csrf_protect en plus de @user_required — voir services/auth.py
pour le détail du mécanisme.
"""
import logging
import uuid as uuid_lib

import bcrypt
from flask import Blueprint, request, jsonify, render_template, make_response

from config import config
from extensions import limiter
from db.supabase import sb_patch, sb_delete
from services.auth import user_required, get_current_user, csrf_protect
from services.billing import (
    get_balance_for_currency, credit_user_balance, debit_user_balance,
    amount_with_markup, get_subscription_price, ensure_referral_code,
)
from services.soleaspay import soleaspay_convert, soleaspay_collect, get_service_id
from db.supabase import sb_get_eq

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
        return jsonify({'ok': False, 'error': 'Erreur lors de la mise à jour du mot de passe'}), 500
    return jsonify({'ok': True, 'message': 'Mot de passe mis à jour'})


@dashboard_bp.route('/api/account', methods=['DELETE'])
@user_required
@csrf_protect
def api_delete_account():
    ok = sb_delete('users', 'id', request.user_id)
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la suppression du compte'}), 500
    resp = make_response(jsonify({'ok': True}))
    resp.delete_cookie('fp_user_token')
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
    converted = soleaspay_convert(amount_after_fee, from_currency, to_currency)
    try:
        converted = round(float(converted), 2)
    except (TypeError, ValueError):
        converted = 0
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
        return jsonify({'ok': False, 'error': f'Solde insuffisant en {from_currency} (disponible : {available:,.0f} {from_currency})'}), 400

    fee = round(amount * config.CONVERSION_FEE_PERCENT / 100, 2)
    amount_after_fee = round(amount - fee, 2)
    converted_amount = soleaspay_convert(amount_after_fee, from_currency, to_currency)
    try:
        converted_amount = round(float(converted_amount), 2)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'Erreur lors de la conversion. Réessayez.'}), 502

    # Remarque : ces deux opérations ne sont pas atomiques entre elles (voir
    # l'avertissement en tête de services/billing.py). Dans le pire cas, un
    # crash serveur entre les deux lignes ferait perdre le montant débité
    # sans créditer l'autre devise. Risque faible en pratique (fenêtre de
    # quelques millisecondes) mais réel — à corriger avec une fonction
    # Postgres atomique côté Supabase (les deux mouvements dans la même
    # transaction SQL).
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


# ── Abonnement Pro ────────────────────────────────────
@dashboard_bp.route('/api/billing/subscribe', methods=['POST'])
@user_required
@csrf_protect
@limiter.limit('10 per hour')
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
    merchant_currency = next((c['currency'] for c in config.COUNTRIES if c['code'] == user.get('country')), 'XOF')
    xaf_total = soleaspay_convert(total, merchant_currency, 'XAF')

    checkout_ref = 'sub_' + uuid_lib.uuid4().hex[:16]

    collect = soleaspay_collect(
        wallet=phone,
        amount=xaf_total,
        currency='XAF',
        order_id=checkout_ref,
        description='Abonnement Flinpay Pro (mensuel)',
        payer=f"{user.get('firstname', '')} {user.get('lastname', '')}".strip(),
        payer_email=user.get('email', ''),
        success_url='https://www.flinpay.cfd/billing?upgraded=1',
        failure_url='https://www.flinpay.cfd/billing',
        service_id=service_id
    )
    if not collect['ok']:
        return jsonify({'ok': False, 'error': f"Erreur SoleasPay: {collect['detail']}"}), 502

    sb_patch('users', 'id', request.user_id, {'pending_upgrade_checkout_id': checkout_ref})
    return jsonify({'ok': True, 'message': 'Une confirmation de paiement a été envoyée sur votre téléphone.'})


@dashboard_bp.route('/billing')
@user_required
def billing():
    return render_template('billing.html', user=get_current_user())


# ── Parrainage ────────────────────────────────────────
@dashboard_bp.route('/api/referral')
@user_required
def api_referral():
    user = get_current_user()
    code = ensure_referral_code(user)

    referred = sb_get_eq('users', 'referred_by', request.user_id, extra_query='order=created_at.desc')
    referred_list = [{
        'firstname': u.get('firstname', ''),
        'lastname': u.get('lastname', ''),
        'plan': u.get('plan', 'starter'),
        'created_at': u.get('created_at')
    } for u in referred]

    earnings = sb_get_eq('referral_earnings', 'referrer_id', request.user_id, extra_query='order=created_at.desc&limit=50')

    return jsonify({
        'ok': True,
        'referral_code': code,
        'referral_link': f'https://www.flinpay.cfd/register?ref={code}',
        'referred_count': len(referred_list),
        'referred_users': referred_list,
        'balance': user.get('referral_balance', 0),
        'earnings_history': earnings,
        'commission_rate': config.REFERRAL_COMMISSION_RATE
    })


@dashboard_bp.route('/referral')
@user_required
def referral():
    return render_template('referral.html', user=get_current_user())
