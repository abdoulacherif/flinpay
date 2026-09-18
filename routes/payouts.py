"""
routes/payouts.py — demandes de retrait (le marchand retire son solde vers son
propre mobile money). Toutes les routes qui créent/annulent un retrait sont
protégées par @csrf_protect : c'est un mouvement d'argent direct.
"""
import logging
from datetime import datetime

from flask import Blueprint, request, jsonify, render_template

from config import config
from extensions import limiter
from db.supabase import sb_get_eq, sb_post, sb_delete_multi
from services.auth import user_required, get_current_user, csrf_protect
from services.billing import (
    get_currency_for_country, get_balances, get_balance_for_currency,
    credit_user_balance, debit_user_balance,
)

logger = logging.getLogger('flinpay.routes.payouts')

payouts_bp = Blueprint('payouts', __name__)


@payouts_bp.route('/payouts')
@user_required
def payouts_page():
    return render_template('payouts.html', user=get_current_user())


@payouts_bp.route('/api/payouts/mine', methods=['GET'])
@user_required
def api_my_payouts():
    payouts = sb_get_eq('payouts', 'user_id', request.user_id, extra_query='order=created_at.desc')
    return jsonify({'ok': True, 'payouts': payouts})


@payouts_bp.route('/api/payouts/mine', methods=['POST'])
@user_required
@csrf_protect
@limiter.limit('10 per hour')
def api_request_payout():
    user = get_current_user()
    if user.get('kyc_status') != 'verified':
        return jsonify({'ok': False, 'error': 'Vérifiez votre identité avant de demander un retrait'}), 403

    data = request.get_json() or {}
    try:
        amount = float(data.get('amount'))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'Montant invalide'}), 400
    phone = (data.get('phone') or '').strip()[:30]
    if amount <= 0 or not phone:
        return jsonify({'ok': False, 'error': 'Montant et numéro de téléphone requis'}), 400
    if amount < config.PAYOUT_MIN_AMOUNT:
        return jsonify({'ok': False, 'error': f'Le montant minimum de retrait est de {config.PAYOUT_MIN_AMOUNT} (dans la devise choisie)'}), 400

    # Le pays choisi pour le retrait détermine la devise dans laquelle le
    # mobile money sera crédité. On ne retire que depuis la poche de solde
    # correspondante, pour ne jamais subir de conversion imposée par
    # SoleasPay au moment du retrait.
    withdraw_country = (data.get('country') or user.get('country') or '').strip()
    if withdraw_country not in {c['code'] for c in config.COUNTRIES}:
        return jsonify({'ok': False, 'error': 'Pays invalide'}), 400
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

    fee = round(amount * config.PAYOUT_FEE_PERCENT / 100, 2)
    net_amount = round(amount - fee, 2)

    row = sb_post('payouts', {
        'user_id': request.user_id, 'amount': amount, 'fee': fee, 'net_amount': net_amount,
        'currency': withdraw_currency, 'phone': phone,
        'operator': (data.get('operator') or '').strip()[:30], 'country': withdraw_country,
        'status': 'pending', 'note': (data.get('note') or '').strip()[:500],
        'created_at': datetime.utcnow().isoformat()
    })
    if not row or (isinstance(row, dict) and row.get('_error')):
        return jsonify({'ok': False, 'error': 'Erreur lors de la demande de retrait'}), 500

    debit_user_balance(request.user_id, withdraw_currency, amount)
    return jsonify({'ok': True, 'payout': row[0] if isinstance(row, list) else row})


@payouts_bp.route('/api/payouts/mine/<int:pid>', methods=['DELETE'])
@user_required
@csrf_protect
def api_cancel_payout(pid):
    matches = sb_get_eq('payouts', 'id', pid, extra_query=f'user_id=eq.{request.user_id}')
    if not matches:
        return jsonify({'ok': False, 'error': 'Introuvable'}), 404
    payout = matches[0]
    if payout['status'] != 'pending':
        return jsonify({'ok': False, 'error': 'Seuls les retraits en attente peuvent être annulés'}), 400

    ok = sb_delete_multi('payouts', {'id': pid, 'user_id': request.user_id})
    if not ok:
        return jsonify({'ok': False, 'error': "Erreur lors de l'annulation"}), 500

    refund_currency = payout.get('currency') or get_currency_for_country(payout.get('country', ''))
    credit_user_balance(request.user_id, refund_currency, payout['amount'])
    return jsonify({'ok': True})
