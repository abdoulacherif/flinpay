"""
routes/admin/payouts.py — création manuelle de retraits, changement de statut
(paiement effectué / échoué), avec remboursement automatique en cas d'échec.
"""
import logging
from datetime import datetime

from flask import Blueprint, request, jsonify

from config import config
from db.supabase import sb_get, sb_get_eq, sb_patch, sb_delete
from services.auth import admin_required, csrf_protect
from services.billing import (
    get_user_by_id, get_currency_for_country, get_balances,
    get_balance_for_currency, credit_user_balance, debit_user_balance,
)
from services.audit import log_admin_action

logger = logging.getLogger('flinpay.routes.admin.payouts')

admin_payouts_bp = Blueprint('admin_payouts', __name__)


@admin_payouts_bp.route('/api/admin/payouts', methods=['GET'])
@admin_required
def api_admin_get_payouts():
    return jsonify({'ok': True, 'items': sb_get('payouts', 'order=created_at.desc')})


@admin_payouts_bp.route('/api/admin/payouts', methods=['POST'])
@admin_required
@csrf_protect
def api_admin_create_payout():
    data = request.get_json() or {}
    if not data.get('user_id') or not data.get('amount') or not data.get('phone'):
        return jsonify({'ok': False, 'error': 'user_id, amount et phone sont requis'}), 400
    target_user_id = data.get('user_id')
    try:
        amount = float(data.get('amount'))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'Montant invalide'}), 400
    if amount <= 0:
        return jsonify({'ok': False, 'error': 'Montant invalide'}), 400

    target_user = get_user_by_id(target_user_id)
    if not target_user:
        return jsonify({'ok': False, 'error': 'Marchand introuvable'}), 404

    withdraw_country = (data.get('country') or target_user.get('country') or '').strip()
    withdraw_currency = get_currency_for_country(withdraw_country)
    available_in_currency = get_balance_for_currency(target_user, withdraw_currency)

    force = bool(data.get('force'))
    if amount > available_in_currency and not force:
        balances = get_balances(target_user)
        other_currencies = {c: v for c, v in balances.items() if c != withdraw_currency and v and v > 0}
        other_desc = (', '.join(f'{v:,.0f} {c}' for c, v in other_currencies.items())
                      if other_currencies else 'aucun autre solde')
        return jsonify({
            'ok': False,
            'error': (f"Solde insuffisant en {withdraw_currency} pour ce marchand "
                      f"(disponible : {available_in_currency:,.0f} {withdraw_currency} — "
                      f"autres devises : {other_desc}). Repassez la requête avec "
                      f"'force': true pour outrepasser sciemment cette vérification.")
        }), 400

    fee = round(amount * config.PAYOUT_FEE_PERCENT / 100, 2)
    net_amount = round(amount - fee, 2)

    payload = {
        'user_id': target_user_id, 'amount': amount, 'fee': fee, 'net_amount': net_amount,
        'currency': withdraw_currency, 'phone': data.get('phone'),
        'operator': data.get('operator', ''), 'country': withdraw_country,
        'status': data.get('status', 'pending'), 'note': (data.get('note') or '')[:500],
        'created_at': datetime.utcnow().isoformat()
    }
    from db.supabase import sb_post
    row = sb_post('payouts', payload)
    if not row or (isinstance(row, dict) and row.get('_error')):
        return jsonify({'ok': False, 'error': 'Erreur lors de la création du retrait'}), 500

    debit_user_balance(target_user_id, withdraw_currency, amount)
    # `force` est explicitement inclus dans le log : un retrait forcé au-delà
    # du solde disponible doit être visible immédiatement dans l'audit.
    log_admin_action('payout_create', {
        'target_user_id': target_user_id, 'amount': amount, 'currency': withdraw_currency, 'forced': force
    })
    return jsonify({'ok': True, 'item': row[0] if isinstance(row, list) else row})


@admin_payouts_bp.route('/api/admin/payouts/<int:pid>', methods=['PUT'])
@admin_required
@csrf_protect
def api_admin_update_payout(pid):
    data = request.get_json() or {}
    allowed_status = {'pending', 'paid', 'failed'}
    if 'status' in data and data['status'] not in allowed_status:
        return jsonify({'ok': False, 'error': 'Statut invalide'}), 400

    matches = sb_get_eq('payouts', 'id', pid)
    if not matches:
        return jsonify({'ok': False, 'error': 'Introuvable'}), 404
    payout = matches[0]

    update = {k: v for k, v in data.items() if k in {'status', 'note', 'phone', 'operator'}}
    ok = sb_patch('payouts', 'id', pid, update)

    if update.get('status') == 'failed' and payout.get('status') != 'failed':
        # Le remboursement va dans la bonne poche de devise (celle qui avait
        # été débitée), jamais dans un champ de solde global obsolète.
        refund_currency = payout.get('currency') or get_currency_for_country(payout.get('country', ''))
        credit_user_balance(payout['user_id'], refund_currency, payout['amount'])
    elif update.get('status') == 'paid' and not payout.get('processed_at'):
        sb_patch('payouts', 'id', pid, {'processed_at': datetime.utcnow().isoformat()})

    if ok:
        log_admin_action('payout_update', {'payout_id': pid, 'changes': update})
    return jsonify({'ok': ok})


@admin_payouts_bp.route('/api/admin/payouts/<int:pid>', methods=['DELETE'])
@admin_required
@csrf_protect
def api_admin_delete_payout(pid):
    ok = sb_delete('payouts', 'id', pid)
    if ok:
        log_admin_action('payout_delete', {'payout_id': pid})
    return jsonify({'ok': ok})
