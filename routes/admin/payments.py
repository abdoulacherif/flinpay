"""
routes/admin/payments.py — vue admin des paiements (revenus, marges) et
gestion des transactions individuelles.

RÈGLE DE SÉCURITÉ — édition de transaction restreinte à une liste blanche
-----------------------------------------------------------------------------
`api_admin_update_transaction` acceptait à l'origine N'IMPORTE QUEL champ du
corps JSON, y compris `amount`, `currency` ou `user_id` — un admin (ou un
attaquant ayant compromis une session admin) pouvait donc réécrire librement
le montant ou le bénéficiaire d'une transaction. Seuls `status` et `note`
sont modifiables ici ; et si `status` passe à 'paid'/'failed' depuis
'pending', on repasse par settle_transaction() pour que le crédit du solde,
le rapprochement facture et le webhook marchand restent cohérents avec
n'importe quel autre chemin qui change ce statut (voir
services/transactions.py).
"""
import logging
from datetime import datetime

from flask import Blueprint, request, jsonify, render_template

from db.supabase import sb_get, sb_get_one, sb_patch_if_pending, sb_delete_multi
from services.auth import admin_required, get_current_user, csrf_protect
from services.transactions import settle_transaction
from services.audit import log_admin_action

logger = logging.getLogger('flinpay.routes.admin.payments')

admin_payments_bp = Blueprint('admin_payments', __name__)

_EDITABLE_TX_FIELDS = {'status', 'note'}
_VALID_TX_STATUSES = {'pending', 'paid', 'failed'}


@admin_payments_bp.route('/admin/payments')
@admin_required
def admin_payments_page():
    return render_template('admin_payments.html', user=get_current_user())


@admin_payments_bp.route('/api/admin/payments', methods=['GET'])
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
            'merchant_name': f"{merchant.get('firstname', '')} {merchant.get('lastname', '')}".strip(),
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


@admin_payments_bp.route('/api/admin/transactions', methods=['GET'])
@admin_required
def api_admin_get_transactions():
    return jsonify({'ok': True, 'items': sb_get('transactions', 'order=created_at.desc&limit=500')})


@admin_payments_bp.route('/api/admin/transactions/<token>', methods=['PUT'])
@admin_required
@csrf_protect
def api_admin_update_transaction(token):
    data = request.get_json() or {}
    data = {k: v for k, v in data.items() if k in _EDITABLE_TX_FIELDS}
    if 'status' in data and data['status'] not in _VALID_TX_STATUSES:
        return jsonify({'ok': False, 'error': 'Statut invalide'}), 400
    if not data:
        return jsonify({'ok': False, 'error': 'Aucun champ modifiable dans la requête'}), 400

    tx = sb_get_one('transactions', 'token', token)
    if not tx:
        return jsonify({'ok': False, 'error': 'Introuvable'}), 404

    new_status = data.get('status')
    if new_status and new_status != tx.get('status') and tx.get('status') == 'pending':
        # Transition surveillée par un humain (admin) mais toujours atomique
        # et suivie des mêmes effets de bord que n'importe quel autre chemin.
        update = dict(data)
        if new_status == 'paid':
            update['paid_at'] = datetime.utcnow().isoformat()
        if sb_patch_if_pending('transactions', 'token', token, update):
            settle_transaction(tx, new_status)
            log_admin_action('transaction_force_status', {'token': token, 'new_status': new_status})
            return jsonify({'ok': True})
        return jsonify({'ok': False, 'error': 'La transaction a changé de statut entre-temps'}), 409

    from db.supabase import sb_patch_multi
    ok = sb_patch_multi('transactions', {'token': token}, data)
    if ok:
        log_admin_action('transaction_update', {'token': token, 'fields': list(data.keys())})
    return jsonify({'ok': ok})


@admin_payments_bp.route('/api/admin/transactions/<token>', methods=['DELETE'])
@admin_required
@csrf_protect
def api_admin_delete_transaction(token):
    ok = sb_delete_multi('transactions', {'token': token})
    if ok:
        log_admin_action('transaction_delete', {'token': token})
    return jsonify({'ok': ok})
