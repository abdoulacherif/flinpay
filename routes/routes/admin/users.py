"""
routes/admin/users.py — vue et gestion admin de tous les marchands.

RÈGLE DE SÉCURITÉ — le mot de passe ne sort JAMAIS de la base
-----------------------------------------------------------------
`password_hash` est systématiquement retiré de toute réponse JSON, même pour
un admin. Un admin légitime n'a aucune raison de voir un hash de mot de passe
(même bcrypt, donc non réversible), et si un compte admin est un jour
compromis, ça limite ce qu'un attaquant peut en extraire.

RÈGLE DE SÉCURITÉ — champs non modifiables via l'édition générique
-----------------------------------------------------------------------
`api_admin_update_user` acceptait à l'origine N'IMPORTE QUEL champ envoyé
dans le corps JSON (seuls `id` et `password_hash` étaient retirés), y compris
`totp_secret`, `email_verify_token`, ou `balances`. Un admin qui a besoin de
changer un solde doit passer par un vrai mouvement de retrait/crédit tracé
(routes/admin/payouts.py), pas par une écriture arbitraire sans trace
financière claire. `_BLOCKED_USER_FIELDS` referme cette porte.
"""
import logging
from datetime import datetime

from flask import Blueprint, request, jsonify, render_template

from db.supabase import sb_get, sb_get_eq, sb_get_one, sb_patch, sb_delete, sb_count, sb_storage_public_url
from services.auth import admin_required, get_current_user, csrf_protect
from services.billing import get_balances
from services.audit import log_admin_action

logger = logging.getLogger('flinpay.routes.admin.users')

admin_users_bp = Blueprint('admin_users', __name__)

_BLOCKED_USER_FIELDS = {
    'id', 'password_hash', 'totp_secret', 'totp_enabled',
    'email_verify_token', 'balances', 'failed_login_count', 'locked_until',
}


def _strip_sensitive(user: dict) -> dict:
    return {k: v for k, v in user.items() if k != 'password_hash'}


def _is_user_online(last_seen_at, now=None) -> bool:
    if not last_seen_at:
        return False
    now = now or datetime.utcnow()
    try:
        last_seen = datetime.fromisoformat(last_seen_at.replace('Z', '+00:00')).replace(tzinfo=None)
        return (now - last_seen).total_seconds() < 120
    except (ValueError, AttributeError):
        return False


@admin_users_bp.route('/api/admin/users', methods=['GET'])
@admin_required
def api_admin_get_users():
    users = sb_get('users', 'order=created_at.desc&limit=500')
    now = datetime.utcnow()
    safe = []
    for u in users:
        u2 = _strip_sensitive(u)
        u2['is_online'] = _is_user_online(u.get('last_seen_at'), now)
        balances = get_balances(u)
        u2['total_balance'] = sum(balances.values()) if balances else u.get('available_balance', 0)
        safe.append(u2)
    return jsonify({'ok': True, 'items': safe})


@admin_users_bp.route('/admin/users/<user_id>')
@admin_required
def admin_user_detail_page(user_id):
    return render_template('admin_user_detail.html', user=get_current_user(), target_user_id=user_id)


@admin_users_bp.route('/api/admin/users/<user_id>/full', methods=['GET'])
@admin_required
def api_admin_get_user_full(user_id):
    target_raw = sb_get_one('users', 'id', user_id)
    if not target_raw:
        return jsonify({'ok': False, 'error': 'Utilisateur introuvable'}), 404
    target = _strip_sensitive(target_raw)
    target['is_online'] = _is_user_online(target.get('last_seen_at'))
    balances = get_balances(target)
    target['total_balance'] = sum(balances.values()) if balances else target.get('available_balance', 0)

    payment_links = sb_get_eq('payment_links', 'user_id', user_id, extra_query='order=created_at.desc')
    for l in payment_links:
        if l.get('image_path'):
            l['image_url'] = sb_storage_public_url('payment-link-images', l['image_path'])

    invoices = sb_get_eq('invoices', 'user_id', user_id, extra_query='order=created_at.desc')

    api_keys = sb_get_eq('api_keys', 'user_id', user_id, extra_query='order=created_at.desc')
    safe_keys = [{
        'id': k['id'], 'key_prefix': k['key_prefix'], 'environment': k.get('environment', 'live'),
        'label': k.get('label') or '', 'active': k.get('active', True),
        'created_at': k.get('created_at'), 'last_used_at': k.get('last_used_at')
    } for k in api_keys]

    webhooks = sb_get_eq('webhooks', 'user_id', user_id, extra_query='order=created_at.desc')
    transactions = sb_get_eq('transactions', 'user_id', user_id, extra_query='order=created_at.desc&limit=100')
    payouts = sb_get_eq('payouts', 'user_id', user_id, extra_query='order=created_at.desc')
    referred_users = sb_get_eq('users', 'referred_by', user_id, extra_query='order=created_at.desc')
    referred_safe = [{'firstname': u.get('firstname'), 'lastname': u.get('lastname'),
                       'email': u.get('email'), 'plan': u.get('plan'), 'created_at': u.get('created_at')} for u in referred_users]

    # Consultation du détail complet d'un compte marchand (données personnelles
    # + financières) : tracé dans le journal d'audit, même en lecture seule.
    log_admin_action('user_view_full', {'target_user_id': user_id})

    return jsonify({
        'ok': True, 'user': target, 'payment_links': payment_links, 'invoices': invoices,
        'api_keys': safe_keys, 'webhooks': webhooks, 'transactions': transactions,
        'payouts': payouts, 'referred_users': referred_safe
    })


@admin_users_bp.route('/api/admin/users/<user_id>', methods=['PUT'])
@admin_required
@csrf_protect
def api_admin_update_user(user_id):
    data = request.get_json() or {}
    data = {k: v for k, v in data.items() if k not in _BLOCKED_USER_FIELDS}
    if not data:
        return jsonify({'ok': False, 'error': 'Aucun champ modifiable dans la requête'}), 400
    ok = sb_patch('users', 'id', user_id, data)
    if ok:
        log_admin_action('user_update', {'target_user_id': user_id, 'fields': list(data.keys())})
    return jsonify({'ok': ok})


@admin_users_bp.route('/api/admin/users/<user_id>', methods=['DELETE'])
@admin_required
@csrf_protect
def api_admin_delete_user(user_id):
    ok = sb_delete('users', 'id', user_id)
    if ok:
        log_admin_action('user_delete', {'target_user_id': user_id})
    return jsonify({'ok': ok})


@admin_users_bp.route('/api/admin/overview')
@admin_required
def api_admin_overview():
    return jsonify({
        'ok': True,
        'users': sb_count('users'),
        'transactions': sb_count('transactions'),
        'pending_kyc': sb_count('users', 'kyc_status=eq.pending'),
        'payment_links': sb_count('payment_links')
    })
