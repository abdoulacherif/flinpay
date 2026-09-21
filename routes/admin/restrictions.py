"""
routes/admin/restrictions.py — pilotage anti-fraude : les 3 niveaux de
restriction (no_withdrawal / no_login / banned), les blocages pays/opérateur
ciblés, et la consultation de l'historique complet d'un marchand (transactions
+ activité) — pensée pour être exportable si une autorité en fait la demande.

Voir services/restrictions.py pour la logique métier et services/activity_log.py
pour le journal d'activité.
"""
import logging

from flask import Blueprint, request, jsonify

from db.supabase import sb_get_one, sb_get_eq
from services.auth import admin_required, csrf_protect
from services.audit import log_admin_action
from services.activity_log import get_user_activity
from services.billing import get_balances
from services.restrictions import (
    LEVELS, set_restriction_level, clear_restriction,
    set_country_restrictions, set_operator_restrictions_bulk,
    get_effective_level,
)

logger = logging.getLogger('flinpay.routes.admin.restrictions')

admin_restrictions_bp = Blueprint('admin_restrictions', __name__)


@admin_restrictions_bp.route('/api/admin/users/<user_id>/restriction', methods=['PUT'])
@admin_required
@csrf_protect
def api_set_user_restriction(user_id):
    data = request.get_json() or {}
    level = data.get('level')
    if level not in LEVELS:
        return jsonify({'ok': False, 'error': f"Niveau invalide. Attendu: {', '.join(LEVELS)}"}), 400

    reason = (data.get('reason') or '').strip()
    if level != 'none' and not reason:
        return jsonify({'ok': False, 'error': 'Un motif est requis pour appliquer une restriction'}), 400

    duration_hours = None
    if level == 'no_withdrawal' and data.get('duration_hours'):
        try:
            duration_hours = int(data['duration_hours'])
            if duration_hours <= 0:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({'ok': False, 'error': 'Durée invalide'}), 400

    if level == 'none':
        ok = clear_restriction(user_id)
    else:
        ok = set_restriction_level(user_id, level, reason=reason, duration_hours=duration_hours)

    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la mise à jour de la restriction'}), 500
    return jsonify({'ok': True})


@admin_restrictions_bp.route('/api/admin/users/<user_id>/country-restrictions', methods=['PUT'])
@admin_required
@csrf_protect
def api_set_country_restrictions(user_id):
    data = request.get_json() or {}
    countries = data.get('countries')
    if not isinstance(countries, list):
        return jsonify({'ok': False, 'error': 'Liste de pays invalide'}), 400
    ok = set_country_restrictions(user_id, countries)
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la mise à jour'}), 500
    return jsonify({'ok': True})


@admin_restrictions_bp.route('/api/admin/users/operator-restrictions', methods=['POST'])
@admin_required
@csrf_protect
def api_bulk_operator_restrictions():
    """Bloque (ou débloque) un ou plusieurs opérateurs pour un ou plusieurs
    marchands en une seule action — utile quand la fraude détectée suit un
    pattern par réseau plutôt que par compte isolé."""
    data = request.get_json() or {}
    user_ids = data.get('user_ids')
    operators = data.get('operators')
    blocked = bool(data.get('blocked', True))
    if not isinstance(user_ids, list) or not user_ids:
        return jsonify({'ok': False, 'error': 'Au moins un utilisateur requis'}), 400
    if not isinstance(operators, list) or not operators:
        return jsonify({'ok': False, 'error': 'Au moins un opérateur requis'}), 400

    results = set_operator_restrictions_bulk(user_ids, operators, blocked)
    failed = [uid for uid, ok in results.items() if not ok]
    if failed:
        return jsonify({'ok': False, 'error': f"Échec pour {len(failed)} utilisateur(s)", 'failed': failed}), 207
    return jsonify({'ok': True, 'updated': len(results)})


@admin_restrictions_bp.route('/api/admin/users/<user_id>/activity', methods=['GET'])
@admin_required
def api_user_activity(user_id):
    """Historique complet d'un marchand : profil + restrictions actuelles +
    activité (connexions, paiements, retraits...) — tout ce qu'il faut pour
    instruire un dossier de fraude ou répondre à une demande officielle."""
    user = sb_get_one('users', 'id', user_id)
    if not user:
        return jsonify({'ok': False, 'error': 'Utilisateur introuvable'}), 404

    activity = get_user_activity(user_id, limit=500)
    payouts = sb_get_eq('payouts', 'user_id', user_id, extra_query='order=created_at.desc')
    transactions = sb_get_eq('transactions', 'user_id', user_id, extra_query='order=created_at.desc&limit=200')

    log_admin_action('user_activity_view', {'target_user_id': user_id})

    return jsonify({
        'ok': True,
        'user': {
            'id': user['id'], 'firstname': user.get('firstname'), 'lastname': user.get('lastname'),
            'email': user.get('email'), 'country': user.get('country'),
            'restriction_level': get_effective_level(user),
            'restriction_reason': user.get('restriction_reason'),
            'restriction_expires_at': user.get('restriction_expires_at'),
            'restricted_countries': user.get('restricted_countries') or [],
            'restricted_operators': user.get('restricted_operators') or [],
            'balances': get_balances(user),
            'kyc_status': user.get('kyc_status'),
            'created_at': user.get('created_at'),
        },
        'activity': activity,
        'payouts': payouts,
        'transactions': transactions,
    })
