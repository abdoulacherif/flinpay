"""
routes/admin/config.py — édition du contenu affiché sur la page d'accueil
publique (statistiques, fonctionnalités, plans tarifaires, témoignages) et de
la configuration générale du site (site_config).

Risque plus faible que les routes financières (pas de mouvement d'argent),
mais ça reste une surface d'écriture accessible uniquement aux admins : CSRF
et audit logging appliqués partout par cohérence, et parce qu'un
témoignage/texte modifié à l'insu de tous peut servir à une attaque de
défacement ou d'ingénierie sociale (ex: changer le texte d'un plan tarifaire
pour tromper des clients).
"""
import logging

from flask import Blueprint, request, jsonify

from db.supabase import sb_get, sb_post, sb_patch, sb_delete
from services.auth import admin_required, csrf_protect
from services.audit import log_admin_action

logger = logging.getLogger('flinpay.routes.admin.config')

admin_config_bp = Blueprint('admin_config', __name__)


def _crud_routes(bp, table, endpoint_prefix, url_segment):
    """Génère les 4 routes GET/POST/PUT/DELETE identiques pour une table de
    contenu (stats, features, pricing_plans, testimonials). Évite de
    dupliquer 4 fois un code strictement identique à part le nom de table."""

    @bp.route(f'/api/admin/{url_segment}', methods=['GET'], endpoint=f'{endpoint_prefix}_list')
    @admin_required
    def _list():
        return jsonify({'ok': True, 'items': sb_get(table, 'order=order_index.asc')})

    @bp.route(f'/api/admin/{url_segment}', methods=['POST'], endpoint=f'{endpoint_prefix}_create')
    @admin_required
    @csrf_protect
    def _create():
        body = request.get_json() or {}
        row = sb_post(table, body)
        if not row or (isinstance(row, dict) and row.get('_error')):
            return jsonify({'ok': False, 'error': 'Erreur lors de la création'}), 500
        log_admin_action(f'{table}_create', {'fields': list(body.keys())})
        return jsonify({'ok': True, 'item': row[0] if isinstance(row, list) else row})

    @bp.route(f'/api/admin/{url_segment}/<int:item_id>', methods=['PUT'], endpoint=f'{endpoint_prefix}_update')
    @admin_required
    @csrf_protect
    def _update(item_id):
        body = request.get_json() or {}
        ok = sb_patch(table, 'id', item_id, body)
        if ok:
            log_admin_action(f'{table}_update', {'id': item_id, 'fields': list(body.keys())})
        return jsonify({'ok': ok})

    @bp.route(f'/api/admin/{url_segment}/<int:item_id>', methods=['DELETE'], endpoint=f'{endpoint_prefix}_delete')
    @admin_required
    @csrf_protect
    def _delete(item_id):
        ok = sb_delete(table, 'id', item_id)
        if ok:
            log_admin_action(f'{table}_delete', {'id': item_id})
        return jsonify({'ok': ok})


_crud_routes(admin_config_bp, 'stats', 'admin_stats', 'stats')
_crud_routes(admin_config_bp, 'features', 'admin_features', 'features')
_crud_routes(admin_config_bp, 'pricing_plans', 'admin_pricing', 'pricing')
_crud_routes(admin_config_bp, 'testimonials', 'admin_testimonials', 'testimonials')


# ── site_config (clé/valeur libre) ───────────────────
@admin_config_bp.route('/api/admin/config', methods=['GET'])
@admin_required
def api_get_config():
    return jsonify({'ok': True, 'items': sb_get('site_config')})


@admin_config_bp.route('/api/admin/config', methods=['PUT'])
@admin_required
@csrf_protect
def api_update_config():
    from datetime import datetime
    body = request.get_json() or {}
    key = body.get('key')
    if not key:
        return jsonify({'ok': False, 'error': 'Clé de configuration requise'}), 400
    ok = sb_patch('site_config', 'key', key, {'value': body.get('value'), 'updated_at': datetime.utcnow().isoformat()})
    if ok:
        log_admin_action('site_config_update', {'key': key})
    return jsonify({'ok': ok})
