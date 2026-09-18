"""
routes/admin/audit.py — consultation du journal d'audit (qui a fait quoi,
quand, depuis quelle IP). C'est la route qui permet de détecter après coup un
usage abusif d'un compte admin — voir services/audit.py.
"""
import logging

from flask import Blueprint, render_template, jsonify

from db.supabase import sb_get
from services.auth import admin_required, get_current_user

logger = logging.getLogger('flinpay.routes.admin.audit')

admin_audit_bp = Blueprint('admin_audit', __name__)


@admin_audit_bp.route('/admin/audit-log')
@admin_required
def admin_audit_log_page():
    return render_template('admin_audit_log.html', user=get_current_user())


@admin_audit_bp.route('/api/admin/audit-log', methods=['GET'])
@admin_required
def api_admin_audit_log():
    logs = sb_get('admin_audit_log', 'order=created_at.desc&limit=300')
    all_users = sb_get('users', 'limit=1000')
    users_map = {u['id']: u for u in all_users}
    items = []
    for l in logs:
        admin = users_map.get(l.get('admin_id'), {})
        items.append({
            'id': l.get('id'),
            'admin_name': f"{admin.get('firstname', '')} {admin.get('lastname', '')}".strip() or 'Inconnu',
            'admin_email': admin.get('email'),
            'action': l.get('action'),
            'details': l.get('details'),
            'ip_address': l.get('ip_address'),
            'created_at': l.get('created_at')
        })
    return jsonify({'ok': True, 'items': items})
