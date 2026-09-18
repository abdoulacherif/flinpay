"""
routes/admin/kyc.py — revue des soumissions KYC : consultation des documents
(via URL signée temporaire uniquement, jamais publique), approbation, rejet.
"""
import logging
from datetime import datetime

from flask import Blueprint, jsonify, render_template, request

from db.supabase import sb_get, sb_get_one, sb_patch, sb_storage_sign
from services.auth import admin_required, csrf_protect
from services.audit import log_admin_action

logger = logging.getLogger('flinpay.routes.admin.kyc')

admin_kyc_bp = Blueprint('admin_kyc', __name__)


@admin_kyc_bp.route('/admin/kyc')
@admin_required
def admin_kyc_page():
    pending = sb_get('users', 'kyc_status=eq.pending&order=kyc_submitted_at.asc')
    return render_template('admin_kyc.html', pending=pending)


@admin_kyc_bp.route('/api/admin/kyc/<user_id>/document')
@admin_required
def api_admin_kyc_document(user_id):
    u = sb_get_one('users', 'id', user_id)
    if not u:
        return jsonify({'ok': False, 'error': 'Utilisateur introuvable'}), 404

    urls = {}
    for key, path_field in [
        ('front', 'kyc_document_front_path'),
        ('back', 'kyc_document_back_path'),
        ('selfie', 'kyc_selfie_path'),
    ]:
        if u.get(path_field):
            # URL signée, valable 1h max (plafonné dans sb_storage_sign lui-même) —
            # jamais d'URL publique permanente pour une pièce d'identité.
            signed = sb_storage_sign('kyc-documents', u[path_field])
            if signed:
                urls[key] = signed
    if not urls:
        return jsonify({'ok': False, 'error': 'Aucun document trouvé'}), 404

    # La consultation d'une pièce d'identité est une action sensible même en
    # lecture seule : elle est tracée.
    log_admin_action('kyc_document_view', {'target_user_id': user_id})
    return jsonify({'ok': True, 'urls': urls})


@admin_kyc_bp.route('/api/admin/kyc/<user_id>/approve', methods=['POST'])
@admin_required
@csrf_protect
def api_admin_kyc_approve(user_id):
    ok = sb_patch('users', 'id', user_id, {
        'kyc_status': 'verified',
        'kyc_reviewed_at': datetime.utcnow().isoformat(),
        'kyc_rejection_reason': None
    })
    if ok:
        log_admin_action('kyc_approve', {'target_user_id': user_id})
    return jsonify({'ok': ok})


@admin_kyc_bp.route('/api/admin/kyc/<user_id>/reject', methods=['POST'])
@admin_required
@csrf_protect
def api_admin_kyc_reject(user_id):
    data = request.get_json() or {}
    reason = (data.get('reason') or 'Document invalide ou illisible').strip()[:500]
    ok = sb_patch('users', 'id', user_id, {
        'kyc_status': 'rejected',
        'kyc_reviewed_at': datetime.utcnow().isoformat(),
        'kyc_rejection_reason': reason
    })
    if ok:
        log_admin_action('kyc_reject', {'target_user_id': user_id, 'reason': reason})
    return jsonify({'ok': ok})
