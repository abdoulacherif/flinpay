import logging
from datetime import datetime
import hashlib

from flask import Blueprint, request, jsonify, render_template

from extensions import limiter
from db.supabase import sb_patch, sb_storage_upload, sb_get_eq
from services.auth import user_required, get_current_user, csrf_protect

logger = logging.getLogger('flinpay.routes.kyc')

kyc_bp = Blueprint('kyc', __name__)

ALLOWED_ID_TYPES = {'national_id', 'passport', 'driver_license'}

@kyc_bp.route('/kyc')
@user_required
def kyc_page():
    return render_template('kyc.html', user=get_current_user())

def _upload_kyc_file(file, allowed_ext, max_bytes, subfolder):
    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in allowed_ext:
        return None, f'Format non supporté pour {subfolder}'
    
    file_bytes = file.read()
    if len(file_bytes) > max_bytes:
        return None, f'Fichier {subfolder} trop volumineux (max {max_bytes // (1024*1024)} Mo)'
    if not file_bytes:
        return None, f'Fichier {subfolder} vide'
        
    path = f"{request.user_id}/{subfolder}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.{ext}"
    uploaded = sb_storage_upload('kyc-documents', path, file_bytes, file.mimetype or 'application/octet-stream')
    if not uploaded['ok']:
        return None, f"Erreur upload {subfolder}"
    return path, None

@kyc_bp.route('/api/kyc/submit', methods=['POST'])
@user_required
@csrf_protect
@limiter.limit('3 per hour')
def api_kyc_submit():
    full_name = (request.form.get('full_name') or '').strip()[:200]
    id_type = (request.form.get('id_type') or '').strip()
    id_number = (request.form.get('id_number') or '').strip()[:60]
    
    file_front = request.files.get('document_front')
    file_back = request.files.get('document_back')
    file_selfie = request.files.get('selfie')

    if id_type not in ALLOWED_ID_TYPES:
        return jsonify({'ok': False, 'error': "Type de document invalide"}), 400

    if not full_name or not id_number \
            or not file_front or not file_front.filename \
            or not file_back or not file_back.filename \
            or not file_selfie or not file_selfie.filename:
        return jsonify({'ok': False, 'error': 'Tous les champs sont requis'}), 400

    # Anti-fraude : vérifier que ce numéro de pièce n'est pas déjà utilisé par un autre compte
    id_hash = hashlib.sha256(id_number.encode()).hexdigest()
    existing = sb_get_eq('users', 'kyc_id_number_hash', id_hash)
    if existing and existing[0]['id'] != request.user_id:
        return jsonify({'ok': False, 'error': "Ce numéro de pièce d'identité est déjà enregistré sur un autre compte"}), 409

    front_path, err = _upload_kyc_file(file_front, ('jpg', 'jpeg', 'png', 'pdf'), 8 * 1024 * 1024, 'recto')
    if err: return jsonify({'ok': False, 'error': err}), 400

    back_path, err = _upload_kyc_file(file_back, ('jpg', 'jpeg', 'png', 'pdf'), 8 * 1024 * 1024, 'verso')
    if err: return jsonify({'ok': False, 'error': err}), 400

    selfie_path, err = _upload_kyc_file(file_selfie, ('jpg', 'jpeg', 'png'), 8 * 1024 * 1024, 'selfie')
    if err: return jsonify({'ok': False, 'error': err}), 400

    updated = sb_patch('users', 'id', request.user_id, {
        'kyc_status': 'pending',
        'kyc_full_name': full_name,
        'kyc_id_type': id_type,
        'kyc_id_number_hash': id_hash, # On stocke le hash, pas le numéro en clair
        'kyc_document_front_path': front_path,
        'kyc_document_back_path': back_path,
        'kyc_selfie_path': selfie_path,
        'kyc_submitted_at': datetime.utcnow().isoformat(),
        'kyc_rejection_reason': None
    })
    if not updated:
        return jsonify({'ok': False, 'error': 'Erreur lors de la mise à jour'}), 500
    return jsonify({'ok': True, 'message': 'Documents envoyés. Vérification sous 24-48h.'})