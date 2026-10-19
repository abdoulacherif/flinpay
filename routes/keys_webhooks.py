import logging
from datetime import datetime

from flask import Blueprint, request, jsonify, render_template

from extensions import limiter
from db.supabase import sb_get_eq, sb_post, sb_delete_multi
from services.auth import user_required, get_current_user, csrf_protect, generate_api_key
from services.webhooks import test_merchant_webhook, is_safe_webhook_url

logger = logging.getLogger('flinpay.routes.keys_webhooks')

keys_webhooks_bp = Blueprint('keys_webhooks', __name__)

@keys_webhooks_bp.route('/api-keys')
@user_required
def api_keys_page():
    return render_template('api_keys.html', user=get_current_user())

@keys_webhooks_bp.route('/api/keys', methods=['GET'])
@user_required
def api_list_keys():
    keys = sb_get_eq('api_keys', 'user_id', request.user_id, extra_query='order=created_at.desc')
    safe = [{
        'id': k['id'], 'key_prefix': k['key_prefix'], 'environment': k.get('environment', 'live'),
        'label': k.get('label') or '', 'active': k.get('active', True),
        'created_at': k.get('created_at'), 'last_used_at': k.get('last_used_at')
    } for k in keys]
    return jsonify({'ok': True, 'keys': safe})

@keys_webhooks_bp.route('/api/keys', methods=['POST'])
@user_required
@csrf_protect
def api_create_key():
    user = get_current_user()
    if user.get('kyc_status') != 'verified':
        return jsonify({'ok': False, 'error': "Vérifiez votre identité avant de générer une clé API"}), 403

    data = request.get_json() or {}
    environment = data.get('environment') if data.get('environment') in ('live', 'sandbox') else 'live'
    label = (data.get('label') or '').strip()[:60]

    full_key, key_hash, display_prefix = generate_api_key(environment)
    row = sb_post('api_keys', {
        'user_id': request.user_id, 'key_prefix': display_prefix, 'key_hash': key_hash,
        'environment': environment, 'label': label, 'active': True,
        'created_at': datetime.utcnow().isoformat()
    })
    if not row or (isinstance(row, dict) and row.get('_error')):
        return jsonify({'ok': False, 'error': 'Erreur lors de la création de la clé'}), 500
    return jsonify({'ok': True, 'key': full_key, 'key_prefix': display_prefix, 'environment': environment})

@keys_webhooks_bp.route('/api/keys/<int:key_id>', methods=['DELETE'])
@user_required
@csrf_protect
def api_delete_key(key_id):
    ok = sb_delete_multi('api_keys', {'id': key_id, 'user_id': request.user_id})
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la révocation'}), 500
    return jsonify({'ok': True})

@keys_webhooks_bp.route('/webhooks')
@user_required
def webhooks_page():
    return render_template('webhooks.html', user=get_current_user())

@keys_webhooks_bp.route('/api/webhooks', methods=['GET'])
@user_required
def api_get_webhooks():
    return jsonify({'ok': True, 'webhooks': sb_get_eq('webhooks', 'user_id', request.user_id, extra_query='order=created_at.desc')})

@keys_webhooks_bp.route('/api/webhooks', methods=['POST'])
@user_required
@csrf_protect
def api_create_webhook():
    data = request.get_json() or {}
    url = (data.get('url') or '').strip()
    if not url or not url.startswith('https://'):
        return jsonify({'ok': False, 'error': 'URL HTTPS requise'}), 400
    
    if not is_safe_webhook_url(url):
        return jsonify({'ok': False, 'error': "URL non autorisée (interdiction de pointer vers un réseau interne)"}), 400

    events = data.get('events') or []
    if not isinstance(events, list) or len(events) > 2:
        return jsonify({'ok': False, 'error': 'Maximum 2 événements'}), 400
        
    allowed_events = {'payment.success', 'payment.failed'}
    events = [e for e in events if e in allowed_events]
    if not events:
        return jsonify({'ok': False, 'error': 'Événement(s) invalide(s)'}), 400

    row = sb_post('webhooks', {
        'user_id': request.user_id, 'url': url,
        'description': (data.get('description') or '').strip()[:300],
        'events': events, 'active': True, 'created_at': datetime.utcnow().isoformat()
    })
    if not row or (isinstance(row, dict) and row.get('_error')):
        return jsonify({'ok': False, 'error': 'Erreur lors de la création du webhook'}), 500
    return jsonify({'ok': True, 'webhook': row[0] if isinstance(row, list) else row})

@keys_webhooks_bp.route('/api/webhooks/<int:wid>', methods=['DELETE'])
@user_required
@csrf_protect
def api_delete_webhook(wid):
    ok = sb_delete_multi('webhooks', {'id': wid, 'user_id': request.user_id})
    return jsonify({'ok': ok})

@keys_webhooks_bp.route('/api/webhooks/<int:wid>/test', methods=['POST'])
@user_required
@csrf_protect
@limiter.limit('5 per hour')
def api_test_webhook(wid):
    matches = sb_get_eq('webhooks', 'id', wid, extra_query=f'user_id=eq.{request.user_id}')
    if not matches:
        return jsonify({'ok': False, 'error': 'Introuvable'}), 404
        
    url = matches[0]['url']
    if not is_safe_webhook_url(url):
        return jsonify({'ok': False, 'error': 'URL bloquée par la sécurité'}), 403

    result = test_merchant_webhook(url)
    if not result['ok']:
        return jsonify(result), 502
    return jsonify(result)