import os
import re
import jwt
import bcrypt
import hashlib
import secrets
import requests
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

@app.template_filter('split')
def split_filter(value, sep=','):
    return (value or '').split(sep)

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
JWT_SECRET = os.getenv('JWT_SECRET')

SUPA_HEADERS = {
    'apikey': SUPABASE_KEY,
    'Authorization': f'Bearer {SUPABASE_KEY}',
    'Content-Type': 'application/json',
    'Prefer': 'return=representation'
}

COUNTRIES = [
    {'code':'CM','name':'Cameroun','flag':'🇨🇲','currency':'XAF'},
    {'code':'BJ','name':'Bénin','flag':'🇧🇯','currency':'XOF'},
    {'code':'ML','name':'Mali','flag':'🇲🇱','currency':'XOF'},
    {'code':'TG','name':'Togo','flag':'🇹🇬','currency':'XOF'},
    {'code':'BF','name':'Burkina Faso','flag':'🇧🇫','currency':'XOF'},
    {'code':'TD','name':'Tchad','flag':'🇹🇩','currency':'XAF'},
    {'code':'CD','name':'RDC','flag':'🇨🇩','currency':'CDF'},
    {'code':'SN','name':'Sénégal','flag':'🇸🇳','currency':'XOF'},
    {'code':'CI','name':"Côte d'Ivoire",'flag':'🇨🇮','currency':'XOF'},
    {'code':'NE','name':'Niger','flag':'🇳🇪','currency':'XOF'},
    {'code':'NG','name':'Nigeria','flag':'🇳🇬','currency':'NGN'},
    {'code':'GA','name':'Gabon','flag':'🇬🇦','currency':'XAF'},
]

def sb_get(table, query=''):
    try:
        r = requests.get(f'{SUPABASE_URL}/rest/v1/{table}?{query}', headers=SUPA_HEADERS, timeout=10)
        return r.json() if r.ok else []
    except:
        return []

def sb_post(table, data):
    try:
        r = requests.post(f'{SUPABASE_URL}/rest/v1/{table}', headers=SUPA_HEADERS, json=data, timeout=10)
        print(f'[sb_post] {table} status={r.status_code} body={r.text[:300]}')
        if r.ok:
            return r.json()
        return {'_error': True, '_status': r.status_code, '_detail': r.text[:300]}
    except Exception as e:
        print(f'[sb_post] error: {e}')
        return {'_error': True, '_status': 0, '_detail': str(e)}

def sb_patch(table, field, value, data):
    try:
        r = requests.patch(f'{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}', headers=SUPA_HEADERS, json=data, timeout=10)
        return r.ok
    except:
        return False

def sb_delete(table, field, value):
    try:
        r = requests.delete(f'{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}', headers=SUPA_HEADERS, timeout=10)
        return r.ok
    except:
        return False

def sb_patch_multi(table, filters, data):
    try:
        qs = '&'.join([f'{k}=eq.{v}' for k, v in filters.items()])
        r = requests.patch(f'{SUPABASE_URL}/rest/v1/{table}?{qs}', headers=SUPA_HEADERS, json=data, timeout=10)
        return r.ok
    except:
        return False

def sb_delete_multi(table, filters):
    try:
        qs = '&'.join([f'{k}=eq.{v}' for k, v in filters.items()])
        r = requests.delete(f'{SUPABASE_URL}/rest/v1/{table}?{qs}', headers=SUPA_HEADERS, timeout=10)
        return r.ok
    except:
        return False

def get_config():
    data = sb_get('site_config')
    return {item['key']: item['value'] for item in data}

def generate_token(username):
    payload = {'sub': username, 'iat': datetime.utcnow(), 'exp': datetime.utcnow() + timedelta(hours=8)}
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except:
        return None

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('fp_user_token')
        if not token:
            return redirect(url_for('login_page'))
        payload = verify_token(token)
        if not payload or payload.get('type') != 'user':
            return redirect(url_for('login_page'))
        users = sb_get('users', f"id=eq.{payload.get('sub')}")
        if not users or not users[0].get('is_admin'):
            return redirect(url_for('login_page'))
        request.user_id = payload.get('sub')
        request.user_email = payload.get('email')
        return f(*args, **kwargs)
    return decorated


# ── AUTH UTILISATEUR ──────────────────────────────
def generate_user_token(user_id, email):
    payload = {
        'sub': str(user_id),
        'email': email,
        'type': 'user',
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def user_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('fp_user_token')
        if not token:
            return redirect(url_for('login_page'))
        payload = verify_token(token)
        if not payload or payload.get('type') != 'user':
            return redirect(url_for('login_page'))
        request.user_id = payload.get('sub')
        request.user_email = payload.get('email')
        return f(*args, **kwargs)
    return decorated

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'ok': False, 'error': 'Email et mot de passe requis'}), 400

    email = data['email'].strip().lower()
    password = data['password']

    users = sb_get('users', f'email=eq.{email}')
    if not users:
        return jsonify({'ok': False, 'error': 'Identifiants incorrects'}), 401

    user = users[0]
    if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        return jsonify({'ok': False, 'error': 'Identifiants incorrects'}), 401

    if not user.get('is_active', True):
        return jsonify({'ok': False, 'error': 'Compte désactivé'}), 403

    token = generate_user_token(user['id'], user['email'])
    resp = make_response(jsonify({'ok': True, 'user': {
        'firstname': user['firstname'],
        'lastname': user['lastname'],
        'email': user['email'],
        'company': user.get('company',''),
        'phone': user.get('phone',''),
        'country': user.get('country',''),
        'plan': user.get('plan','starter')
    }}))
    resp.set_cookie('fp_user_token', token, httponly=True, samesite='Lax', max_age=7*24*3600)
    return resp

@app.route('/api/logout')
def api_logout():
    resp = make_response(redirect(url_for('login_page')))
    resp.delete_cookie('fp_user_token')
    return resp

@app.route('/api/me')
@user_required
def api_me():
    users = sb_get('users', f"id=eq.{request.user_id}")
    if not users:
        return jsonify({'ok': False}), 404
    user = users[0]
    return jsonify({'ok': True, 'user': {
        'firstname': user['firstname'],
        'lastname': user['lastname'],
        'email': user['email'],
        'company': user.get('company',''),
        'phone': user.get('phone',''),
        'country': user.get('country',''),
        'plan': user.get('plan','starter'),
        'kyc_status': user.get('kyc_status', 'unverified'),
        'kyc_rejection_reason': user.get('kyc_rejection_reason')
    }})


@app.route('/api/profile', methods=['PUT'])
@user_required
def api_update_profile():
    data = request.get_json()
    if not data:
        return jsonify({'ok': False, 'error': 'Données manquantes'}), 400
    allowed = {}
    for field in ['firstname', 'lastname', 'company', 'phone']:
        if field in data and isinstance(data[field], str):
            allowed[field] = data[field].strip()
    if not allowed:
        return jsonify({'ok': False, 'error': 'Aucun champ à mettre à jour'}), 400
    ok = sb_patch('users', 'id', request.user_id, allowed)
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la mise à jour du profil'}), 500
    return jsonify({'ok': True, 'message': 'Profil mis à jour'})

@app.route('/api/password', methods=['PUT'])
@user_required
def api_change_password():
    data = request.get_json()
    if not data or not data.get('old_password') or not data.get('new_password'):
        return jsonify({'ok': False, 'error': 'Champs manquants'}), 400
    if len(data['new_password']) < 8:
        return jsonify({'ok': False, 'error': 'Le nouveau mot de passe doit contenir au moins 8 caractères'}), 400
    users = sb_get('users', f"id=eq.{request.user_id}")
    if not users:
        return jsonify({'ok': False, 'error': 'Utilisateur introuvable'}), 404
    user = users[0]
    if not bcrypt.checkpw(data['old_password'].encode('utf-8'), user['password_hash'].encode('utf-8')):
        return jsonify({'ok': False, 'error': 'Mot de passe actuel incorrect'}), 401
    new_hash = bcrypt.hashpw(data['new_password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    ok = sb_patch('users', 'id', request.user_id, {'password_hash': new_hash})
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la mise à jour du mot de passe'}), 500
    return jsonify({'ok': True, 'message': 'Mot de passe mis à jour'})

@app.route('/api/account', methods=['DELETE'])
@user_required
def api_delete_account():
    ok = sb_delete('users', 'id', request.user_id)
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la suppression du compte'}), 500
    resp = make_response(jsonify({'ok': True}))
    resp.delete_cookie('fp_user_token')
    return resp

# ── API TRANSACTIONS ──────────────────────────────
@app.route('/api/transactions', methods=['GET'])
@user_required
def api_get_transactions():
    txs = sb_get('transactions', f"user_id=eq.{request.user_id}&order=created_at.desc&limit=100")
    return jsonify({'ok': True, 'transactions': txs})

@app.route('/api/pay', methods=['POST'])
def api_pay():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'ok': False, 'error': 'Clé API requise'}), 401
    provided_key = auth.replace('Bearer ', '', 1).strip()
    key_hash = hashlib.sha256(provided_key.encode()).hexdigest()

    matches = sb_get('api_keys', f'key_hash=eq.{key_hash}&active=eq.true')
    if not matches:
        return jsonify({'ok': False, 'error': 'Clé API invalide ou révoquée'}), 401
    key_row = matches[0]
    user_id = key_row['user_id']
    environment = key_row.get('environment', 'live')
    sb_patch('api_keys', 'id', key_row['id'], {'last_used_at': datetime.utcnow().isoformat()})

    data = request.get_json()
    if not data:
        return jsonify({'ok': False, 'error': 'Données manquantes'}), 400

    required = ['amount', 'phone', 'client_name', 'order_id']
    for field in required:
        if not data.get(field):
            return jsonify({'ok': False, 'error': f'Champ manquant: {field}'}), 400

    import uuid
    token = 'fp_tx_' + uuid.uuid4().hex[:20]

    tx_payload = {
        'token': token,
        'order_id': data['order_id'],
        'amount': data['amount'],
        'client_name': data['client_name'],
        'client_phone': data['phone'],
        'country': data.get('country', ''),
        'status': 'pending',
        'environment': 'sandbox' if environment == 'sandbox' else 'production',
        'user_id': user_id,
        'created_at': datetime.utcnow().isoformat()
    }

    tx = sb_post('transactions', tx_payload)

    if not tx or (isinstance(tx, dict) and tx.get('_error')):
        return jsonify({'ok': False, 'error': 'Erreur lors de la création de la transaction'}), 500

    return jsonify({
        'ok': True,
        'token': token,
        'order_id': data['order_id'],
        'amount': data['amount'],
        'status': 'pending',
        'payment_url': f'https://flinpay.vercel.app/pay/{token}'
    })

@app.route('/api/transactions/export', methods=['GET'])
@user_required
def api_export_transactions():
    txs = sb_get('transactions', f"user_id=eq.{request.user_id}&order=created_at.desc")
    import io, csv
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Client', 'Montant', 'Statut', 'Pays', 'Date'])
    for tx in txs:
        writer.writerow([tx.get('token',''), tx.get('client_name',''), tx.get('amount',''), tx.get('status',''), tx.get('country',''), tx.get('created_at','')])
    from flask import Response
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=transactions_flinpay.csv'})

# ── KYC (vérification d'identité) ─────────────────
@app.route('/kyc')
@user_required
def kyc_page():
    return render_template('kyc.html', user=get_current_user())

@app.route('/api/kyc/submit', methods=['POST'])
@user_required
def api_kyc_submit():
    full_name = (request.form.get('full_name') or '').strip()
    id_type = (request.form.get('id_type') or '').strip()
    id_number = (request.form.get('id_number') or '').strip()
    file = request.files.get('document')

    if not full_name or not id_type or not id_number or not file or not file.filename:
        return jsonify({'ok': False, 'error': 'Tous les champs et le document sont requis'}), 400

    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in ('jpg', 'jpeg', 'png', 'pdf'):
        return jsonify({'ok': False, 'error': 'Format non supporté (jpg, png ou pdf uniquement)'}), 400

    file_bytes = file.read()
    if len(file_bytes) > 8 * 1024 * 1024:
        return jsonify({'ok': False, 'error': 'Fichier trop volumineux (8 Mo max)'}), 400

    path = f"{request.user_id}/{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.{ext}"
    uploaded = sb_storage_upload('kyc-documents', path, file_bytes, file.mimetype or 'application/octet-stream')
    if not uploaded:
        return jsonify({'ok': False, 'error': "Erreur lors de l'upload du document. Vérifie que le bucket 'kyc-documents' existe."}), 500

    updated = sb_patch('users', 'id', request.user_id, {
        'kyc_status': 'pending',
        'kyc_full_name': full_name,
        'kyc_id_type': id_type,
        'kyc_id_number': id_number,
        'kyc_document_path': path,
        'kyc_submitted_at': datetime.utcnow().isoformat(),
        'kyc_rejection_reason': None
    })
    if not updated:
        return jsonify({'ok': False, 'error': 'Erreur lors de la mise à jour du profil'}), 500
    return jsonify({'ok': True, 'message': 'Document envoyé. Vérification sous 24-48h.'})

# ── ADMIN : REVUE KYC ─────────────────────────────
@app.route('/admin/kyc')
@admin_required
def admin_kyc_page():
    pending = sb_get('users', 'kyc_status=eq.pending&order=kyc_submitted_at.asc')
    return render_template('admin_kyc.html', pending=pending)

@app.route('/api/admin/kyc/<user_id>/document')
@admin_required
def api_admin_kyc_document(user_id):
    users = sb_get('users', f'id=eq.{user_id}')
    if not users or not users[0].get('kyc_document_path'):
        return jsonify({'ok': False, 'error': 'Document introuvable'}), 404
    url = sb_storage_sign('kyc-documents', users[0]['kyc_document_path'])
    if not url:
        return jsonify({'ok': False, 'error': 'Erreur de génération du lien'}), 500
    return jsonify({'ok': True, 'url': url})

@app.route('/api/admin/kyc/<user_id>/approve', methods=['POST'])
@admin_required
def api_admin_kyc_approve(user_id):
    ok = sb_patch('users', 'id', user_id, {
        'kyc_status': 'verified',
        'kyc_reviewed_at': datetime.utcnow().isoformat(),
        'kyc_rejection_reason': None
    })
    return jsonify({'ok': ok})

@app.route('/api/admin/kyc/<user_id>/reject', methods=['POST'])
@admin_required
def api_admin_kyc_reject(user_id):
    data = request.get_json() or {}
    reason = (data.get('reason') or 'Document invalide ou illisible').strip()
    ok = sb_patch('users', 'id', user_id, {
        'kyc_status': 'rejected',
        'kyc_reviewed_at': datetime.utcnow().isoformat(),
        'kyc_rejection_reason': reason
    })
    return jsonify({'ok': ok})

# ── API KEYS (réelles, hashées) ───────────────────
@app.route('/api/keys', methods=['GET'])
@user_required
def api_list_keys():
    keys = sb_get('api_keys', f"user_id=eq.{request.user_id}&order=created_at.desc")
    safe = [{
        'id': k['id'],
        'key_prefix': k['key_prefix'],
        'environment': k.get('environment', 'live'),
        'label': k.get('label') or '',
        'active': k.get('active', True),
        'created_at': k.get('created_at'),
        'last_used_at': k.get('last_used_at')
    } for k in keys]
    return jsonify({'ok': True, 'keys': safe})

@app.route('/api/keys', methods=['POST'])
@user_required
def api_create_key():
    user = get_current_user()
    if user.get('kyc_status') != 'verified':
        return jsonify({'ok': False, 'error': "Vérifiez votre identité avant de générer une clé API"}), 403

    data = request.get_json() or {}
    environment = data.get('environment') if data.get('environment') in ('live', 'sandbox') else 'live'
    label = (data.get('label') or '').strip()[:60]

    full_key, key_hash, display_prefix = generate_api_key(environment)
    row = sb_post('api_keys', {
        'user_id': request.user_id,
        'key_prefix': display_prefix,
        'key_hash': key_hash,
        'environment': environment,
        'label': label,
        'active': True,
        'created_at': datetime.utcnow().isoformat()
    })
    if not row or (isinstance(row, dict) and row.get('_error')):
        detail = row.get('_detail') if isinstance(row, dict) else 'inconnue'
        return jsonify({'ok': False, 'error': f'Erreur Supabase: {detail}'}), 500
    return jsonify({'ok': True, 'key': full_key, 'key_prefix': display_prefix, 'environment': environment})

@app.route('/api/keys/<int:key_id>', methods=['DELETE'])
@user_required
def api_delete_key(key_id):
    ok = sb_delete_multi('api_keys', {'id': key_id, 'user_id': request.user_id})
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la révocation'}), 500
    return jsonify({'ok': True})

# ── API PAYMENT LINKS ─────────────────────────────
@app.route('/api/payment-links', methods=['GET'])
@user_required
def api_get_payment_links():
    links = sb_get('payment_links', f"user_id=eq.{request.user_id}&order=created_at.desc")
    return jsonify({'ok': True, 'links': links})

@app.route('/api/payment-links', methods=['POST'])
@user_required
def api_create_payment_link():
    data = request.get_json()
    if not data or not data.get('name') or not data.get('amount'):
        return jsonify({'ok': False, 'error': 'Nom et montant requis'}), 400
    try:
        amount = float(data['amount'])
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'Montant invalide'}), 400
    if amount <= 0:
        return jsonify({'ok': False, 'error': 'Montant invalide'}), 400

    import uuid
    token = 'pay_' + uuid.uuid4().hex[:12]

    payload = {
        'token': token,
        'user_id': request.user_id,
        'name': data['name'].strip(),
        'amount': amount,
        'description': (data.get('description') or '').strip(),
        'usage_limit': data.get('usage_limit') or None,
        'expires_at': data.get('expires_at') or None,
        'active': True,
        'views': 0,
        'paid_count': 0,
        'created_at': datetime.utcnow().isoformat()
    }
    link = sb_post('payment_links', payload)
    if not link or (isinstance(link, dict) and link.get('_error')):
        detail = link.get('_detail') if isinstance(link, dict) else 'inconnue'
        return jsonify({'ok': False, 'error': f'Erreur Supabase: {detail}'}), 500
    return jsonify({'ok': True, 'link': link[0] if isinstance(link, list) else link})

@app.route('/api/payment-links/<token>', methods=['PUT'])
@user_required
def api_update_payment_link(token):
    data = request.get_json() or {}
    allowed = {}
    if 'active' in data:
        allowed['active'] = bool(data['active'])
    if not allowed:
        return jsonify({'ok': False, 'error': 'Aucun champ à mettre à jour'}), 400
    ok = sb_patch_multi('payment_links', {'token': token, 'user_id': request.user_id}, allowed)
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la mise à jour'}), 500
    return jsonify({'ok': True})

@app.route('/api/payment-links/<token>', methods=['DELETE'])
@user_required
def api_delete_payment_link(token):
    ok = sb_delete_multi('payment_links', {'token': token, 'user_id': request.user_id})
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la suppression'}), 500
    return jsonify({'ok': True})

# ── ROUTES PUBLIQUES ──────────────────────────────
@app.route('/')
def index():
    cfg = get_config()
    stats = sb_get('stats', 'order=order_index.asc')
    features = sb_get('features', 'is_visible=eq.true&order=order_index.asc')
    plans = sb_get('pricing_plans', 'is_visible=eq.true&order=order_index.asc')
    testimonials = sb_get('testimonials', 'is_visible=eq.true&order=order_index.asc')
    return render_template('index.html', cfg=cfg, stats=stats, features=features, plans=plans, testimonials=testimonials, countries=COUNTRIES)

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

def sb_storage_upload(bucket, path, file_bytes, content_type):
    try:
        url = f'{SUPABASE_URL}/storage/v1/object/{bucket}/{path}'
        headers = {
            'apikey': SUPABASE_KEY,
            'Authorization': f'Bearer {SUPABASE_KEY}',
            'Content-Type': content_type or 'application/octet-stream',
            'x-upsert': 'true'
        }
        r = requests.post(url, headers=headers, data=file_bytes, timeout=20)
        return r.ok
    except Exception as e:
        print(f'[sb_storage_upload] error: {e}')
        return False

def sb_storage_sign(bucket, path, expires_in=3600):
    try:
        url = f'{SUPABASE_URL}/storage/v1/object/sign/{bucket}/{path}'
        r = requests.post(url, headers=SUPA_HEADERS, json={'expiresIn': expires_in}, timeout=10)
        if not r.ok:
            return None
        signed_path = r.json().get('signedURL')
        return f'{SUPABASE_URL}/storage/v1{signed_path}' if signed_path else None
    except Exception as e:
        print(f'[sb_storage_sign] error: {e}')
        return None

def generate_api_key(environment):
    raw = secrets.token_hex(24)
    prefix = 'fp_live_' if environment == 'live' else 'fp_test_'
    full_key = prefix + raw
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    display_prefix = full_key[:14] + '…'
    return full_key, key_hash, display_prefix

def sb_count(table, query=''):
    try:
        headers = dict(SUPA_HEADERS)
        headers['Prefer'] = 'count=exact'
        sep = '&' if query else ''
        r = requests.get(f'{SUPABASE_URL}/rest/v1/{table}?{query}{sep}limit=1', headers=headers, timeout=10)
        cr = r.headers.get('Content-Range', '')
        return int(cr.split('/')[-1]) if '/' in cr else 0
    except:
        return 0

def get_current_user():
    users = sb_get('users', f"id=eq.{request.user_id}")
    return users[0] if users else {}

@app.route('/dashboard')
@user_required
def dashboard():
    users = sb_get('users', f"id=eq.{request.user_id}")
    user = users[0] if users else {}
    return render_template('dashboard.html', user=user)

@app.route('/docs')
def docs():
    return render_template('404.html')

@app.route('/favicon.ico')
def favicon():
    return '', 204

# ── API REGISTER ──────────────────────────────────
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    if not data:
        return jsonify({'ok': False, 'error': 'Données manquantes'}), 400
    for field in ['firstname','lastname','email','country','phone','password']:
        if not data.get(field):
            return jsonify({'ok': False, 'error': f'Champ manquant: {field}'}), 400
    email = data['email'].strip().lower()
    if len(data['password']) < 8:
        return jsonify({'ok': False, 'error': 'Mot de passe trop court'}), 400
    existing = sb_get('users', f'email=eq.{email}')
    if existing:
        return jsonify({'ok': False, 'error': 'Email déjà utilisé'}), 409
    hashed = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user = sb_post('users', {
        'firstname': data['firstname'].strip(),
        'lastname': data['lastname'].strip(),
        'email': email,
        'company': data.get('company','').strip(),
        'country': data['country'],
        'phone': data['phone'].strip(),
        'password_hash': hashed,
        'plan': 'starter',
        'is_active': True,
        'created_at': datetime.utcnow().isoformat()
    })
    if not user or (isinstance(user, dict) and user.get('_error')):
        detail = user.get('_detail') if isinstance(user, dict) else 'inconnue'
        return jsonify({'ok': False, 'error': f'Erreur Supabase: {detail}'}), 500
    return jsonify({'ok': True, 'message': 'Compte créé avec succès'})

# ── PAGE PUBLIQUE : LIEN DE PAIEMENT ──────────────
def _link_status(link):
    """Retourne (valide, raison) pour un lien de paiement."""
    if not link:
        return False, 'introuvable'
    if not link.get('active', True):
        return False, 'inactif'
    if link.get('expires_at'):
        try:
            if datetime.utcnow().date() > datetime.fromisoformat(link['expires_at']).date():
                return False, 'expire'
        except Exception:
            pass
    if link.get('usage_limit') and (link.get('paid_count') or 0) >= link['usage_limit']:
        return False, 'limite'
    return True, ''

@app.route('/pay/<token>')
def pay_page(token):
    links = sb_get('payment_links', f'token=eq.{token}')
    link = links[0] if links else None
    valid, reason = _link_status(link)
    if link and valid:
        sb_patch_multi('payment_links', {'token': token}, {'views': (link.get('views') or 0) + 1})
    return render_template('pay.html', link=link, valid=valid, reason=reason, token=token)

@app.route('/api/pay-link/<token>', methods=['POST'])
def api_pay_link(token):
    links = sb_get('payment_links', f'token=eq.{token}')
    link = links[0] if links else None
    valid, reason = _link_status(link)
    if not valid:
        messages = {
            'introuvable': 'Lien introuvable',
            'inactif': 'Ce lien est désactivé',
            'expire': 'Ce lien a expiré',
            'limite': "Ce lien a atteint sa limite d'utilisation"
        }
        return jsonify({'ok': False, 'error': messages.get(reason, 'Lien invalide')}), 400

    data = request.get_json() or {}
    phone = (data.get('phone') or '').strip()
    if not phone:
        return jsonify({'ok': False, 'error': 'Numéro de téléphone requis'}), 400

    import uuid
    tx = sb_post('transactions', {
        'token': 'fp_tx_' + uuid.uuid4().hex[:20],
        'order_id': 'link_' + uuid.uuid4().hex[:10],
        'amount': link['amount'],
        'client_name': (data.get('name') or '').strip() or 'Client',
        'client_phone': phone,
        'country': data.get('country', ''),
        'status': 'pending',
        'environment': 'production',
        'user_id': link['user_id'],
        'created_at': datetime.utcnow().isoformat()
    })
    if not tx or (isinstance(tx, dict) and tx.get('_error')):
        return jsonify({'ok': False, 'error': 'Erreur lors de la création du paiement'}), 500

    sb_patch_multi('payment_links', {'token': token}, {'paid_count': (link.get('paid_count') or 0) + 1})
    return jsonify({'ok': True, 'message': 'Paiement initié, en attente de confirmation.'})

# ── ADMIN LOGIN (obsolète — redirige vers le login normal) ──
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    return redirect(url_for('login_page'))

@app.route('/admin/logout')
def admin_logout():
    resp = make_response(redirect(url_for('login_page')))
    resp.delete_cookie('fp_user_token')
    return resp

@app.route('/admin')
@admin_required
def admin():
    return render_template('admin.html', user=get_current_user())

# ── ADMIN : TRANSACTIONS (tous les utilisateurs) ──
@app.route('/api/admin/transactions', methods=['GET'])
@admin_required
def api_admin_get_transactions():
    return jsonify({'ok': True, 'items': sb_get('transactions', 'order=created_at.desc&limit=500')})

@app.route('/api/admin/transactions/<int:tid>', methods=['PUT'])
@admin_required
def api_admin_update_transaction(tid):
    ok = sb_patch('transactions', 'id', tid, request.get_json())
    return jsonify({'ok': ok})

@app.route('/api/admin/transactions/<int:tid>', methods=['DELETE'])
@admin_required
def api_admin_delete_transaction(tid):
    ok = sb_delete('transactions', 'id', tid)
    return jsonify({'ok': ok})

# ── ADMIN : PAYOUTS ────────────────────────────────
@app.route('/api/admin/payouts', methods=['GET'])
@admin_required
def api_admin_get_payouts():
    return jsonify({'ok': True, 'items': sb_get('payouts', 'order=created_at.desc')})

@app.route('/api/admin/payouts', methods=['POST'])
@admin_required
def api_admin_create_payout():
    data = request.get_json() or {}
    if not data.get('user_id') or not data.get('amount') or not data.get('phone'):
        return jsonify({'ok': False, 'error': 'user_id, amount et phone sont requis'}), 400
    payload = {
        'user_id': data.get('user_id'),
        'amount': data.get('amount'),
        'phone': data.get('phone'),
        'operator': data.get('operator', ''),
        'country': data.get('country', ''),
        'status': data.get('status', 'pending'),
        'note': data.get('note', ''),
        'created_at': datetime.utcnow().isoformat()
    }
    row = sb_post('payouts', payload)
    if not row or (isinstance(row, dict) and row.get('_error')):
        detail = row.get('_detail') if isinstance(row, dict) else 'inconnue'
        return jsonify({'ok': False, 'error': f'Erreur Supabase: {detail}'}), 500
    return jsonify({'ok': True, 'item': row[0] if isinstance(row, list) else row})

@app.route('/api/admin/payouts/<int:pid>', methods=['PUT'])
@admin_required
def api_admin_update_payout(pid):
    return jsonify({'ok': sb_patch('payouts', 'id', pid, request.get_json())})

@app.route('/api/admin/payouts/<int:pid>', methods=['DELETE'])
@admin_required
def api_admin_delete_payout(pid):
    return jsonify({'ok': sb_delete('payouts', 'id', pid)})

# ── ADMIN : UTILISATEURS (voir/modifier/supprimer tout) ──
@app.route('/api/admin/users', methods=['GET'])
@admin_required
def api_admin_get_users():
    users = sb_get('users', 'order=created_at.desc&limit=500')
    safe = [{k: v for k, v in u.items() if k != 'password_hash'} for u in users]
    return jsonify({'ok': True, 'items': safe})

@app.route('/api/admin/users/<user_id>', methods=['PUT'])
@admin_required
def api_admin_update_user(user_id):
    data = request.get_json() or {}
    data.pop('password_hash', None)
    data.pop('id', None)
    ok = sb_patch('users', 'id', user_id, data)
    return jsonify({'ok': ok})

@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@admin_required
def api_admin_delete_user(user_id):
    ok = sb_delete('users', 'id', user_id)
    return jsonify({'ok': ok})

@app.route('/api/admin/overview')
@admin_required
def api_admin_overview():
    return jsonify({
        'ok': True,
        'users': sb_count('users'),
        'transactions': sb_count('transactions'),
        'pending_kyc': sb_count('users', 'kyc_status=eq.pending'),
        'payment_links': sb_count('payment_links')
    })

# ── API ADMIN CONFIG ──────────────────────────────
@app.route('/api/admin/config', methods=['GET'])
@admin_required
def api_get_config():
    return jsonify({'ok': True, 'items': sb_get('site_config')})

@app.route('/api/admin/config', methods=['PUT'])
@admin_required
def api_update_config():
    body = request.get_json()
    ok = sb_patch('site_config', 'key', body.get('key'), {'value': body.get('value'), 'updated_at': datetime.utcnow().isoformat()})
    return jsonify({'ok': ok})

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def api_get_stats():
    return jsonify({'ok': True, 'items': sb_get('stats', 'order=order_index.asc')})

@app.route('/api/admin/stats', methods=['POST'])
@admin_required
def api_create_stat():
    row = sb_post('stats', request.get_json())
    if not row or (isinstance(row, dict) and row.get('_error')):
        detail = row.get('_detail') if isinstance(row, dict) else 'inconnue'
        return jsonify({'ok': False, 'error': f'Erreur Supabase: {detail}'}), 500
    return jsonify({'ok': True, 'item': row[0] if isinstance(row, list) else row})

@app.route('/api/admin/stats/<int:sid>', methods=['PUT'])
@admin_required
def api_update_stat(sid):
    return jsonify({'ok': sb_patch('stats', 'id', sid, request.get_json())})

@app.route('/api/admin/stats/<int:sid>', methods=['DELETE'])
@admin_required
def api_delete_stat(sid):
    return jsonify({'ok': sb_delete('stats', 'id', sid)})

@app.route('/api/admin/features', methods=['GET'])
@admin_required
def api_get_features():
    return jsonify({'ok': True, 'items': sb_get('features', 'order=order_index.asc')})

@app.route('/api/admin/features', methods=['POST'])
@admin_required
def api_create_feature():
    row = sb_post('features', request.get_json())
    if not row or (isinstance(row, dict) and row.get('_error')):
        detail = row.get('_detail') if isinstance(row, dict) else 'inconnue'
        return jsonify({'ok': False, 'error': f'Erreur Supabase: {detail}'}), 500
    return jsonify({'ok': True, 'item': row[0] if isinstance(row, list) else row})

@app.route('/api/admin/features/<int:fid>', methods=['PUT'])
@admin_required
def api_update_feature(fid):
    return jsonify({'ok': sb_patch('features', 'id', fid, request.get_json())})

@app.route('/api/admin/features/<int:fid>', methods=['DELETE'])
@admin_required
def api_delete_feature(fid):
    return jsonify({'ok': sb_delete('features', 'id', fid)})

@app.route('/api/admin/pricing', methods=['GET'])
@admin_required
def api_get_pricing():
    return jsonify({'ok': True, 'items': sb_get('pricing_plans', 'order=order_index.asc')})

@app.route('/api/admin/pricing', methods=['POST'])
@admin_required
def api_create_plan():
    row = sb_post('pricing_plans', request.get_json())
    if not row or (isinstance(row, dict) and row.get('_error')):
        detail = row.get('_detail') if isinstance(row, dict) else 'inconnue'
        return jsonify({'ok': False, 'error': f'Erreur Supabase: {detail}'}), 500
    return jsonify({'ok': True, 'item': row[0] if isinstance(row, list) else row})

@app.route('/api/admin/pricing/<int:pid>', methods=['PUT'])
@admin_required
def api_update_plan(pid):
    return jsonify({'ok': sb_patch('pricing_plans', 'id', pid, request.get_json())})

@app.route('/api/admin/pricing/<int:pid>', methods=['DELETE'])
@admin_required
def api_delete_plan(pid):
    return jsonify({'ok': sb_delete('pricing_plans', 'id', pid)})

@app.route('/api/admin/testimonials', methods=['GET'])
@admin_required
def api_get_testimonials():
    return jsonify({'ok': True, 'items': sb_get('testimonials', 'order=order_index.asc')})

@app.route('/api/admin/testimonials', methods=['POST'])
@admin_required
def api_create_testimonial():
    row = sb_post('testimonials', request.get_json())
    if not row or (isinstance(row, dict) and row.get('_error')):
        detail = row.get('_detail') if isinstance(row, dict) else 'inconnue'
        return jsonify({'ok': False, 'error': f'Erreur Supabase: {detail}'}), 500
    return jsonify({'ok': True, 'item': row[0] if isinstance(row, list) else row})

@app.route('/api/admin/testimonials/<int:tid>', methods=['PUT'])
@admin_required
def api_update_testimonial(tid):
    return jsonify({'ok': sb_patch('testimonials', 'id', tid, request.get_json())})

@app.route('/api/admin/testimonials/<int:tid>', methods=['DELETE'])
@admin_required
def api_delete_testimonial(tid):
    return jsonify({'ok': sb_delete('testimonials', 'id', tid)})

# ── ERREURS ───────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    import traceback
    orig = getattr(e, 'original_exception', e)
    traceback.print_exc()
    return jsonify({'error': str(orig), 'type': type(orig).__name__}), 500


@app.route('/transactions')
@user_required
def transactions():
    return render_template('transactions.html', user=get_current_user())

@app.route('/payouts')
@user_required
def payouts():
    return render_template('payouts.html', user=get_current_user())

@app.route('/api-keys')
@user_required
def api_keys_page():
    return render_template('api_keys.html', user=get_current_user())

@app.route('/webhooks')
@user_required
def webhooks_page():
    return render_template('webhooks.html', user=get_current_user())

@app.route('/sandbox')
@user_required
def sandbox():
    return render_template('sandbox.html', user=get_current_user())

@app.route('/profile')
@user_required
def profile():
    return render_template('profile.html', user=get_current_user())

@app.route('/billing')
@user_required
def billing():
    return render_template('billing.html', user=get_current_user())

@app.route('/payment-links')
@user_required
def payment_links():
    return render_template('payment_links.html', user=get_current_user())

@app.route('/referral')
@user_required
def referral():
    return render_template('referral.html', user=get_current_user())

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
