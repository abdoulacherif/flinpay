import os
import re
import jwt
import bcrypt
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
        token = request.cookies.get('fp_token')
        if not token or not verify_token(token):
            return redirect(url_for('admin_login'))
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
        'plan': user.get('plan','starter')
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
    api_key = auth.replace('Bearer ', '', 1).strip()

    # NOTE: la table api_keys n'existe pas encore (à créer avec le "grand backend").
    # En attendant, on tente de résoudre l'utilisateur propriétaire de la clé ;
    # si la table est absente, owner reste vide et la transaction est créée sans user_id
    # (elle n'apparaîtra pas dans /api/transactions tant que ce lien n'est pas en place).
    owner = sb_get('api_keys', f'key=eq.{api_key}&select=user_id')
    user_id = owner[0]['user_id'] if owner else None

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
        'environment': 'sandbox',
        'created_at': datetime.utcnow().isoformat()
    }
    if user_id:
        tx_payload['user_id'] = user_id

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

# ── ADMIN LOGIN ───────────────────────────────────
@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    if request.method == 'POST':
        data = request.get_json()
        if data.get('username') == ADMIN_USERNAME and data.get('password') == ADMIN_PASSWORD:
            token = generate_token(data['username'])
            resp = make_response(jsonify({'ok': True}))
            resp.set_cookie('fp_token', token, httponly=True, samesite='Lax', max_age=8*3600)
            return resp
        return jsonify({'ok': False, 'error': 'Identifiants incorrects'}), 401
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    resp = make_response(redirect(url_for('admin_login')))
    resp.delete_cookie('fp_token')
    return resp

@app.route('/admin')
@admin_required
def admin():
    return render_template('admin.html')

# ── API ADMIN CONFIG ──────────────────────────────
@app.route('/api/admin/config', methods=['GET'])
@admin_required
def api_get_config():
    return jsonify(sb_get('site_config'))

@app.route('/api/admin/config', methods=['PUT'])
@admin_required
def api_update_config():
    body = request.get_json()
    ok = sb_patch('site_config', 'key', body.get('key'), {'value': body.get('value'), 'updated_at': datetime.utcnow().isoformat()})
    return jsonify({'ok': ok})

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def api_get_stats():
    return jsonify(sb_get('stats', 'order=order_index.asc'))

@app.route('/api/admin/stats', methods=['POST'])
@admin_required
def api_create_stat():
    return jsonify(sb_post('stats', request.get_json()))

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
    return jsonify(sb_get('features', 'order=order_index.asc'))

@app.route('/api/admin/features', methods=['POST'])
@admin_required
def api_create_feature():
    return jsonify(sb_post('features', request.get_json()))

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
    return jsonify(sb_get('pricing_plans', 'order=order_index.asc'))

@app.route('/api/admin/pricing', methods=['POST'])
@admin_required
def api_create_plan():
    return jsonify(sb_post('pricing_plans', request.get_json()))

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
    return jsonify(sb_get('testimonials', 'order=order_index.asc'))

@app.route('/api/admin/testimonials', methods=['POST'])
@admin_required
def api_create_testimonial():
    return jsonify(sb_post('testimonials', request.get_json()))

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
    return jsonify({'error': str(e)}), 500


@app.route('/transactions')
@user_required
def transactions():
    return render_template('transactions.html')

@app.route('/payouts')
@user_required
def payouts():
    return render_template('payouts.html')

@app.route('/api-keys')
@user_required
def api_keys_page():
    return render_template('api_keys.html')

@app.route('/webhooks')
@user_required
def webhooks_page():
    return render_template('webhooks.html')

@app.route('/sandbox')
@user_required
def sandbox():
    return render_template('sandbox.html')

@app.route('/profile')
@user_required
def profile():
    return render_template('profile.html')

@app.route('/billing')
@user_required
def billing():
    return render_template('billing.html')

@app.route('/payment-links')
@user_required
def payment_links():
    return render_template('payment_links.html')

@app.route('/referral')
@user_required
def referral():
    return render_template('referral.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
