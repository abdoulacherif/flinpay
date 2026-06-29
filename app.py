import os
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

# ── CONFIG ────────────────────────────────────────
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
    {'code': 'CM', 'name': 'Cameroun',      'flag': '🇨🇲', 'currency': 'XAF'},
    {'code': 'BJ', 'name': 'Bénin',         'flag': '🇧🇯', 'currency': 'XOF'},
    {'code': 'ML', 'name': 'Mali',           'flag': '🇲🇱', 'currency': 'XOF'},
    {'code': 'TG', 'name': 'Togo',           'flag': '🇹🇬', 'currency': 'XOF'},
    {'code': 'BF', 'name': 'Burkina Faso',   'flag': '🇧🇫', 'currency': 'XOF'},
    {'code': 'TD', 'name': 'Tchad',          'flag': '🇹🇩', 'currency': 'XAF'},
    {'code': 'CD', 'name': 'RDC',            'flag': '🇨🇩', 'currency': 'CDF'},
    {'code': 'SN', 'name': 'Sénégal',        'flag': '🇸🇳', 'currency': 'XOF'},
    {'code': 'CI', 'name': "Côte d'Ivoire",  'flag': '🇨🇮', 'currency': 'XOF'},
    {'code': 'NE', 'name': 'Niger',          'flag': '🇳🇪', 'currency': 'XOF'},
    {'code': 'NG', 'name': 'Nigeria',        'flag': '🇳🇬', 'currency': 'NGN'},
    {'code': 'GA', 'name': 'Gabon',          'flag': '🇬🇦', 'currency': 'XAF'},
]

# ── HELPERS SUPABASE ──────────────────────────────
def sb_get(table, query=''):
    try:
        r = requests.get(
            f'{SUPABASE_URL}/rest/v1/{table}?{query}',
            headers=SUPA_HEADERS, timeout=10
        )
        return r.json() if r.ok else []
    except:
        return []

def sb_post(table, data):
    try:
        r = requests.post(
            f'{SUPABASE_URL}/rest/v1/{table}',
            headers=SUPA_HEADERS, json=data, timeout=10
        )
        return r.json() if r.ok else None
    except:
        return None

def sb_patch(table, field, value, data):
    try:
        r = requests.patch(
            f'{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}',
            headers=SUPA_HEADERS, json=data, timeout=10
        )
        return r.ok
    except:
        return False

def sb_delete(table, field, value):
    try:
        r = requests.delete(
            f'{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}',
            headers=SUPA_HEADERS, timeout=10
        )
        return r.ok
    except:
        return False

def get_config():
    data = sb_get('site_config')
    cfg = {}
    for item in data:
        cfg[item['key']] = item['value']
    return cfg

# ── AUTH JWT ──────────────────────────────────────
def generate_token(username):
    payload = {
        'sub': username,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=8)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('fp_token')
        if not token:
            return redirect(url_for('admin_login'))
        payload = verify_token(token)
        if not payload:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

def api_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Token manquant', 'code': 401}), 401
        token = auth.split(' ')[1]
        payload = verify_token(token)
        if not payload:
            return jsonify({'error': 'Token invalide ou expiré', 'code': 401}), 401
        return f(*args, **kwargs)
    return decorated

# ── ROUTES PUBLIQUES ──────────────────────────────
@app.route('/')
def index():
    cfg = get_config()
    stats = sb_get('stats', 'order=order_index.asc')
    features = sb_get('features', 'is_visible=eq.true&order=order_index.asc')
    plans = sb_get('pricing_plans', 'is_visible=eq.true&order=order_index.asc')
    testimonials = sb_get('testimonials', 'is_visible=eq.true&order=order_index.asc')
    return render_template('index.html',
        cfg=cfg,
        stats=stats,
        features=features,
        plans=plans,
        testimonials=testimonials,
        countries=COUNTRIES
    )

@app.route('/docs')
def docs():
    return render_template('docs.html', countries=COUNTRIES)

# ── ROUTES ADMIN ──────────────────────────────────
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            token = generate_token(username)
            resp = make_response(jsonify({'ok': True}))
            resp.set_cookie(
                'fp_token', token,
                httponly=True,
                secure=False,
                samesite='Lax',
                max_age=8*3600
            )
            return resp
        return jsonify({'ok': False, 'error': 'Identifiants incorrects'}), 401

    return render_template('login.html')

@app.route('/admin/logout')
def admin_logout():
    resp = make_response(redirect(url_for('admin_login')))
    resp.delete_cookie('fp_token')
    return resp

@app.route('/admin')
@admin_required
def admin():
    return render_template('admin.html')

# ── API ADMIN — CONFIG ────────────────────────────
@app.route('/api/admin/config', methods=['GET'])
@admin_required
def api_get_config():
    data = sb_get('site_config')
    return jsonify(data)

@app.route('/api/admin/config', methods=['PUT'])
@admin_required
def api_update_config():
    body = request.get_json()
    key = body.get('key')
    value = body.get('value')
    if not key:
        return jsonify({'error': 'Clé manquante'}), 400
    ok = sb_patch('site_config', 'key', key, {
        'value': value,
        'updated_at': datetime.utcnow().isoformat()
    })
    return jsonify({'ok': ok})

# ── API ADMIN — STATS ─────────────────────────────
@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def api_get_stats():
    return jsonify(sb_get('stats', 'order=order_index.asc'))

@app.route('/api/admin/stats', methods=['POST'])
@admin_required
def api_create_stat():
    data = request.get_json()
    result = sb_post('stats', data)
    return jsonify(result)

@app.route('/api/admin/stats/<int:stat_id>', methods=['PUT'])
@admin_required
def api_update_stat(stat_id):
    data = request.get_json()
    ok = sb_patch('stats', 'id', stat_id, data)
    return jsonify({'ok': ok})

@app.route('/api/admin/stats/<int:stat_id>', methods=['DELETE'])
@admin_required
def api_delete_stat(stat_id):
    ok = sb_delete('stats', 'id', stat_id)
    return jsonify({'ok': ok})

# ── API ADMIN — FEATURES ──────────────────────────
@app.route('/api/admin/features', methods=['GET'])
@admin_required
def api_get_features():
    return jsonify(sb_get('features', 'order=order_index.asc'))

@app.route('/api/admin/features', methods=['POST'])
@admin_required
def api_create_feature():
    data = request.get_json()
    return jsonify(sb_post('features', data))

@app.route('/api/admin/features/<int:fid>', methods=['PUT'])
@admin_required
def api_update_feature(fid):
    data = request.get_json()
    ok = sb_patch('features', 'id', fid, data)
    return jsonify({'ok': ok})

@app.route('/api/admin/features/<int:fid>', methods=['DELETE'])
@admin_required
def api_delete_feature(fid):
    ok = sb_delete('features', 'id', fid)
    return jsonify({'ok': ok})

# ── API ADMIN — PRICING ───────────────────────────
@app.route('/api/admin/pricing', methods=['GET'])
@admin_required
def api_get_pricing():
    return jsonify(sb_get('pricing_plans', 'order=order_index.asc'))

@app.route('/api/admin/pricing', methods=['POST'])
@admin_required
def api_create_plan():
    data = request.get_json()
    return jsonify(sb_post('pricing_plans', data))

@app.route('/api/admin/pricing/<int:pid>', methods=['PUT'])
@admin_required
def api_update_plan(pid):
    data = request.get_json()
    ok = sb_patch('pricing_plans', 'id', pid, data)
    return jsonify({'ok': ok})

@app.route('/api/admin/pricing/<int:pid>', methods=['DELETE'])
@admin_required
def api_delete_plan(pid):
    ok = sb_delete('pricing_plans', 'id', pid)
    return jsonify({'ok': ok})

# ── API ADMIN — TESTIMONIALS ──────────────────────
@app.route('/api/admin/testimonials', methods=['GET'])
@admin_required
def api_get_testimonials():
    return jsonify(sb_get('testimonials', 'order=order_index.asc'))

@app.route('/api/admin/testimonials', methods=['POST'])
@admin_required
def api_create_testimonial():
    data = request.get_json()
    return jsonify(sb_post('testimonials', data))

@app.route('/api/admin/testimonials/<int:tid>', methods=['PUT'])
@admin_required
def api_update_testimonial(tid):
    data = request.get_json()
    ok = sb_patch('testimonials', 'id', tid, data)
    return jsonify({'ok': ok})

@app.route('/api/admin/testimonials/<int:tid>', methods=['DELETE'])
@admin_required
def api_delete_testimonial(tid):
    ok = sb_delete('testimonials', 'id', tid)
    return jsonify({'ok': ok})

# ── ERREURS ───────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Erreur serveur interne'}), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
