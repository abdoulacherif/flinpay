"""
services/auth.py — authentification (JWT en cookie), décorateurs de protection
des routes, verrouillage anti-bruteforce, et protection CSRF.

NOTE SUR CSRF ET LES COOKIES DE SESSION
----------------------------------------
Flinpay authentifie via un cookie JWT (`fp_user_token`, HttpOnly + SameSite=Lax
+ Secure en prod — voir extensions.py/app.py). SameSite=Lax bloque déjà la
majorité des attaques CSRF classiques (un `<form>` sur un site tiers qui
soumettrait vers Flinpay). Ce qui reste possible en théorie : les requêtes
"simples" (GET, ou POST avec Content-Type text/plain ou form-urlencoded) sur
certains navigateurs plus anciens. Comme toutes les routes API de Flinpay
attendent du JSON (`Content-Type: application/json`), qui déclenche un
préflight CORS bloqué par la liste blanche stricte d'origines (voir
extensions.py), le risque résiduel est faible — mais pour les actions les
plus sensibles (mot de passe, désactivation 2FA, demande de retrait), on
ajoute un jeton CSRF en défense supplémentaire (double-submit cookie) via
`generate_csrf_token()` / `csrf_protect`, à appliquer sur ces routes précises
quand on les écrira.
"""
import logging
import secrets
from datetime import datetime, timedelta
from functools import wraps

import jwt
from flask import request, redirect, url_for, make_response, jsonify

from config import config
from db.supabase import sb_get_one, sb_patch

logger = logging.getLogger('flinpay.auth')

JWT_ALGORITHM = 'HS256'  # épinglé explicitement : ne jamais laisser PyJWT
                          # déduire l'algorithme depuis le token entrant, ce
                          # qui ouvrirait la porte à une attaque de confusion
                          # d'algorithme (ex: token signé avec 'none' ou avec
                          # une clé publique RSA passée comme secret HMAC).


# ── JWT ─────────────────────────────────────────────
def generate_user_token(user_id, email):
    payload = {
        'sub': str(user_id),
        'email': email,
        'type': 'user',
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=JWT_ALGORITHM)


def generate_pending_2fa_token(user_id):
    payload = {
        'sub': str(user_id),
        'type': 'pending_2fa',
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(minutes=10)
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token):
    try:
        return jwt.decode(token, config.JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as e:
        logger.debug(f"[verify_token] token invalide/expiré: {e}")
        return None


def _login_success_response(user):
    """Construit la réponse de connexion réussie (cookie + payload utilisateur)."""
    token = generate_user_token(user['id'], user['email'])
    resp = make_response(jsonify({'ok': True, 'user': {
        'firstname': user['firstname'],
        'lastname': user['lastname'],
        'email': user['email'],
        'company': user.get('company', ''),
        'phone': user.get('phone', ''),
        'country': user.get('country', ''),
        'plan': user.get('plan', 'starter')
    }}))
    resp.set_cookie(
        'fp_user_token', token,
        httponly=True,
        samesite='Lax',
        secure=config.IS_PRODUCTION,
        max_age=7 * 24 * 3600
    )
    return resp


# ── Décorateurs de protection des routes ────────────
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
        touch_last_seen(request.user_id)
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('fp_user_token')
        if not token:
            return redirect(url_for('login_page'))
        payload = verify_token(token)
        if not payload or payload.get('type') != 'user':
            return redirect(url_for('login_page'))
        # Le statut admin est vérifié en base à CHAQUE requête (pas dans le
        # JWT) : ça permet de révoquer immédiatement les droits admin d'un
        # compte sans attendre l'expiration du token (7 jours).
        user = sb_get_one('users', 'id', payload.get('sub'))
        if not user or not user.get('is_admin'):
            logger.warning(f"[admin_required] tentative d'accès admin refusée pour user={payload.get('sub')}")
            return redirect(url_for('login_page'))
        request.user_id = payload.get('sub')
        request.user_email = payload.get('email')
        return f(*args, **kwargs)
    return decorated


def touch_last_seen(user_id):
    try:
        sb_patch('users', 'id', user_id, {'last_seen_at': datetime.utcnow().isoformat()})
    except Exception as e:
        logger.debug(f"[touch_last_seen] échec non bloquant: {e}")


# ── Anti-bruteforce sur la connexion ─────────────────
def is_locked_out(user) -> bool:
    locked_until = user.get('locked_until')
    if not locked_until:
        return False
    try:
        lu = datetime.fromisoformat(locked_until.replace('Z', '+00:00')).replace(tzinfo=None)
        return datetime.utcnow() < lu
    except (ValueError, AttributeError):
        return False


def register_failed_login(user):
    """Incrémente le compteur d'échecs et verrouille le compte au-delà du
    seuil autorisé (config.LOGIN_MAX_ATTEMPTS)."""
    attempts = (user.get('failed_login_count') or 0) + 1
    update = {'failed_login_count': attempts}
    if attempts >= config.LOGIN_MAX_ATTEMPTS:
        update['locked_until'] = (datetime.utcnow() + timedelta(minutes=config.LOGIN_LOCKOUT_MINUTES)).isoformat()
        logger.warning(f"[register_failed_login] compte verrouillé après {attempts} échecs: user={user.get('id')}")
    sb_patch('users', 'id', user['id'], update)


def reset_failed_login(user_id):
    """Réinitialise le compteur d'échecs après une connexion réussie."""
    sb_patch('users', 'id', user_id, {'failed_login_count': 0, 'locked_until': None})


# ── CSRF (double-submit cookie) ──────────────────────
CSRF_COOKIE_NAME = 'fp_csrf_token'
CSRF_HEADER_NAME = 'X-CSRF-Token'


def generate_csrf_token(response):
    """Pose un cookie CSRF lisible en JS (donc PAS httponly — le frontend doit
    pouvoir le lire pour le renvoyer dans l'en-tête X-CSRF-Token). À appeler
    au moment du login, en plus de la pose du cookie de session."""
    token = secrets.token_urlsafe(32)
    response.set_cookie(
        CSRF_COOKIE_NAME, token,
        httponly=False,
        samesite='Lax',
        secure=config.IS_PRODUCTION,
        max_age=7 * 24 * 3600
    )
    return token


def csrf_protect(f):
    """Décorateur à empiler sur les routes les plus sensibles (changement de
    mot de passe, désactivation 2FA, demande de retrait...) EN PLUS de
    @user_required. Compare le cookie CSRF au header X-CSRF-Token envoyé par
    le frontend — un site tiers qui déclencherait une requête cross-site ne
    peut pas lire le cookie Flinpay pour le recopier dans ce header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
        header_token = request.headers.get(CSRF_HEADER_NAME)
        if not cookie_token or not header_token or not secrets.compare_digest(cookie_token, header_token):
            logger.warning(f"[csrf_protect] jeton CSRF manquant ou invalide sur {request.path}")
            return jsonify({'ok': False, 'error': 'Jeton de sécurité invalide, rechargez la page.'}), 403
        return f(*args, **kwargs)
    return decorated
