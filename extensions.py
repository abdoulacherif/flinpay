"""
Extensions Flask partagées : CORS, rate limiting, en-têtes de sécurité, logging.

Tout ce qui touche à la sécurité transversale (donc appliqué à CHAQUE requête,
peu importe la route) vit ici plutôt que dispersé dans app.py comme avant.
"""
import logging
from datetime import datetime

from flask import request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import config

# ── Logging ─────────────────────────────────────────
# Avant : le code utilisait `print()` partout, y compris pour journaliser des
# corps de réponse bruts d'API tierces (SoleasPay). En production, ça part dans
# des logs non structurés, jamais purgés, potentiellement exposés. On passe au
# module `logging` standard avec un niveau configurable, et on interdit
# formellement de logger un corps de réponse en entier (voir services/).
logging.basicConfig(
    level=logging.DEBUG if config.DEBUG else logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('flinpay')

if config.DEBUG:
    logger.warning(
        "FLASK_DEBUG est activé — ne JAMAIS déployer avec cette valeur en "
        "production (le debugger Flask permet l'exécution de code arbitraire "
        "si l'appli plante et que le debugger est exposé publiquement)."
    )


def get_client_ip() -> str:
    """Récupère l'IP réelle du visiteur à partir de X-Forwarded-For.

    Important : ceci ne doit être fiable QUE si l'application tourne derrière
    un proxy de confiance qui écrase cet en-tête lui-même (Render, Heroku,
    Nginx bien configuré...). Voir app.py où ProxyFix est appliqué — sans ça,
    n'importe quel client peut usurper son IP en envoyant son propre en-tête
    X-Forwarded-For, ce qui casserait le rate-limiting et le verrouillage anti-
    bruteforce basés dessus.
    """
    ip = request.headers.get('x-forwarded-for', request.remote_addr or '')
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()
    return ip or 'unknown'


# ── CORS ────────────────────────────────────────────
def init_cors(app):
    """CORS restreint à la liste blanche définie dans config.py. On ne met
    JAMAIS '*' ici : ce site gère de l'argent, un wildcard permettrait à
    n'importe quel site tiers de faire des requêtes authentifiées via cookie
    au nom d'un utilisateur connecté."""
    CORS(app, origins=config.ALLOWED_ORIGINS, supports_credentials=True)


# ── Rate limiting ───────────────────────────────────
# Limite globale par défaut + limites spécifiques posées directement sur les
# routes sensibles (login, paiement, webhooks) dans leurs blueprints respectifs
# via le décorateur @limiter.limit(...). Stockage en mémoire par défaut : pour
# un déploiement multi-instances, configurer LIMITER_STORAGE_URI vers Redis
# pour que la limite soit partagée entre tous les workers.
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=['200 per minute', '3000 per hour'],
    storage_uri='memory://',
)


def init_limiter(app):
    limiter.init_app(app)


# ── En-têtes de sécurité ────────────────────────────
def init_security_headers(app):
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        response.headers['X-XSS-Protection'] = '0'  # obsolète et parfois contre-productif ; CSP fait le travail

        if config.IS_PRODUCTION:
            response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'

        # Les pages de paiement et de facture doivent pouvoir être intégrées en
        # iframe par le widget "Payer avec Flinpay" (voir /widget.js) — on ne
        # restreint donc pas leur frame-ancestors. Tout le reste du site refuse
        # d'être affiché dans une iframe externe (protection anti-clickjacking).
        if request.path.startswith('/pay/') or request.path.startswith('/invoice/'):
            response.headers['Content-Security-Policy'] = "frame-ancestors *"
        else:
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['Content-Security-Policy'] = "frame-ancestors 'self'"

        # Les réponses contenant des données de compte (solde, transactions...)
        # ne doivent jamais être mises en cache par le navigateur ou un proxy
        # intermédiaire partagé.
        if request.path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-store'

        return response


# ── Contexte des templates ──────────────────────────
def init_template_helpers(app):
    @app.context_processor
    def inject_globals():
        return {'current_year': datetime.utcnow().year}

    @app.template_filter('split')
    def split_filter(value, sep=','):
        return (value or '').split(sep)


def init_extensions(app):
    init_cors(app)
    init_limiter(app)
    init_security_headers(app)
    init_template_helpers(app)
