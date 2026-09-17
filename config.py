"""
Configuration centralisée de Flinpay.

Règle de sécurité n°1 de ce fichier : on ne démarre JAMAIS l'application avec un
secret manquant ou une valeur par défaut faible. Avant, `app.py` faisait
`os.getenv('JWT_SECRET')` sans aucune vérification — si la variable d'env était
absente (mauvais déploiement, .env oublié...), JWT_SECRET valait `None` et
l'application démarrait quand même, avec un système de session cassé de façon
silencieuse. Ici, ça plante au démarrage avec un message clair, ce qui est
exactement ce qu'on veut pour une variable qui protège l'argent de vrais
utilisateurs.
"""
import os
import sys
from dotenv import load_dotenv

load_dotenv()


def _require(name: str) -> str:
    """Lève une erreur explicite et arrête le démarrage si une variable
    d'environnement critique est absente. Mieux vaut un crash au déploiement
    qu'une clé JWT ou un secret webhook vide en production."""
    value = os.getenv(name)
    if not value:
        sys.stderr.write(
            f"\n[CONFIG] Variable d'environnement manquante : {name}\n"
            f"[CONFIG] L'application ne peut pas démarrer sans cette valeur "
            f"(elle protège des données ou des fonds utilisateurs).\n\n"
        )
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _optional(name: str, default: str = '') -> str:
    return os.getenv(name, default)


class Config:
    # ── Environnement ──────────────────────────────
    ENV = os.getenv('FLASK_ENV', 'production')
    DEBUG = os.getenv('FLASK_DEBUG', 'false').lower() in ('1', 'true', 'yes')
    IS_PRODUCTION = ENV == 'production'

    # ── Secrets critiques (obligatoires) ───────────
    # Si l'une de ces lignes lève une exception, c'est volontaire : ne jamais
    # faire tourner Flinpay sans ces valeurs correctement configurées.
    SECRET_KEY = _require('SECRET_KEY')
    JWT_SECRET = _require('JWT_SECRET')
    SUPABASE_URL = _require('SUPABASE_URL')
    SUPABASE_KEY = _require('SUPABASE_KEY')
    SOLEASPAY_API_KEY = _require('SOLEASPAY_API_KEY')
    SOLEASPAY_CALLBACK_SECRET = _require('SOLEASPAY_CALLBACK_SECRET')

    # ── Garde-fou supplémentaire : longueur minimale des secrets ──
    # Un secret JWT de 4 caractères techniquement "présent" reste catastrophique.
    for _name, _val, _min_len in [
        ('SECRET_KEY', SECRET_KEY, 32),
        ('JWT_SECRET', JWT_SECRET, 32),
        ('SOLEASPAY_CALLBACK_SECRET', SOLEASPAY_CALLBACK_SECRET, 16),
    ]:
        if len(_val) < _min_len:
            sys.stderr.write(
                f"\n[CONFIG] {_name} fait moins de {_min_len} caractères — "
                f"trop court pour être un secret cryptographique sûr. "
                f"Générez-en un nouveau, par exemple avec :\n"
                f"    python -c \"import secrets; print(secrets.token_hex(32))\"\n\n"
            )
            raise RuntimeError(f"{_name} is too short to be a secure secret")

    # ── Secrets optionnels (fonctionnalités dégradables) ───
    # Ces intégrations sont importantes mais pas vitales au démarrage : si elles
    # manquent, on veut que l'app tourne quand même (KYC, connexion, paiements de
    # base restent fonctionnels) — seule la fonctionnalité concernée est coupée.
    ADMIN_USERNAME = _optional('ADMIN_USERNAME')
    ADMIN_PASSWORD = _optional('ADMIN_PASSWORD')

    LEEKPAY_SECRET_KEY = _optional('LEEKPAY_SECRET_KEY')
    LEEKPAY_PUBLIC_KEY = _optional('LEEKPAY_PUBLIC_KEY')
    LEEKPAY_API_BASE = 'https://leekpay.fr/api/v1'

    SOLEASPAY_BASE = 'https://soleaspay.com'
    SOLEASPAY_MIN_AMOUNT = 100  # XAF/XOF — en dessous, SoleasPay refuse la transaction

    EMAIL_ADDRESS = _optional('EMAIL_ADDRESS')
    EMAIL_APP_PASSWORD = _optional('EMAIL_APP_PASSWORD')

    # ── CORS : liste blanche stricte, jamais de wildcard ───
    ALLOWED_ORIGINS = [
        'https://www.flinpay.cfd',
        'https://flinpay.cfd',
        'https://flinpay.vercel.app',
    ]

    # ── Cookies de session ──────────────────────────
    # Secure=True bloque l'envoi du cookie de session en clair sur HTTP — on ne
    # le force que hors dev local, pour ne pas casser un environnement de test
    # qui tournerait sans HTTPS.
    SESSION_COOKIE_SECURE = IS_PRODUCTION
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # ── Pays et opérateurs mobile money couverts ────
    COUNTRIES = [
        {'code': 'CM', 'name': 'Cameroun', 'flag': '🇨🇲', 'currency': 'XAF'},
        {'code': 'CI', 'name': "Côte d'Ivoire", 'flag': '🇨🇮', 'currency': 'XOF'},
        {'code': 'BF', 'name': 'Burkina Faso', 'flag': '🇧🇫', 'currency': 'XOF'},
        {'code': 'BJ', 'name': 'Bénin', 'flag': '🇧🇯', 'currency': 'XOF'},
        {'code': 'TG', 'name': 'Togo', 'flag': '🇹🇬', 'currency': 'XOF'},
        {'code': 'CD', 'name': 'RDC', 'flag': '🇨🇩', 'currency': 'CDF'},
        {'code': 'GA', 'name': 'Gabon', 'flag': '🇬🇦', 'currency': 'XAF'},
    ]

    # Services réellement actifs chez SoleasPay par pays (vérifié via /api/services-list).
    # format : code_pays -> { clé_opérateur: (service_id, libellé) }
    SOLEASPAY_SERVICES = {
        'CM': {'momo': (1, 'MTN Mobile Money'), 'om': (2, 'Orange Money')},
        'CI': {'om': (29, 'Orange Money'), 'momo': (30, 'MTN Money'), 'moov': (31, 'Moov Money'), 'wave': (32, 'Wave')},
        'BF': {'moov': (33, 'Moov Money'), 'om': (34, 'Orange Money')},
        'BJ': {'momo': (35, 'MTN Money'), 'moov': (36, 'Moov Money')},
        'TG': {'tmoney': (37, 'T-Money'), 'moov': (38, 'Moov Money')},
        'CD': {'vodacom': (52, 'Vodacom M-Pesa'), 'airtel': (53, 'Airtel Money'), 'om': (54, 'Orange Money')},
        'GA': {'airtel': (57, 'Airtel Money')},
    }

    # ── Constantes métier (plans, quotas, retraits) ─
    FREE_PLAN_MONTHLY_LIMIT = 300
    PAYOUT_MIN_AMOUNT = 600
    PAYOUT_FEE_PERCENT = 3.5
    CONVERSION_FEE_PERCENT = 5.5
    REFERRAL_COMMISSION_RATE = 0.10

    # ── Anti-bruteforce connexion ───────────────────
    LOGIN_MAX_ATTEMPTS = 5
    LOGIN_LOCKOUT_MINUTES = 15

    # ── Marges (liens de paiement / API directe) ────
    LINK_MARKUP_DEFAULT_PERCENT = 5.0
    LINK_MARKUP_DEFAULT_FLAT_FEE = 150
    LINK_MARKUP_BY_OPERATOR = {}
    LINK_MARKUP_FLAT_FEE_BY_OPERATOR = {}

    API_MARKUP_DEFAULT_PERCENT = 5.0
    API_MARKUP_DEFAULT_FLAT_FEE = 150
    API_MARKUP_BY_OPERATOR = {}
    API_MARKUP_FLAT_FEE_BY_OPERATOR = {}


config = Config()
