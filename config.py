import os
import sys
from dotenv import load_dotenv

load_dotenv()


def _require(name: str) -> str:
    value = os.getenv(name)
    if not value:
        sys.stderr.write(
            f"\n[CONFIG] Variable d'environnement manquante : {name}\n"
            f"[CONFIG] L'application ne peut pas démarrer sans cette valeur.\n\n"
        )
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _optional(name: str, default: str = '') -> str:
    return os.getenv(name, default) or default


def _require_in_prod(name: str, default: str = '') -> str:
    value = os.getenv(name, default)
    if not value and os.getenv('FLASK_ENV', 'production').lower() == 'production':
        raise RuntimeError(f"Missing required environment variable in production: {name}")
    return value or default


class Config:
    # ── Environnement ───────────────────────────────
    ENV = os.getenv('FLASK_ENV', 'production').lower().strip()
    if ENV not in ('production', 'development', 'test'):
        raise RuntimeError(f"FLASK_ENV invalide : {ENV!r}")

    DEBUG = os.getenv('FLASK_DEBUG', 'false').lower() in ('1', 'true', 'yes')
    IS_PRODUCTION = ENV == 'production'

    if IS_PRODUCTION and DEBUG:
        raise RuntimeError("FLASK_DEBUG=true est interdit en production")

    # ── Secrets critiques ───────────────────────────
    SECRET_KEY = _require('SECRET_KEY')
    JWT_SECRET = _require('JWT_SECRET')
    SUPABASE_URL = _require('SUPABASE_URL')
    SUPABASE_KEY = _require('SUPABASE_KEY')
    SUPABASE_KEY_READONLY = _optional('SUPABASE_KEY_READONLY') or SUPABASE_KEY

    GATEWAY_CLIENT_ID = _require('GATEWAY_CLIENT_ID')
    GATEWAY_CLIENT_SECRET = _require('GATEWAY_CLIENT_SECRET')
    GATEWAY_MERCHANT_API_KEY = _optional('GATEWAY_MERCHANT_API_KEY')

    GATEWAY_ENVIRONMENT = _optional('GATEWAY_ENVIRONMENT', '').lower().strip()
    if IS_PRODUCTION:
        if GATEWAY_ENVIRONMENT != 'production':
            raise RuntimeError(
                f"GATEWAY_ENVIRONMENT doit valoir 'production' en production (actuel : {GATEWAY_ENVIRONMENT!r})"
            )
    elif GATEWAY_ENVIRONMENT not in ('sandbox', 'production'):
        GATEWAY_ENVIRONMENT = 'sandbox'

    for _name, _val, _min in [
        ('SECRET_KEY', SECRET_KEY, 32),
        ('JWT_SECRET', JWT_SECRET, 32),
        ('GATEWAY_CLIENT_SECRET', GATEWAY_CLIENT_SECRET, 16),
    ]:
        if len(_val) < _min:
            raise RuntimeError(f"{_name} doit faire au moins {_min} caractères")

    if not SUPABASE_URL.startswith('https://'):
        raise RuntimeError("SUPABASE_URL doit utiliser HTTPS")

    ADMIN_USERNAME = _optional('ADMIN_USERNAME')
    ADMIN_PASSWORD_HASH = _optional('ADMIN_PASSWORD_HASH')
    if IS_PRODUCTION and ADMIN_USERNAME and not ADMIN_PASSWORD_HASH:
        raise RuntimeError("ADMIN_PASSWORD_HASH est requis en production quand ADMIN_USERNAME est défini")

    LIMITER_STORAGE_URI = _require_in_prod('LIMITER_STORAGE_URI', default='memory://')
    if IS_PRODUCTION and LIMITER_STORAGE_URI == 'memory://':
        raise RuntimeError("LIMITER_STORAGE_URI ne doit pas être memory:// en production")

    LEEKPAY_SECRET_KEY = _optional('LEEKPAY_SECRET_KEY')
    LEEKPAY_PUBLIC_KEY = _optional('LEEKPAY_PUBLIC_KEY')
    LEEKPAY_API_BASE = 'https://leekpay.fr/api/v1'

    GATEWAY_BASE_URL = 'https://api.mysoleas.com'
    IDENTITY_BASE_URL = 'https://account.mysoleas.com'
    GATEWAY_MIN_AMOUNT = 100

    for _name, _url in [('GATEWAY_BASE_URL', GATEWAY_BASE_URL),
                        ('IDENTITY_BASE_URL', IDENTITY_BASE_URL)]:
        if not _url.startswith('https://'):
            raise RuntimeError(f"{_name} doit utiliser HTTPS")

    GATEWAY_FEES_DEDUCTED_FROM_MERCHANT = True

    EMAIL_ADDRESS = _optional('EMAIL_ADDRESS')
    EMAIL_APP_PASSWORD = _optional('EMAIL_APP_PASSWORD')

    # ── CORS (whitelist stricte) ────────────────────
    ALLOWED_ORIGINS = [
        'https://www.flinpay.cfd',
        'https://flinpay.cfd',
    ]
    # En dev, autorise localhost
    if not IS_PRODUCTION:
        ALLOWED_ORIGINS += ['http://localhost:5000', 'http://127.0.0.1:5000']

    # ── Hosts autorisés ─────────────────────────────
    # Les preview deployments Vercel utilisent des URLs dynamiques du type
    # flinpay-abc123-def456.vercel.app. On accepte tout sous-domaine *.vercel.app
    # ET les domaines Flinpay. Pas de wildcard général : seulement ce qui est
    # nécessaire pour le déploiement et la production.
    ALLOWED_HOSTS = {
        'www.flinpay.cfd',
        'flinpay.cfd',
    }

    # Ajout dynamique des preview Vercel si l'env var existe
    _extra_hosts = os.getenv('EXTRA_ALLOWED_HOSTS', '')
    if _extra_hosts:
        for _h in _extra_hosts.split(','):
            _h = _h.strip().lower()
            if _h:
                ALLOWED_HOSTS.add(_h)

    if not IS_PRODUCTION:
        ALLOWED_HOSTS |= {'localhost', '127.0.0.1'}

    # Préfixes/suffixes acceptés (pour *.vercel.app)
    # On garde une liste de suffixes et on vérifie côté app.py
    ALLOWED_HOST_SUFFIXES = ('.vercel.app',)

    # ── Cookies de session ──────────────────────────
    SESSION_COOKIE_SECURE = IS_PRODUCTION
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    SESSION_COOKIE_NAME = '__Host-fp_session'
    PERMANENT_SESSION_LIFETIME_SECONDS = 12 * 3600

    MAX_CONTENT_LENGTH = 12 * 1024 * 1024

    # ── Pays / devises ──────────────────────────────
    COUNTRIES = [
        {'code': 'CM', 'name': 'Cameroun', 'flag': '🇨🇲', 'currency': 'XAF'},
        {'code': 'CI', 'name': "Côte d'Ivoire", 'flag': '🇨🇮', 'currency': 'XOF'},
        {'code': 'BF', 'name': 'Burkina Faso', 'flag': '🇧🇫', 'currency': 'XOF'},
        {'code': 'BJ', 'name': 'Bénin', 'flag': '🇧🇯', 'currency': 'XOF'},
        {'code': 'TG', 'name': 'Togo', 'flag': '🇹🇬', 'currency': 'XOF'},
        {'code': 'CD', 'name': 'RDC', 'flag': '🇨🇩', 'currency': 'CDF'},
        {'code': 'GA', 'name': 'Gabon', 'flag': '🇬🇦', 'currency': 'XAF'},
    ]

    COUNTRY_ALPHA3 = {
        'CM': 'CMR', 'CI': 'CIV', 'BF': 'BFA', 'BJ': 'BEN',
        'TG': 'TGO', 'CD': 'COD', 'GA': 'GAB',
    }

    if set(COUNTRY_ALPHA3.keys()) != {c['code'] for c in COUNTRIES}:
        raise RuntimeError("COUNTRIES et COUNTRY_ALPHA3 désynchronisés")

    # ── Constantes métier ───────────────────────────
    FREE_PLAN_MONTHLY_LIMIT = 300
    PAYOUT_MIN_AMOUNT = 600
    PAYOUT_FEE_PERCENT = 3.5
    CONVERSION_FEE_PERCENT = 5.5
    REFERRAL_COMMISSION_RATE = 0.10

    LOGIN_MAX_ATTEMPTS = 5
    LOGIN_LOCKOUT_MINUTES = 15
    TOTP_FAILURE_WINDOW_MINUTES = 15

    LINK_MARKUP_DEFAULT_PERCENT = 5.0
    LINK_MARKUP_DEFAULT_FLAT_FEE = 150
    LINK_MARKUP_BY_OPERATOR = {}
    LINK_MARKUP_FLAT_FEE_BY_OPERATOR = {}

    API_MARKUP_DEFAULT_PERCENT = 5.0
    API_MARKUP_DEFAULT_FLAT_FEE = 150
    API_MARKUP_BY_OPERATOR = {}
    API_MARKUP_FLAT_FEE_BY_OPERATOR = {}

    for _name, _val in [
        ('LINK_MARKUP_DEFAULT_PERCENT', LINK_MARKUP_DEFAULT_PERCENT),
        ('API_MARKUP_DEFAULT_PERCENT', API_MARKUP_DEFAULT_PERCENT),
        ('CONVERSION_FEE_PERCENT', CONVERSION_FEE_PERCENT),
        ('PAYOUT_FEE_PERCENT', PAYOUT_FEE_PERCENT),
        ('REFERRAL_COMMISSION_RATE', REFERRAL_COMMISSION_RATE * 100),
    ]:
        if not (0 <= _val <= 30):
            raise RuntimeError(f"{_name} hors plage : {_val}")
    for _name, _val in [
        ('LINK_MARKUP_DEFAULT_FLAT_FEE', LINK_MARKUP_DEFAULT_FLAT_FEE),
        ('API_MARKUP_DEFAULT_FLAT_FEE', API_MARKUP_DEFAULT_FLAT_FEE),
    ]:
        if not (0 <= _val <= 10000):
            raise RuntimeError(f"{_name} hors plage : {_val}")


config = Config()