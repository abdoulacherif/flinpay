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
    # ── Passerelle de paiement (ex-SoleasPay, aujourd'hui l'écosystème
    # Mysoleas). Ce nom n'apparaît jamais côté utilisateur — voir
    # services/gateway.py — mais reste nécessaire ici en interne.
    GATEWAY_CLIENT_ID = _require('GATEWAY_CLIENT_ID')
    GATEWAY_CLIENT_SECRET = _require('GATEWAY_CLIENT_SECRET')
    # Optionnelle : uniquement utilisée pour la vérification de numéro de
    # téléphone (/phone-numbers/verify), qui s'authentifie par clé API et non
    # par JWT. Fonctionnalité de confort — dégradable si absente.
    GATEWAY_MERCHANT_API_KEY = _optional('GATEWAY_MERCHANT_API_KEY')

    # ── Garde-fou supplémentaire : longueur minimale des secrets ──
    # Un secret JWT de 4 caractères techniquement "présent" reste catastrophique.
    for _name, _val, _min_len in [
        ('SECRET_KEY', SECRET_KEY, 32),
        ('JWT_SECRET', JWT_SECRET, 32),
        ('GATEWAY_CLIENT_SECRET', GATEWAY_CLIENT_SECRET, 16),
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

    # ── Domaines de la passerelle (voir services/gateway.py) ────
    GATEWAY_BASE_URL = 'https://api.mysoleas.com'
    IDENTITY_BASE_URL = 'https://account.mysoleas.com'
    GATEWAY_MIN_AMOUNT = 100  # plancher de sécurité ; le vrai minimum dépend du service (catalogue)

    # RÈGLE FINANCIÈRE IMPORTANTE — voir services/gateway.py::compute_customer_charge.
    # Faute de pouvoir lire la configuration réelle de feeBearer sur le
    # dashboard Mysoleas, on part du principe (confirmé par le comportement de
    # l'ancienne intégration) que les frais du prestataire sont déduits de ce
    # que Flinpay reçoit. Le code se couvre donc lui-même en les ajoutant au
    # montant demandé au client, en se basant sur le devis réel
    # (/transactions/fees/quote) plutôt qu'un pourcentage estimé à l'aveugle.
    # À repasser à False seulement après avoir confirmé avec Mysoleas que
    # feeBearer=CUSTOMER est actif sur l'application (sinon double-facturation
    # du client).
    GATEWAY_FEES_DEDUCTED_FROM_MERCHANT = True

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

    # Correspondance code pays interne (ISO alpha-2, utilisé dans nos URLs et
    # notre base de données) -> code ISO alpha-3 attendu par la passerelle.
    # La liste des services actifs n'est plus codée en dur ici : elle est
    # désormais interrogée en direct (avec cache court) via
    # services/gateway.list_services(), car elle peut changer côté
    # prestataire sans que nous ayons à redéployer.
    COUNTRY_ALPHA3 = {
        'CM': 'CMR', 'CI': 'CIV', 'BF': 'BFA', 'BJ': 'BEN',
        'TG': 'TGO', 'CD': 'COD', 'GA': 'GAB',
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
