"""
services/billing.py — tout ce qui touche à l'argent du marchand : soldes par
devise, marges appliquées aux paiements, quotas du plan gratuit, parrainage.

AVERTISSEMENT IMPORTANT — condition de course sur les soldes
------------------------------------------------------------
`credit_user_balance` / `debit_user_balance` suivent un pattern
lire-modifier-écrire (lire le solde JSON, calculer le nouveau montant, le
réécrire en entier). Ce pattern N'EST PAS atomique : si deux requêtes
modifient le solde du même utilisateur en même temps (par exemple un webhook
SoleasPay qui crédite un paiement au même instant qu'une vérification
manuelle qui fait la même chose, ou deux retraits admin lancés à quelques
millisecondes d'intervalle), l'une des deux écritures peut écraser l'autre —
un crédit ou un débit peut silencieusement disparaître. C'est un risque réel
sur un système qui gère de l'argent.

Le code applicatif limite déjà une partie du risque ailleurs (sb_patch_if_pending
empêche le double-crédit d'une même transaction en la marquant atomiquement
'paid' une seule fois), mais le solde lui-même reste vulnérable si deux
opérations *différentes* arrivent en même temps.

Correctif recommandé (hors périmètre de ce fichier, nécessite un accès au
schéma Supabase) : remplacer ces deux fonctions par un appel RPC vers une
fonction Postgres qui fait l'incrément en une seule opération atomique côté
base de données, par exemple :

    create or replace function increment_balance(p_user_id uuid, p_currency text, p_delta numeric)
    returns void as $$
      update users
      set balances = jsonb_set(
        coalesce(balances, '{}'::jsonb),
        array[p_currency],
        to_jsonb(coalesce((balances->>p_currency)::numeric, 0) + p_delta)
      )
      where id = p_user_id;
    $$ language sql;

et appelée via `POST /rest/v1/rpc/increment_balance`. Tant que ce n'est pas
fait, le risque décrit ci-dessus reste présent.
"""
import logging
import secrets
from datetime import datetime

from config import config
from db.supabase import sb_get, sb_get_eq, sb_get_one, sb_patch, sb_count

logger = logging.getLogger('flinpay.billing')

VALID_CURRENCIES = {c['currency'] for c in config.COUNTRIES}


def get_user_by_id(user_id):
    return sb_get_one('users', 'id', user_id) or {}


def get_currency_for_country(country_code):
    return next((c['currency'] for c in config.COUNTRIES if c['code'] == country_code), 'XOF')


# ── Soldes ──────────────────────────────────────────
def get_balances(user):
    """Retourne le dict des soldes par devise, ex: {'XAF': 1200, 'XOF': 500}."""
    return user.get('balances') or {}


def get_balance_for_currency(user, currency):
    return float(get_balances(user).get(currency) or 0)


def credit_user_balance(user_id, currency, amount):
    """Crédite la poche de solde correspondant à une devise précise, sans
    toucher aux autres. Voir l'avertissement en tête de fichier sur la
    condition de course. `amount` doit toujours être positif ici — un montant
    négatif passé par erreur ferait un débit déguisé en crédit."""
    if currency not in VALID_CURRENCIES:
        logger.error(f"[credit_user_balance] devise inconnue rejetée: {currency!r} pour user={user_id}")
        return False
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        logger.error(f"[credit_user_balance] montant invalide pour user={user_id}: {amount!r}")
        return False
    if amount < 0:
        logger.error(f"[credit_user_balance] montant négatif rejeté (utilisez debit_user_balance) pour user={user_id}")
        return False
    user = get_user_by_id(user_id)
    balances = get_balances(user)
    balances[currency] = round(float(balances.get(currency) or 0) + amount, 2)
    return sb_patch('users', 'id', user_id, {'balances': balances})


def debit_user_balance(user_id, currency, amount):
    if currency not in VALID_CURRENCIES:
        logger.error(f"[debit_user_balance] devise inconnue rejetée: {currency!r} pour user={user_id}")
        return False
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        logger.error(f"[debit_user_balance] montant invalide pour user={user_id}: {amount!r}")
        return False
    if amount < 0:
        logger.error(f"[debit_user_balance] montant négatif rejeté pour user={user_id}")
        return False
    user = get_user_by_id(user_id)
    balances = get_balances(user)
    balances[currency] = round(float(balances.get(currency) or 0) - amount, 2)
    return sb_patch('users', 'id', user_id, {'balances': balances})


# ── Quotas (plan Starter vs Pro) ─────────────────────
def get_monthly_transaction_count(user_id):
    first_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    return sb_count('transactions', f'user_id=eq.{user_id}&created_at=gte.{first_of_month}')


def check_quota(user_id):
    """Retourne (autorisé, message_erreur_ou_None)."""
    user = get_user_by_id(user_id)
    if user.get('plan') == 'pro':
        return True, None
    count = get_monthly_transaction_count(user_id)
    if count >= config.FREE_PLAN_MONTHLY_LIMIT:
        return False, (
            f"Limite de {config.FREE_PLAN_MONTHLY_LIMIT} transactions/mois atteinte "
            f"sur le plan Starter. Passez au plan Pro pour un accès illimité."
        )
    return True, None


# ── Marges ────────────────────────────────────────────
def get_markup_percent():
    row = sb_get_one('site_config', 'key', 'markup_percent')
    if row:
        try:
            return float(row['value'])
        except (TypeError, ValueError, KeyError):
            pass
    return 2.5


def get_subscription_price():
    row = sb_get_one('site_config', 'key', 'subscription_price')
    if row:
        try:
            return float(row['value'])
        except (TypeError, ValueError, KeyError):
            pass
    return 8500.0


def amount_with_markup(base_amount):
    """Montant à envoyer au prestataire : le prix du marchand + notre marge,
    pour que le client final paie le surplus au lieu que ce soit déduit du
    solde du marchand."""
    return round(float(base_amount) * (1 + get_markup_percent() / 100), 2)


def get_link_markup_percent(operator_key):
    return config.LINK_MARKUP_BY_OPERATOR.get(operator_key, config.LINK_MARKUP_DEFAULT_PERCENT)


def get_link_markup_flat_fee(operator_key):
    return config.LINK_MARKUP_FLAT_FEE_BY_OPERATOR.get(operator_key, config.LINK_MARKUP_DEFAULT_FLAT_FEE)


def link_amount_with_markup(base_amount, operator_key):
    pct = get_link_markup_percent(operator_key)
    flat = get_link_markup_flat_fee(operator_key)
    return round(float(base_amount) * (1 + pct / 100) + flat, 2)


def get_api_markup_percent(operator_key):
    return config.API_MARKUP_BY_OPERATOR.get(operator_key, config.API_MARKUP_DEFAULT_PERCENT)


def get_api_markup_flat_fee(operator_key):
    return config.API_MARKUP_FLAT_FEE_BY_OPERATOR.get(operator_key, config.API_MARKUP_DEFAULT_FLAT_FEE)


def api_amount_with_markup(base_amount, operator_key):
    pct = get_api_markup_percent(operator_key)
    flat = get_api_markup_flat_fee(operator_key)
    return round(float(base_amount) * (1 + pct / 100) + flat, 2)


# ── Parrainage ────────────────────────────────────────
def generate_referral_code():
    return 'FP' + secrets.token_hex(3).upper()


def ensure_referral_code(user):
    if user.get('referral_code'):
        return user['referral_code']
    code = generate_referral_code()
    for _ in range(5):
        if not sb_get_eq('users', 'referral_code', code):
            break
        code = generate_referral_code()
    sb_patch('users', 'id', user['id'], {'referral_code': code})
    return code
