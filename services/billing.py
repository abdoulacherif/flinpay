import logging
import json
from datetime import datetime, timedelta

from db.supabase import sb_get_eq, sb_get_one, sb_post, sb_patch

from config import config

logger = logging.getLogger('flinpay.billing')


# ── Utilisateur ─────────────────────────────────────
def get_user_by_id(user_id):
    if not user_id:
        return None
    return sb_get_one('users', 'id', user_id)


# ── Devises / pays ──────────────────────────────────
def get_currency_for_country(country_code: str) -> str:
    for c in config.COUNTRIES:
        if c['code'] == country_code:
            return c['currency']
    return 'XOF'


# ── Soldes (colonne JSON `balances`) ────────────────
def _read_balances_raw(user: dict) -> dict:
    """Retourne le dict brut de la colonne `balances` (peut inclure des devises à 0).
    Gère le cas où Supabase renvoie la valeur comme string JSON."""
    if not user:
        return {}
    raw = user.get('balances')
    if not raw:
        return {}
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except (ValueError, TypeError):
            return {}
    return raw if isinstance(raw, dict) else {}


def get_balances(user: dict) -> dict:
    """Retourne {devise: montant} depuis la colonne `balances` (filtre > 0)."""
    if not user:
        return {}
    raw = user.get('balances')
    if not raw:
        return {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            return {}
    if not isinstance(raw, dict):
        return {}

    balances = {}
    for currency, val in raw.items():
        try:
            amount = float(val)
        except (TypeError, ValueError):
            continue
        if amount > 0:
            balances[currency] = amount
    return balances


def get_balance_for_currency(user: dict, currency: str) -> float:
    return get_balances(user).get(currency, 0.0)


def credit_user_balance(user_id: str, currency: str, amount: float):
    try:
        user = sb_get_one('users', 'id', user_id)
        if not user:
            return False
        balances = _read_balances_raw(user)
        current = float(balances.get(currency) or 0)
        balances[currency] = round(current + float(amount), 2)
        return sb_patch('users', 'id', user_id, {'balances': balances})
    except Exception as e:
        logger.error(f"[credit_user_balance] {e}")
        return False


def debit_user_balance(user_id: str, currency: str, amount: float):
    try:
        user = sb_get_one('users', 'id', user_id)
        if not user:
            return False
        balances = _read_balances_raw(user)
        current = float(balances.get(currency) or 0)
        new_val = round(current - float(amount), 2)
        if new_val < 0:
            new_val = 0
        balances[currency] = new_val
        return sb_patch('users', 'id', user_id, {'balances': balances})
    except Exception as e:
        logger.error(f"[debit_user_balance] {e}")
        return False


# ── Quotas mensuels ─────────────────────────────────
def get_monthly_transaction_count(user_id: str) -> int:
    try:
        start_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
        rows = sb_get_eq(
            'transactions', 'user_id', user_id,
            extra_query=f'created_at=gte.{start_of_month}&status=eq.paid'
        )
        return len(rows)
    except Exception as e:
        logger.error(f"[get_monthly_transaction_count] {e}")
        return 0


def check_quota(user_id: str) -> tuple:
    try:
        user = sb_get_one('users', 'id', user_id)
        if not user:
            return False, 'Compte introuvable'
        if user.get('plan') == 'pro':
            return True, None
        count = get_monthly_transaction_count(user_id)
        limit = config.FREE_PLAN_MONTHLY_LIMIT
        if count >= limit:
            return False, f'Quota mensuel atteint ({count}/{limit}). Passez au plan Pro pour continuer.'
        return True, None
    except Exception as e:
        logger.error(f"[check_quota] {e}")
        return True, None


# ── Marges (liens de paiement / API) ────────────────
def _apply_markup(base_amount: float, operator: str, percent_map: dict, flat_map: dict, default_percent: float, default_flat: float) -> float:
    percent = percent_map.get(operator, default_percent)
    flat = flat_map.get(operator, default_flat)
    return round(float(base_amount) * (1 + percent / 100.0) + flat, 2)


def amount_with_markup(base_amount: float, operator: str = '') -> float:
    return _apply_markup(
        base_amount, operator,
        config.LINK_MARKUP_BY_OPERATOR, config.LINK_MARKUP_FLAT_FEE_BY_OPERATOR,
        config.LINK_MARKUP_DEFAULT_PERCENT, config.LINK_MARKUP_DEFAULT_FLAT_FEE,
    )


def link_amount_with_markup(base_amount: float, operator: str = '') -> float:
    return _apply_markup(
        base_amount, operator,
        config.LINK_MARKUP_BY_OPERATOR, config.LINK_MARKUP_FLAT_FEE_BY_OPERATOR,
        config.LINK_MARKUP_DEFAULT_PERCENT, config.LINK_MARKUP_DEFAULT_FLAT_FEE,
    )


def api_amount_with_markup(base_amount: float, operator: str = '') -> float:
    return _apply_markup(
        base_amount, operator,
        config.API_MARKUP_BY_OPERATOR, config.API_MARKUP_FLAT_FEE_BY_OPERATOR,
        config.API_MARKUP_DEFAULT_PERCENT, config.API_MARKUP_DEFAULT_FLAT_FEE,
    )


# ── Abonnement Pro ──────────────────────────────────
def get_subscription_price() -> float:
    return 8500.0


# ── Parrainage ──────────────────────────────────────
def ensure_referral_code(user: dict) -> str:
    if not user:
        return ''
    existing = user.get('referral_code')
    if existing:
        return existing

    import secrets
    for _ in range(5):
        code = 'FP' + secrets.token_hex(3).upper()
        if not sb_get_eq('users', 'referral_code', code):
            if sb_patch('users', 'id', user['id'], {'referral_code': code}):
                return code
    return ''


# ── Récompenses FP ──────────────────────────────────
FP_PER_XOF_COLLECTED = 0.004
FP_TO_XOF_RATE = 250.0


def compute_fp_reward(amount_collected_xof: float) -> float:
    try:
        amount = float(amount_collected_xof or 0)
    except (TypeError, ValueError):
        return 0.0
    if amount <= 0:
        return 0.0
    return round(amount * FP_PER_XOF_COLLECTED, 2)


def credit_fp_for_transaction(user_id: str, amount_xof: float, transaction_token: str):
    fp = compute_fp_reward(amount_xof)
    if fp <= 0:
        return 0.0

    try:
        existing = sb_get_eq('fp_history', 'transaction_token', transaction_token)
        if existing:
            return 0.0

        sb_post('fp_history', {
            'user_id': user_id,
            'amount_fp': fp,
            'source_amount': float(amount_xof),
            'source_currency': 'XOF',
            'transaction_token': transaction_token,
            'created_at': datetime.utcnow().isoformat(),
        })

        user = sb_get_one('users', 'id', user_id)
        if user:
            new_balance = float(user.get('fp_balance') or 0) + fp
            sb_patch('users', 'id', user_id, {'fp_balance': round(new_balance, 2)})

        return fp
    except Exception as e:
        logger.warning(f"[credit_fp_for_transaction] failed: {e}")
        return 0.0