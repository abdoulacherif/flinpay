"""
services/fx.py — conversion entre devises.

XAF et XOF sont à parité fixe 1:1 (BEAC / BCEAO).
Toute autre paire (notamment CDF, GHS, NGN) est convertie via open.er-api.com
(gratuit, sans clé) avec un cache de 1h. Si l'API est indisponible, un taux
de secours fixe est utilisé (FALLBACK_RATES) pour ne pas bloquer l'utilisateur,
mais un warning est loggé pour que tu saches quand la mise à jour automatique
échoue.
"""

import logging
import time

import requests

logger = logging.getLogger('flinpay.fx')

# Parités fixes garanties (franc CFA)
_FIXED_PARITIES = {
    ('XAF', 'XOF'): 1.0,
    ('XOF', 'XAF'): 1.0,
}

# Taux de secours si l'API externe est down. À ajuster manuellement de temps
# en temps si les taux dérivent (1 XOF ≈ 4.75 CDF aujourd'hui, mais ça bouge).
FALLBACK_RATES = {
    ('XOF', 'CDF'): 4.75,
    ('CDF', 'XOF'): 0.21,
    ('XAF', 'CDF'): 4.75,
    ('CDF', 'XAF'): 0.21,
}

_CACHE = {}
_CACHE_TTL = 3600  # 1 heure


def _fetch_rates(base_currency: str) -> dict:
    """Récupère les taux depuis open.er-api.com (gratuit)."""
    now = time.time()
    cached = _CACHE.get(base_currency)
    if cached and (now - cached['ts']) < _CACHE_TTL:
        return cached['rates']

    try:
        r = requests.get(
            f'https://open.er-api.com/v6/latest/{base_currency}',
            timeout=5
        )
        data = r.json()
        rates = data.get('rates') or {}
        if rates:
            _CACHE[base_currency] = {'ts': now, 'rates': rates}
            return rates
        logger.warning(f"[fx] API returned no rates for {base_currency}")
        return {}
    except Exception as e:
        logger.warning(f"[fx] API error for base {base_currency}: {e}")
        return {}


def can_convert(from_currency: str, to_currency: str) -> bool:
    from_currency = (from_currency or '').upper()
    to_currency = (to_currency or '').upper()
    if from_currency == to_currency:
        return True
    if (from_currency, to_currency) in _FIXED_PARITIES:
        return True
    # Une paire est convertible si l'API renvoie un taux ou si on a un fallback
    if (from_currency, to_currency) in FALLBACK_RATES:
        return True
    rates = _fetch_rates(from_currency)
    return bool(rates.get(to_currency))


def convert(amount: float, from_currency: str, to_currency: str):
    """Retourne le montant converti, ou None si la paire n'est pas prise en
    charge. Ne devine jamais un taux — mais couvre les paires CDF via API
    externe ou fallback."""
    from_currency = (from_currency or '').upper()
    to_currency = (to_currency or '').upper()

    if from_currency == to_currency:
        return round(float(amount), 2)

    # 1. Parité fixe CFA
    fixed = _FIXED_PARITIES.get((from_currency, to_currency))
    if fixed is not None:
        return round(float(amount) * fixed, 2)

    # 2. Taux API live
    rates = _fetch_rates(from_currency)
    rate = rates.get(to_currency)
    if rate:
        return round(float(amount) * rate, 2)

    # 3. Fallback fixe (API down ou paire non listée)
    fallback = FALLBACK_RATES.get((from_currency, to_currency))
    if fallback is not None:
        logger.info(f"[fx] fallback used {from_currency}->{to_currency} = {fallback}")
        return round(float(amount) * fallback, 2)

    # 4. Vraiment aucune option
    logger.warning(f"[fx] no rate available for {from_currency}->{to_currency}")
    return None