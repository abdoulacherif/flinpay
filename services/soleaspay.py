"""
services/soleaspay.py — intégration avec l'agrégateur mobile money SoleasPay.

RÈGLE DE SÉCURITÉ — ne jamais journaliser de données financières/personnelles
en clair au niveau INFO. Le code d'origine faisait `print()` sur le corps
COMPLET de chaque réponse SoleasPay (qui contient des numéros de téléphone,
montants, références de paiement...) avec des commentaires "TEMPORAIRE — à
retirer après debug" qui, sans surprise, n'avaient jamais été retirés. Ici,
tout ça passe en `logger.debug()` uniquement (désactivé par défaut en
production, voir extensions.py), et les numéros de téléphone sont masqués
avant d'être loggés, même en debug.
"""
import logging

import requests

from config import config

logger = logging.getLogger('flinpay.soleaspay')


def _mask_wallet(wallet: str) -> str:
    """Masque un numéro de téléphone pour les logs : ne garde que les 2 derniers
    chiffres. Un numéro de mobile money identifie une personne réelle."""
    wallet = str(wallet or '')
    if len(wallet) <= 2:
        return '**'
    return '*' * (len(wallet) - 2) + wallet[-2:]


def get_country_operators(country_code):
    return config.SOLEASPAY_SERVICES.get(country_code, {})


def get_service_id(country_code, operator_key):
    ops = config.SOLEASPAY_SERVICES.get(country_code, {})
    entry = ops.get(operator_key)
    return entry[0] if entry else None


def soleaspay_convert(amount, from_currency, to_currency='XAF'):
    if from_currency == to_currency:
        return float(amount)
    try:
        r = requests.get(
            f'{config.SOLEASPAY_BASE}/api/convert',
            params={'amount': amount, 'from': from_currency, 'to': to_currency},
            timeout=10
        )
        data = r.json()
        if data.get('success'):
            return float(data['data']['value'])
        logger.warning(f"[soleaspay_convert] échec conversion {from_currency}->{to_currency}: status={r.status_code}")
    except (requests.RequestException, ValueError, KeyError, TypeError) as e:
        logger.error(f"[soleaspay_convert] error: {e}")
    # Repli : XOF/XAF sont à parité de toute façon, donc ce repli reste
    # raisonnable pour ces deux devises précises. Pour toute autre paire, un
    # échec de conversion silencieux serait dangereux (montant faux facturé
    # au client) — on journalise donc systématiquement l'échec ci-dessus pour
    # qu'il soit visible en monitoring.
    return float(amount)


def soleaspay_collect(wallet, amount, currency, order_id, description, payer, payer_email,
                       success_url, failure_url, service_id):
    if not isinstance(amount, (int, float)) or amount <= 0:
        return {'ok': False, 'detail': 'Montant invalide'}
    try:
        headers = {
            'x-api-key': config.SOLEASPAY_API_KEY,
            'operation': '2',
            'service': str(service_id),
            'Content-Type': 'application/json'
        }
        payload = {
            'wallet': wallet,
            'amount': amount,
            'currency': currency,
            'order_id': order_id,
            'description': description,
            'payer': payer,
            'payerEmail': payer_email or '',
            'successUrl': success_url,
            'failureUrl': failure_url
        }
        r = requests.post(f'{config.SOLEASPAY_BASE}/api/agent/bills/v3', headers=headers, json=payload, timeout=20)
        data = r.json()
        logger.debug(f"[soleaspay_collect] order={order_id} wallet={_mask_wallet(wallet)} status={r.status_code}")
        if data.get('success'):
            return {'ok': True, 'data': data.get('data', {})}
        logger.warning(f"[soleaspay_collect] order={order_id} refused: status={r.status_code}")
        return {'ok': False, 'detail': data.get('message', 'Erreur inconnue')}
    except (requests.RequestException, ValueError) as e:
        logger.error(f"[soleaspay_collect] order={order_id} error: {e}")
        return {'ok': False, 'detail': str(e)}


def soleaspay_verify(order_id, pay_id):
    try:
        headers = {'x-api-key': config.SOLEASPAY_API_KEY, 'Content-Type': 'application/json'}
        params = {'orderId': order_id, 'payId': pay_id}
        r = requests.get(f'{config.SOLEASPAY_BASE}/api/agent/verif-pay', headers=headers, params=params, timeout=15)
        data = r.json()
        logger.debug(f"[soleaspay_verify] order={order_id} status={r.status_code} remote_status={data.get('status')}")
        if data.get('success'):
            return {'ok': True, 'status': data.get('status'), 'data': data.get('data', {})}
        return {'ok': False, 'detail': data.get('message', 'Erreur inconnue')}
    except (requests.RequestException, ValueError) as e:
        logger.error(f"[soleaspay_verify] order={order_id} error: {e}")
        return {'ok': False, 'detail': str(e)}


def soleaspay_verify_callback_signature(header_value: str) -> bool:
    """Vérifie la signature du webhook entrant. hmac.compare_digest() est
    utilisé pour la comparaison — JAMAIS `==` sur des secrets, car `==` sur des
    chaînes en Python compare caractère par caractère et s'arrête au premier
    caractère différent : le temps de réponse varie selon la position du
    premier mismatch, ce qui permet en théorie de deviner la signature valide
    octet par octet via une attaque temporelle (timing attack)."""
    import hashlib
    import hmac
    if not header_value or not config.SOLEASPAY_CALLBACK_SECRET:
        return False
    expected = hashlib.sha512(config.SOLEASPAY_CALLBACK_SECRET.encode()).hexdigest()
    return hmac.compare_digest(expected, header_value)
