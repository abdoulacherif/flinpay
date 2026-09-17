"""
services/leekpay.py — intégration LeekPay (utilisée en complément de SoleasPay).

LEEKPAY_SECRET_KEY / LEEKPAY_PUBLIC_KEY sont optionnels (voir config.py) :
cette intégration peut être absente d'un déploiement sans empêcher le reste de
l'application de fonctionner. Chaque fonction vérifie donc explicitement que
la configuration est présente avant d'appeler l'API externe, plutôt que
d'envoyer une requête avec une clé `None`/vide qui échouerait de façon
confuse côté LeekPay.
"""
import hashlib
import hmac
import logging

import requests

from config import config

logger = logging.getLogger('flinpay.leekpay')


def _leekpay_configured() -> bool:
    return bool(config.LEEKPAY_SECRET_KEY)


def leekpay_create_checkout(amount, description, return_url=None, cancel_url=None,
                             customer_name=None, customer_phone=None, customer_email=None,
                             webhook_url=None, metadata=None):
    if not _leekpay_configured():
        logger.error("[leekpay_create_checkout] LEEKPAY_SECRET_KEY non configurée")
        return {'ok': False, 'detail': 'LeekPay non configuré sur ce déploiement'}
    if not isinstance(amount, (int, float)) or amount <= 0:
        return {'ok': False, 'detail': 'Montant invalide'}
    try:
        payload = {
            'amount': amount,
            'currency': 'XOF',
            'description': (description or '')[:500]
        }
        if return_url: payload['return_url'] = return_url
        if cancel_url: payload['cancel_url'] = cancel_url
        if customer_name: payload['customer_name'] = customer_name
        if customer_phone: payload['customer_phone'] = customer_phone
        if customer_email: payload['customer_email'] = customer_email
        if webhook_url: payload['webhook_url'] = webhook_url
        if metadata: payload['metadata'] = metadata

        r = requests.post(
            f'{config.LEEKPAY_API_BASE}/checkout',
            headers={
                'Authorization': f'Bearer {config.LEEKPAY_SECRET_KEY}',
                'Content-Type': 'application/json'
            },
            json=payload, timeout=15
        )
        if r.status_code == 201 and r.json().get('success'):
            return {'ok': True, 'data': r.json()['data']}
        logger.warning(f"[leekpay_create_checkout] failed: status={r.status_code}")
        return {'ok': False, 'detail': r.text[:300]}
    except (requests.RequestException, ValueError) as e:
        logger.error(f"[leekpay_create_checkout] error: {e}")
        return {'ok': False, 'detail': str(e)}


def leekpay_get_checkout(checkout_id):
    if not _leekpay_configured():
        return {'ok': False, 'detail': 'LeekPay non configuré sur ce déploiement'}
    try:
        r = requests.get(
            f'{config.LEEKPAY_API_BASE}/checkout/{checkout_id}',
            headers={'Authorization': f'Bearer {config.LEEKPAY_SECRET_KEY}'},
            timeout=10
        )
        if r.ok:
            return {'ok': True, 'data': r.json().get('data', {})}
        return {'ok': False, 'detail': r.text[:300]}
    except (requests.RequestException, ValueError) as e:
        logger.error(f"[leekpay_get_checkout] error: {e}")
        return {'ok': False, 'detail': str(e)}


def leekpay_verify_signature(raw_body: bytes, signature: str) -> bool:
    """Comparaison en temps constant (hmac.compare_digest) — voir la note dans
    services/soleaspay.py sur les attaques temporelles si on utilisait `==`."""
    if not signature or not config.LEEKPAY_PUBLIC_KEY:
        return False
    expected = hmac.new(config.LEEKPAY_PUBLIC_KEY.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
