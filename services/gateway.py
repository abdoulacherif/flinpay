import logging
import threading
import time
import uuid as uuid_lib

import requests

from config import config

logger = logging.getLogger('flinpay.gateway')

DEFAULT_TIMEOUT = 15

SUCCESS_STATUSES = {'COMPLETED', 'SUCCESS'}
FAILURE_STATUSES = {'FAILED', 'CANCELLED', 'REFUNDED'}
FINAL_STATUSES = SUCCESS_STATUSES | FAILURE_STATUSES


def map_remote_status(remote_status: str) -> str:
    if remote_status in SUCCESS_STATUSES:
        return 'paid'
    if remote_status in FAILURE_STATUSES:
        return 'failed'
    return 'pending'


class GatewayError(Exception):
    def __init__(self, message, detail=None, status_code=None):
        super().__init__(message)
        self.detail = detail
        self.status_code = status_code


_token_lock = threading.Lock()
_token_cache = {'access_token': None, 'expires_at': 0, 'token_endpoint': None}


def _discover_token_endpoint() -> str:
    if _token_cache['token_endpoint']:
        return _token_cache['token_endpoint']
    try:
        r = requests.get(
            f'{config.IDENTITY_BASE_URL}/.well-known/openid-configuration',
            timeout=DEFAULT_TIMEOUT,
        )
        if r.ok:
            endpoint = r.json().get('token_endpoint')
            if endpoint:
                _token_cache['token_endpoint'] = endpoint
                return endpoint
    except (requests.RequestException, ValueError) as e:
        logger.warning(f"[gateway] découverte OIDC indisponible: {e}")
    fallback = f'{config.IDENTITY_BASE_URL}/oauth/v2/token'
    _token_cache['token_endpoint'] = fallback
    return fallback


def _get_access_token() -> str:
    with _token_lock:
        now = time.time()
        if _token_cache['access_token'] and now < _token_cache['expires_at'] - 30:
            return _token_cache['access_token']

        endpoint = _discover_token_endpoint()
        payload = {
            'grant_type': 'client_credentials',
            'client_id': config.GATEWAY_CLIENT_ID,
            'client_secret': config.GATEWAY_CLIENT_SECRET,
            'scope': 'payments services countries providers',
        }
        try:
            r = requests.post(
                endpoint, json=payload, timeout=DEFAULT_TIMEOUT,
                headers={'X-SP-Environment': config.GATEWAY_ENVIRONMENT},
            )
            data = r.json()
        except (requests.RequestException, ValueError) as e:
            logger.error(f"[gateway] échec d'authentification: {e}")
            raise GatewayError("Authentification auprès du prestataire impossible") from e

        token = data.get('access_token')
        if not r.ok or not token:
            logger.error(f"[gateway] auth refusée: status={r.status_code} body={r.text[:300]}")
            error_detail = data if isinstance(data, dict) else {'raw': r.text[:300]}
            error_detail['_debug_endpoint'] = endpoint
            error_detail['_debug_client_id_prefix'] = (config.GATEWAY_CLIENT_ID or '')[:6] + '…'
            raise GatewayError(
                "Authentification auprès du prestataire refusée",
                detail=error_detail,
                status_code=r.status_code,
            )

        expires_in = data.get('expires_in') or 3600
        if data.get('token_expired_at'):
            _token_cache['expires_at'] = float(data['token_expired_at'])
        else:
            _token_cache['expires_at'] = now + float(expires_in)
        _token_cache['access_token'] = token
        return token


def _invalidate_token():
    with _token_lock:
        _token_cache['access_token'] = None


def _gateway_request(method, path, json_body=None, params=None, extra_headers=None, retry_on_auth_fail=True):
    token = _get_access_token()
    headers = {
        'x-sp-auth-token': f'Bearer {token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-Request-Id': uuid_lib.uuid4().hex,
        'X-SP-Environment': config.GATEWAY_ENVIRONMENT,
    }
    if extra_headers:
        headers.update(extra_headers)

    url = f'{config.GATEWAY_BASE_URL}{path}'
    try:
        r = requests.request(method, url, json=json_body, params=params, headers=headers, timeout=DEFAULT_TIMEOUT)
    except requests.RequestException as e:
        logger.error(f"[gateway] {method} {path} erreur réseau: {e}")
        raise GatewayError("Le prestataire est momentanément injoignable") from e

    if r.status_code == 401 and retry_on_auth_fail:
        logger.info(f"[gateway] token rejeté sur {path}, renouvellement")
        _invalidate_token()
        return _gateway_request(method, path, json_body, params, extra_headers, retry_on_auth_fail=False)

    try:
        data = r.json()
    except ValueError:
        logger.error(f"[gateway] {method} {path} réponse non-JSON: status={r.status_code}")
        raise GatewayError("Réponse invalide du prestataire", status_code=r.status_code)

    if not r.ok or data.get('success') is False:
        message = data.get('message', 'erreur inconnue')
        logger.warning(f"[gateway] {method} {path} échec: status={r.status_code} message={message}")
        raise GatewayError(message, detail=data, status_code=r.status_code)

    return data.get('data', data)


_catalogue_cache = {}
_CATALOGUE_TTL = 600


def _cached(key, ttl, fetch_fn):
    entry = _catalogue_cache.get(key)
    if entry and time.time() - entry['t'] < ttl:
        return entry['v']
    value = fetch_fn()
    _catalogue_cache[key] = {'v': value, 't': time.time()}
    return value


def alpha3(country_code_alpha2: str) -> str:
    a3 = config.COUNTRY_ALPHA3.get((country_code_alpha2 or '').upper())
    if not a3:
        raise GatewayError(f"Pays non pris en charge: {country_code_alpha2}")
    return a3


def list_countries():
    def _fetch():
        data = _gateway_request('GET', '/country/list', params={'page': 1, 'limit': 100})
        items = data if isinstance(data, list) else data.get('items', [])
        return [c for c in items if c.get('active')]
    return _cached('countries', _CATALOGUE_TTL, _fetch)


def list_services(country_code_alpha2: str, currency: str = None):
    country3 = alpha3(country_code_alpha2)
    cache_key = f'services:{country3}:{currency or "*"}'

    def _fetch():
        params = {'country': country3}
        if currency:
            params['currency'] = currency
        data = _gateway_request('GET', '/service/list', params=params)
        items = data if isinstance(data, list) else data.get('items', [])
        logger.info(f"[gateway] services {country3}: {len(items)} bruts")
        if items:
            logger.info(f"[gateway] premier service: {list(items[0].keys())}")
        return [s for s in items if s.get('is_active', True)]
    return _cached(cache_key, _CATALOGUE_TTL, _fetch)


def find_service(country_code_alpha2: str, operator_key: str, for_operation: str = 'collect'):
    services = list_services(country_code_alpha2)
    need_flag = 'is_can_collect' if for_operation == 'collect' else 'is_can_disburse'
    operator_key = (operator_key or '').lower()
    for s in services:
        code = (s.get('code') or '').lower()
        if operator_key and operator_key not in code:
            continue
        if s.get(need_flag, True):
            return s
    return None


def build_countries_operators(country_codes_alpha2):
    result = {}
    for code in country_codes_alpha2:
        try:
            result[code] = list_services(code)
        except GatewayError as e:
            logger.warning(f"[gateway] catalogue indisponible pour {code}: {e}")
            result[code] = []
    return result


def get_fee_quote(service_id: int, amount: float, currency: str):
    return _gateway_request('POST', '/transactions/fees/quote', json_body={
        'serviceId': service_id, 'amount': amount, 'currency': currency
    })


def compute_customer_charge(base_amount: float, service_id: int, currency: str):
    try:
        quote = get_fee_quote(service_id, base_amount, currency)
        fee = float(quote.get('feeAmount') or 0)
    except GatewayError as e:
        logger.warning(f"[gateway] devis de frais indisponible: {e}")
        fee = 0.0

    if config.GATEWAY_FEES_DEDUCTED_FROM_MERCHANT:
        customer_charge = round(base_amount + fee, 2)
    else:
        customer_charge = round(base_amount, 2)
    return customer_charge, fee, base_amount


def collection_intent(amount, currency, provider_code, customer_wallet, description, transaction_uuid=None, channel='PROVIDER'):
    transaction_uuid = transaction_uuid or uuid_lib.uuid4().hex
    body = {
        'amount': amount, 'currency': currency, 'transaction_uuid': transaction_uuid,
        'provider': provider_code, 'channel': channel,
        'customer_wallet': customer_wallet, 'description': (description or '')[:200],
    }
    return _gateway_request('POST', '/collection/intent', json_body=body,
                             extra_headers={'X-Idempotency-Key': transaction_uuid})


def collection_execute(transaction_reference, invoice_reference=None, otp=None):
    body = {'transaction_reference': transaction_reference}
    if invoice_reference:
        body['invoice_reference'] = str(invoice_reference)[:120]
    if otp:
        body['otp'] = otp
    return _gateway_request('POST', '/collection/execute', json_body=body)


def collection_status(transaction_reference):
    return _gateway_request('POST', '/collection/status', json_body={'transaction_reference': transaction_reference})


def collect_payment(*, base_amount, currency, service, customer_wallet, description, invoice_reference, otp=None):
    customer_charge, provider_fee, base_amount = compute_customer_charge(base_amount, service['id'], currency)
    if customer_charge < config.GATEWAY_MIN_AMOUNT:
        return {'ok': False, 'error': f"Montant trop faible (minimum {config.GATEWAY_MIN_AMOUNT} {currency})"}
    if service.get('is_need_otp') and not otp:
        return {'ok': False, 'error': "Code de confirmation (OTP) requis pour cet opérateur", 'requires_otp': True}

    try:
        intent = collection_intent(
            amount=customer_charge, currency=currency, provider_code=service['code'],
            customer_wallet=customer_wallet, description=description,
        )
        tx_ref = intent.get('transaction_reference')
        if not tx_ref:
            return {'ok': False, 'error': "Réponse inattendue du prestataire"}

        exec_result = collection_execute(tx_ref, invoice_reference=invoice_reference, otp=otp)
        return {
            'ok': True,
            'transaction_reference': tx_ref,
            'customer_charge': customer_charge,
            'provider_fee': provider_fee,
            'base_amount': base_amount,
            'confirmation_url': exec_result.get('confirmation_url') or intent.get('confirmation_url'),
            'confirmation_helper': service.get('confirmation_helper'),
        }
    except GatewayError as e:
        return {'ok': False, 'error': e.detail.get('message') if isinstance(e.detail, dict) else str(e)}


def disbursement_intent(amount, currency, provider_code, customer_wallet, description, transaction_uuid=None, channel='PROVIDER'):
    transaction_uuid = transaction_uuid or uuid_lib.uuid4().hex
    body = {
        'amount': amount, 'currency': currency, 'transaction_uuid': transaction_uuid,
        'provider': provider_code, 'channel': channel,
        'customer_wallet': customer_wallet, 'description': (description or '')[:200],
    }
    return _gateway_request('POST', '/disbursement/intent', json_body=body,
                             extra_headers={'X-Idempotency-Key': transaction_uuid})


def disbursement_execute(transaction_reference, invoice_reference=None):
    body = {'transaction_reference': transaction_reference}
    if invoice_reference:
        body['invoice_reference'] = str(invoice_reference)[:120]
    return _gateway_request('POST', '/disbursement/execute', json_body=body)


def disbursement_status(transaction_reference):
    return _gateway_request('POST', '/disbursement/status', json_body={'transaction_reference': transaction_reference})


def send_payout(*, amount, currency, service, customer_wallet, description, invoice_reference):
    try:
        intent = disbursement_intent(
            amount=amount, currency=currency, provider_code=service['code'],
            customer_wallet=customer_wallet, description=description,
        )
        tx_ref = intent.get('transaction_reference')
        fee = float(intent.get('fee') or 0)
        if not tx_ref:
            return {'ok': False, 'error': "Réponse inattendue du prestataire"}
        disbursement_execute(tx_ref, invoice_reference=invoice_reference)
        return {'ok': True, 'transaction_reference': tx_ref, 'provider_fee': fee}
    except GatewayError as e:
        msg = e.detail.get('message') if isinstance(e.detail, dict) else str(e)
        friendly = {
            'insufficient_balance': "Solde insuffisant chez le prestataire pour ce retrait",
            'provider_not_found': "Opérateur indisponible pour ce pays",
            'user_wallet_not_found': "Aucun portefeuille compatible pour cette devise",
        }.get(msg, msg)
        return {'ok': False, 'error': friendly}


def subscription_create(*, customer_email, customer_phone, amount, currency, frequency, description, metadata=None, idempotency_key=None):
    body = {
        'customer_email': customer_email, 'customer_phone_number': customer_phone,
        'amount': amount, 'currency': currency, 'frequency': frequency,
        'description': (description or '')[:200], 'metadata': metadata or {},
    }
    headers = {'X-Idempotency-Key': idempotency_key} if idempotency_key else None
    return _gateway_request('POST', '/merchand/billing/subscribe', json_body=body, extra_headers=headers)


def subscription_detail(reference):
    return _gateway_request('GET', f'/merchand/billing/subscriptions/detail/{reference}', params={'for': 'merchant'})


def subscription_cancel(reference, reason=None):
    return _gateway_request('POST', f'/merchand/billing/subscriptions/cancel/{reference}', json_body={'reason': reason} if reason else {})


def subscription_payments(reference):
    return _gateway_request('GET', f'/merchand/billing/subscriptions/payments/{reference}')


def verify_phone_number(wallet: str, country_code_alpha2: str):
    if not config.GATEWAY_MERCHANT_API_KEY:
        return None
    try:
        r = requests.post(
            f'{config.GATEWAY_BASE_URL}/phone-numbers/verify',
            headers={'X-API-Key': config.GATEWAY_MERCHANT_API_KEY, 'Content-Type': 'application/json'},
            json={'wallet': wallet, 'country': alpha3(country_code_alpha2)},
            timeout=DEFAULT_TIMEOUT,
        )
        data = r.json()
        return data if data.get('valid') else None
    except (requests.RequestException, ValueError, GatewayError) as e:
        logger.info(f"[gateway] vérification de numéro indisponible: {e}")
        return None