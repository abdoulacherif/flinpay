import logging
import unicodedata
from urllib.parse import quote
import requests

from config import config

logger = logging.getLogger('flinpay.db')

SUPA_HEADERS = {
    'apikey': config.SUPABASE_KEY,
    'Authorization': f'Bearer {config.SUPABASE_KEY}',
    'Content-Type': 'application/json',
    'Prefer': 'return=representation'
}

DEFAULT_TIMEOUT = 10
STORAGE_TIMEOUT = 20

ALLOWED_STORAGE_BUCKETS = {'kyc-documents', 'payment-link-images'}

ALLOWED_FILTER_COLUMNS = {
    # Identifiants
    'id', 'token', 'user_id', 'email', 'ip_address', 'key_hash', 'wid',
    'order_id', 'gateway_reference', 'invoice_token', 'payment_link_token',
    'key_prefix', 'environment',
    'referral_code', 'referred_by', 'referred_id', 'referrer_id',
    'pending_upgrade_checkout_id', 'pending_upgrade_currency',

    # Statuts / flags
    'status', 'active', 'is_active', 'is_admin', 'email_verified',
    'totp_enabled', 'email_link_enabled', 'kyc_status', 'restriction_level',
    'is_visible', 'is_popular',

    # Tokens / sécurité
    'email_verify_token_hash', 'email_verify_token_expires_at',
    'login_link_token_hash', 'login_link_code_hash', 'login_link_expires_at',
    'password_reset_token_hash', 'password_reset_expires_at',
    'kyc_id_number_hash', 'password_hash', 'locked_until', 'login_attempts',

    # 2FA
    'totp_secret',

    # KYC
    'kyc_full_name', 'kyc_id_type', 'kyc_id_number',
    'kyc_document_front_path', 'kyc_document_back_path', 'kyc_selfie_path',
    'kyc_submitted_at', 'kyc_rejection_reason',

    # Soldes / plan
    'available_balance', 'referral_balance',
    'plan', 'plan_expires_at', 'monthly_limit',
    'balance_xof', 'balance_xaf', 'balance_cdf',

    # Transactions / paiements
    'amount', 'currency', 'country', 'operator',
    'client_name', 'client_email', 'client_phone',
    'client_amount', 'fee_amount', 'gateway_status',
    'paid_at', 'sent_at', 'due_date', 'items', 'notes',
    'invoice_number', 'payment_link_token', 'gateway_reference',
    'user_agent', 'referer_url',

    # Payouts
    'payout_id', 'net_amount', 'phone', 'note',

    # Webhooks / API keys
    'url', 'events', 'description', 'label', 'last_used_at',

    # Site config / pricing
    'key', 'value', 'price', 'period', 'cta_text', 'features',
    'order_index', 'paid_count', 'views',

    # Divers
    'source', 'created_at', 'updated_at', 'deleted_at', 'guard_field',
    'country_code', 'last4', 'name', 'role', 'company', 'firstname', 'lastname',

    # Récompenses FP
    'fp_balance', 'amount_fp', 'source_amount', 'source_currency',
}


def eq(value) -> str:
    return quote(str(value), safe='')


def _safe_filter_field(field: str) -> str:
    if not ALLOWED_FILTER_COLUMNS or '*' in ALLOWED_FILTER_COLUMNS:
        return field
    if field not in ALLOWED_FILTER_COLUMNS:
        raise ValueError(f"Colonne de filtre non autorisée: {field!r}")
    return field


def _build_filter_qs(filters: dict) -> str:
    parts = []
    for k, v in filters.items():
        safe_k = _safe_filter_field(k)
        parts.append(f'{safe_k}=eq.{eq(v)}')
    return '&'.join(parts)


def _safe_storage_path(bucket: str, path: str) -> str:
    if bucket not in ALLOWED_STORAGE_BUCKETS:
        raise ValueError(f"Bucket de storage non autorisé : {bucket!r}")

    path = unicodedata.normalize('NFC', str(path)).strip()

    if ('..' in path
            or path.startswith('/')
            or '%2e' in path.lower()
            or '%2f' in path.lower()
            or '\x00' in path
            or '\\' in path):
        raise ValueError(f"Chemin de storage invalide (sécurité) : {path!r}")

    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-")
    if not set(path).issubset(allowed_chars):
        raise ValueError(f"Caractères invalides dans le chemin : {path!r}")

    return path


def sb_get(table, query=''):
    try:
        r = requests.get(
            f'{config.SUPABASE_URL}/rest/v1/{table}?{query}',
            headers=SUPA_HEADERS, timeout=DEFAULT_TIMEOUT
        )
        return r.json() if r.ok else []
    except requests.RequestException as e:
        logger.error(f"[sb_get] {table} error: {e}")
        return []
    except ValueError as e:
        logger.error(f"[sb_get] {table} invalid JSON response: {e}")
        return []


def sb_get_eq(table, field, value, extra_query=''):
    safe_field = _safe_filter_field(field)
    query = f'{safe_field}=eq.{eq(value)}'
    if extra_query:
        query += f'&{extra_query}'
    return sb_get(table, query)


def sb_get_one(table, field, value):
    rows = sb_get_eq(table, field, value)
    return rows[0] if rows else None


def sb_post(table, data):
    try:
        r = requests.post(
            f'{config.SUPABASE_URL}/rest/v1/{table}',
            headers=SUPA_HEADERS, json=data, timeout=DEFAULT_TIMEOUT
        )
        if r.ok:
            return r.json()
        logger.error(f"[sb_post] {table} failed: status={r.status_code}")
        logger.debug(f"[sb_post] {table} body={r.text[:300]}")
        return {'_error': True, '_status': r.status_code}
    except requests.RequestException as e:
        logger.error(f"[sb_post] {table} error: {e}")
        return {'_error': True, '_status': 0}


def sb_patch(table, field, value, data):
    try:
        safe_field = _safe_filter_field(field)
        r = requests.patch(
            f'{config.SUPABASE_URL}/rest/v1/{table}?{safe_field}=eq.{eq(value)}',
            headers=SUPA_HEADERS, json=data, timeout=DEFAULT_TIMEOUT
        )
        if not r.ok:
            logger.error(f"[sb_patch] {table} failed: status={r.status_code}")
        return r.ok
    except (requests.RequestException, ValueError) as e:
        logger.error(f"[sb_patch] {table} error: {e}")
        return False


def sb_delete(table, field, value):
    try:
        safe_field = _safe_filter_field(field)
        r = requests.delete(
            f'{config.SUPABASE_URL}/rest/v1/{table}?{safe_field}=eq.{eq(value)}',
            headers=SUPA_HEADERS, timeout=DEFAULT_TIMEOUT
        )
        if not r.ok:
            logger.error(f"[sb_delete] {table} failed: status={r.status_code}")
        return r.ok
    except (requests.RequestException, ValueError) as e:
        logger.error(f"[sb_delete] {table} error: {e}")
        return False


def sb_patch_multi(table, filters: dict, data):
    try:
        qs = _build_filter_qs(filters)
        r = requests.patch(
            f'{config.SUPABASE_URL}/rest/v1/{table}?{qs}',
            headers=SUPA_HEADERS, json=data, timeout=DEFAULT_TIMEOUT
        )
        if not r.ok:
            logger.error(f"[sb_patch_multi] {table} failed: status={r.status_code}")
        return r.ok
    except (requests.RequestException, ValueError) as e:
        logger.error(f"[sb_patch_multi] {table} error: {e}")
        return False


def sb_patch_if_pending(table, token_field, token_value, data):
    try:
        safe_field = _safe_filter_field(token_field)
        qs = f'{safe_field}=eq.{eq(token_value)}&status=eq.pending'
        r = requests.patch(
            f'{config.SUPABASE_URL}/rest/v1/{table}?{qs}',
            headers=SUPA_HEADERS, json=data, timeout=DEFAULT_TIMEOUT
        )
        if not r.ok:
            logger.error(f"[sb_patch_if_pending] {table} failed: status={r.status_code}")
            return False
        return bool(r.json())
    except (requests.RequestException, ValueError) as e:
        logger.error(f"[sb_patch_if_pending] {table} error: {e}")
        return False


def sb_patch_if_field_equals(table, id_field, id_value, guard_field, guard_value, data):
    try:
        safe_id = _safe_filter_field(id_field)
        safe_guard = _safe_filter_field(guard_field)
        qs = f'{safe_id}=eq.{eq(id_value)}&{safe_guard}=eq.{eq(guard_value)}'
        r = requests.patch(
            f'{config.SUPABASE_URL}/rest/v1/{table}?{qs}',
            headers=SUPA_HEADERS, json=data, timeout=DEFAULT_TIMEOUT
        )
        if not r.ok:
            logger.error(f"[sb_patch_if_field_equals] {table} failed: status={r.status_code}")
            return False
        return bool(r.json())
    except (requests.RequestException, ValueError) as e:
        logger.error(f"[sb_patch_if_field_equals] {table} error: {e}")
        return False


def sb_delete_multi(table, filters: dict):
    try:
        qs = _build_filter_qs(filters)
        r = requests.delete(
            f'{config.SUPABASE_URL}/rest/v1/{table}?{qs}',
            headers=SUPA_HEADERS, timeout=DEFAULT_TIMEOUT
        )
        if not r.ok:
            logger.error(f"[sb_delete_multi] {table} failed: status={r.status_code}")
        return r.ok
    except (requests.RequestException, ValueError) as e:
        logger.error(f"[sb_delete_multi] {table} error: {e}")
        return False


def sb_count(table, query=''):
    try:
        headers = dict(SUPA_HEADERS)
        headers['Prefer'] = 'count=exact'
        sep = '&' if query else ''
        r = requests.get(
            f'{config.SUPABASE_URL}/rest/v1/{table}?{query}{sep}limit=1',
            headers=headers, timeout=DEFAULT_TIMEOUT
        )
        cr = r.headers.get('Content-Range', '')
        return int(cr.split('/')[-1]) if '/' in cr else 0
    except (requests.RequestException, ValueError) as e:
        logger.error(f"[sb_count] {table} error: {e}")
        return 0


def sb_storage_upload(bucket, path, file_bytes, content_type):
    try:
        path = _safe_storage_path(bucket, path)
    except ValueError as e:
        logger.error(f"[sb_storage_upload] {e}")
        return {'ok': False, 'detail': 'Chemin de fichier invalide'}

    try:
        url = f'{config.SUPABASE_URL}/storage/v1/object/{bucket}/{path}'
        headers = {
            'apikey': config.SUPABASE_KEY,
            'Authorization': f'Bearer {config.SUPABASE_KEY}',
            'Content-Type': content_type or 'application/octet-stream',
            'x-upsert': 'false',
        }
        r = requests.post(url, headers=headers, data=file_bytes, timeout=STORAGE_TIMEOUT)
        if r.ok:
            return {'ok': True}
        logger.error(f"[sb_storage_upload] {bucket}/{path} failed: status={r.status_code}")
        return {'ok': False, 'detail': "Erreur d'upload"}
    except requests.RequestException as e:
        logger.error(f"[sb_storage_upload] error: {e}")
        return {'ok': False, 'detail': "Erreur réseau"}


def sb_storage_sign(bucket, path, expires_in=3600):
    try:
        path = _safe_storage_path(bucket, path)
    except ValueError as e:
        logger.error(f"[sb_storage_sign] {e}")
        return None

    try:
        expires_in = max(60, min(int(expires_in or 3600), 3600))
    except (ValueError, TypeError):
        expires_in = 3600

    try:
        url = f'{config.SUPABASE_URL}/storage/v1/object/sign/{bucket}/{path}'
        r = requests.post(url, headers=SUPA_HEADERS, json={'expiresIn': expires_in}, timeout=DEFAULT_TIMEOUT)
        if not r.ok:
            logger.error(f"[sb_storage_sign] {bucket}/{path} failed: status={r.status_code}")
            return None
        signed_path = r.json().get('signedURL')
        return f'{config.SUPABASE_URL}/storage/v1{signed_path}' if signed_path else None
    except (requests.RequestException, ValueError) as e:
        logger.error(f"[sb_storage_sign] error: {e}")
        return None


def sb_storage_public_url(bucket, path):
    if bucket == 'kyc-documents':
        raise ValueError("kyc-documents ne doit jamais être exposé via une URL publique")
    path = _safe_storage_path(bucket, path)
    return f'{config.SUPABASE_URL}/storage/v1/object/public/{bucket}/{path}'