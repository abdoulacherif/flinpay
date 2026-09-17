"""
db/supabase.py — accès à Supabase via son API REST (PostgREST) et à son Storage.

RÈGLE DE SÉCURITÉ — injection via les filtres PostgREST
---------------------------------------------------------
PostgREST accepte ses filtres sous forme de chaîne de requête, par ex. :
    /users?email=eq.jean@example.com
Le code d'origine construisait ces chaînes avec des f-strings brutes partout :
    sb_get('users', f'email=eq.{email}')
Si `email` (ou n'importe quelle valeur utilisateur) contient un caractère
spécial pour PostgREST ou pour une query string (&, =, %, ,, *, .) un
attaquant peut injecter des filtres supplémentaires ou détourner la requête
prévue — c'est l'équivalent d'une injection SQL, mais à la couche PostgREST.
`eq()` ci-dessous échappe correctement la valeur : à utiliser SYSTÉMATIQUEMENT
pour toute valeur qui n'est pas une constante écrite en dur dans le code.

RÈGLE DE SÉCURITÉ — cette couche contourne le Row Level Security
--------------------------------------------------------------------
SUPABASE_KEY est ici la clé "service role", qui contourne entièrement le RLS
de Supabase. Autrement dit : TOUTE la logique d'autorisation ("cet
utilisateur a-t-il le droit de voir/modifier cette ligne ?") repose
uniquement sur le code applicatif (décorateurs @user_required/@admin_required
et filtres user_id=eq.… posés à la main dans chaque route). Une seule route
qui oublie de filtrer par user_id expose les données de TOUS les marchands.
Recommandation : activer des policies RLS côté Supabase en complément — pas
en remplacement — des vérifications applicatives existantes.
"""
import logging
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

# Liste blanche des buckets Storage utilisés par l'application. N'importe
# quelle fonction sb_storage_* refuse un bucket hors de cette liste — défense
# en profondeur si jamais un nom de bucket venait un jour d'une entrée
# utilisateur au lieu d'être toujours codé en dur dans l'appelant.
ALLOWED_STORAGE_BUCKETS = {'kyc-documents', 'payment-link-images'}


def eq(value) -> str:
    """Échappe une valeur pour un filtre PostgREST du type `champ=eq.<valeur>`.
    À utiliser systématiquement pour toute valeur venant de l'utilisateur ou
    de la requête HTTP."""
    return quote(str(value), safe='')


def _safe_storage_path(bucket: str, path: str) -> str:
    if bucket not in ALLOWED_STORAGE_BUCKETS:
        raise ValueError(f"Bucket de storage non autorisé : {bucket!r}")
    path = str(path)
    # Empêche toute traversée de répertoire. Les chemins sont normalement
    # construits à partir de request.user_id (UUID Supabase) côté serveur,
    # jamais saisis librement par l'utilisateur — mais on verrouille quand
    # même ici en dernier rempart.
    if '..' in path or path.startswith('/'):
        raise ValueError(f"Chemin de storage invalide (traversée détectée) : {path!r}")
    return path


# ── Lecture / écriture génériques (table REST) ─────
def sb_get(table, query=''):
    """Lecture brute. Si `query` inclut des valeurs utilisateur, construisez-la
    avec eq() plutôt que par interpolation directe — voir sb_get_eq() pour le
    cas le plus courant (filtrer sur une seule colonne)."""
    try:
        r = requests.get(f'{config.SUPABASE_URL}/rest/v1/{table}?{query}', headers=SUPA_HEADERS, timeout=DEFAULT_TIMEOUT)
        return r.json() if r.ok else []
    except requests.RequestException as e:
        logger.error(f"[sb_get] {table} error: {e}")
        return []
    except ValueError as e:  # JSON invalide
        logger.error(f"[sb_get] {table} invalid JSON response: {e}")
        return []


def sb_get_eq(table, field, value, extra_query=''):
    """Variante sûre de sb_get pour filtrer une table par une seule colonne.
    Échappe automatiquement `value`. Préférer cette fonction à
    sb_get(table, f'{field}=eq.{value}')."""
    query = f'{field}=eq.{eq(value)}'
    if extra_query:
        query += f'&{extra_query}'
    return sb_get(table, query)


def sb_get_one(table, field, value):
    """Comme sb_get_eq mais retourne directement la première ligne (ou None).
    Évite le pattern répété `matches = sb_get(...); x = matches[0] if matches else None`."""
    rows = sb_get_eq(table, field, value)
    return rows[0] if rows else None


def sb_post(table, data):
    try:
        r = requests.post(f'{config.SUPABASE_URL}/rest/v1/{table}', headers=SUPA_HEADERS, json=data, timeout=DEFAULT_TIMEOUT)
        if r.ok:
            return r.json()
        # Le statut est toujours journalisé ; le corps de la réponse (qui peut
        # contenir des données sensibles selon la table) ne l'est qu'au
        # niveau DEBUG, jamais en INFO/WARNING en production.
        logger.error(f"[sb_post] {table} failed: status={r.status_code}")
        logger.debug(f"[sb_post] {table} body={r.text[:300]}")
        return {'_error': True, '_status': r.status_code, '_detail': r.text[:300]}
    except requests.RequestException as e:
        logger.error(f"[sb_post] {table} error: {e}")
        return {'_error': True, '_status': 0, '_detail': str(e)}


def sb_patch(table, field, value, data):
    try:
        r = requests.patch(
            f'{config.SUPABASE_URL}/rest/v1/{table}?{field}=eq.{eq(value)}',
            headers=SUPA_HEADERS, json=data, timeout=DEFAULT_TIMEOUT
        )
        if not r.ok:
            logger.error(f"[sb_patch] {table} failed: status={r.status_code}")
        return r.ok
    except requests.RequestException as e:
        logger.error(f"[sb_patch] {table} error: {e}")
        return False


def sb_delete(table, field, value):
    try:
        r = requests.delete(
            f'{config.SUPABASE_URL}/rest/v1/{table}?{field}=eq.{eq(value)}',
            headers=SUPA_HEADERS, timeout=DEFAULT_TIMEOUT
        )
        if not r.ok:
            logger.error(f"[sb_delete] {table} failed: status={r.status_code}")
        return r.ok
    except requests.RequestException as e:
        logger.error(f"[sb_delete] {table} error: {e}")
        return False


def _build_filter_qs(filters: dict) -> str:
    return '&'.join(f'{k}=eq.{eq(v)}' for k, v in filters.items())


def sb_patch_multi(table, filters: dict, data):
    """Comme sb_patch mais avec plusieurs colonnes de filtre (ex: token + user_id
    ensemble, pour garantir qu'un marchand ne peut modifier QUE ses propres lignes)."""
    try:
        qs = _build_filter_qs(filters)
        r = requests.patch(f'{config.SUPABASE_URL}/rest/v1/{table}?{qs}', headers=SUPA_HEADERS, json=data, timeout=DEFAULT_TIMEOUT)
        if not r.ok:
            logger.error(f"[sb_patch_multi] {table} failed: status={r.status_code}")
        return r.ok
    except requests.RequestException as e:
        logger.error(f"[sb_patch_multi] {table} error: {e}")
        return False


def sb_patch_if_pending(table, token_field, token_value, data):
    """Met à jour une ligne UNIQUEMENT si elle est encore status='pending', de
    façon atomique côté base de données. Retourne True seulement si CETTE
    requête a réellement effectué la transition — protège contre le double
    crédit quand un webhook et une vérification manuelle se chevauchent."""
    try:
        qs = f'{token_field}=eq.{eq(token_value)}&status=eq.pending'
        r = requests.patch(f'{config.SUPABASE_URL}/rest/v1/{table}?{qs}', headers=SUPA_HEADERS, json=data, timeout=DEFAULT_TIMEOUT)
        if not r.ok:
            logger.error(f"[sb_patch_if_pending] {table} failed: status={r.status_code}")
            return False
        return bool(r.json())
    except requests.RequestException as e:
        logger.error(f"[sb_patch_if_pending] {table} error: {e}")
        return False
    except ValueError as e:
        logger.error(f"[sb_patch_if_pending] {table} invalid JSON: {e}")
        return False


def sb_delete_multi(table, filters: dict):
    try:
        qs = _build_filter_qs(filters)
        r = requests.delete(f'{config.SUPABASE_URL}/rest/v1/{table}?{qs}', headers=SUPA_HEADERS, timeout=DEFAULT_TIMEOUT)
        if not r.ok:
            logger.error(f"[sb_delete_multi] {table} failed: status={r.status_code}")
        return r.ok
    except requests.RequestException as e:
        logger.error(f"[sb_delete_multi] {table} error: {e}")
        return False


def sb_count(table, query=''):
    try:
        headers = dict(SUPA_HEADERS)
        headers['Prefer'] = 'count=exact'
        sep = '&' if query else ''
        r = requests.get(f'{config.SUPABASE_URL}/rest/v1/{table}?{query}{sep}limit=1', headers=headers, timeout=DEFAULT_TIMEOUT)
        cr = r.headers.get('Content-Range', '')
        return int(cr.split('/')[-1]) if '/' in cr else 0
    except (requests.RequestException, ValueError) as e:
        logger.error(f"[sb_count] {table} error: {e}")
        return 0


# ── Storage (documents KYC, images de liens de paiement) ──
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
            'x-upsert': 'true'
        }
        r = requests.post(url, headers=headers, data=file_bytes, timeout=STORAGE_TIMEOUT)
        if r.ok:
            return {'ok': True}
        logger.error(f"[sb_storage_upload] {bucket}/{path} failed: status={r.status_code}")
        return {'ok': False, 'detail': r.text[:300]}
    except requests.RequestException as e:
        logger.error(f"[sb_storage_upload] error: {e}")
        return {'ok': False, 'detail': str(e)}


def sb_storage_sign(bucket, path, expires_in=3600):
    """Génère une URL signée temporaire — utilisé pour les documents KYC, qui ne
    doivent JAMAIS être exposés via une URL publique permanente (ce sont des
    pièces d'identité). expires_in est plafonné à 1h max ici, quel que soit
    ce qu'un futur appelant pourrait passer par erreur."""
    try:
        path = _safe_storage_path(bucket, path)
    except ValueError as e:
        logger.error(f"[sb_storage_sign] {e}")
        return None
    expires_in = min(int(expires_in or 3600), 3600)
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
    """Réservé aux buckets dont le contenu est légitimement public (images de
    liens de paiement). Ne JAMAIS utiliser pour kyc-documents — voir
    sb_storage_sign() pour tout document sensible."""
    if bucket == 'kyc-documents':
        raise ValueError("kyc-documents ne doit jamais être exposé via une URL publique — utilisez sb_storage_sign()")
    path = _safe_storage_path(bucket, path)
    return f'{config.SUPABASE_URL}/storage/v1/object/public/{bucket}/{path}'
