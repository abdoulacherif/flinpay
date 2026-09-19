"""
services/restrictions.py — système de restriction anti-fraude à 3 niveaux,
plus des restrictions fines par pays et par opérateur mobile money.

NIVEAUX DE RESTRICTION (du plus léger au plus sévère)
-----------------------------------------------------
  none          — aucune restriction, compte normal
  no_withdrawal — le compte reste utilisable (connexion, encaissements) mais
                  ne peut plus RIEN retirer. Peut avoir une date d'expiration
                  (délai) : passé ce délai, la restriction se lève
                  automatiquement, sans action admin — exactement comme le
                  verrouillage anti-bruteforce (services/auth.is_locked_out).
  no_login      — le compte ne peut plus se connecter du tout (donc plus rien
                  faire). Les sessions déjà ouvertes sont coupées à la
                  prochaine requête (le flag est revérifié à chaque appel
                  protégé, pas seulement à la connexion).
  banned        — le compte est bloqué de façon définitive. Comme no_login,
                  mais signale une décision terminale (fraude avérée), pas
                  une mesure conservatoire.

RESTRICTIONS FINES (indépendantes des 3 niveaux ci-dessus)
------------------------------------------------------------
Un compte par ailleurs normal peut avoir certains PAYS ou certains RÉSEAUX
(opérateurs mobile money : mtn, orange, moov, wave...) bloqués
spécifiquement, par exemple si la fraude détectée est concentrée sur un
corridor précis. Ça n'empêche pas le reste du compte de fonctionner.

Toute modification de restriction passe par set_* ci-dessous, qui journalise
systématiquement l'action dans le journal d'audit admin (services/audit.py)
— qui a restreint qui, pourquoi, et pour combien de temps doit toujours être
traçable.
"""
import logging
from datetime import datetime, timedelta

from db.supabase import sb_patch
from services.audit import log_admin_action

logger = logging.getLogger('flinpay.restrictions')

LEVELS = ('none', 'no_withdrawal', 'no_login', 'banned')
_LOGIN_BLOCKING_LEVELS = {'no_login', 'banned'}
_WITHDRAWAL_BLOCKING_LEVELS = {'no_withdrawal', 'no_login', 'banned'}


def _restriction_active(user: dict) -> bool:
    """Une restriction avec date d'expiration passée est considérée levée,
    sans qu'il soit nécessaire qu'un admin la retire manuellement."""
    expires_at = user.get('restriction_expires_at')
    if not expires_at:
        return True
    try:
        exp = datetime.fromisoformat(expires_at.replace('Z', '+00:00')).replace(tzinfo=None)
        return datetime.utcnow() < exp
    except (ValueError, AttributeError):
        return True


def get_effective_level(user: dict) -> str:
    level = user.get('restriction_level') or 'none'
    if level == 'no_withdrawal' and not _restriction_active(user):
        return 'none'
    return level


def is_login_blocked(user: dict) -> bool:
    return get_effective_level(user) in _LOGIN_BLOCKING_LEVELS


def is_withdrawal_blocked(user: dict) -> bool:
    return get_effective_level(user) in _WITHDRAWAL_BLOCKING_LEVELS


def login_block_message(user: dict) -> str:
    level = get_effective_level(user)
    reason = (user.get('restriction_reason') or '').strip()
    if level == 'banned':
        base = "Ce compte a été définitivement bloqué."
    else:
        base = "Ce compte est temporairement suspendu."
    return f"{base} {reason}".strip() if reason else base


def withdrawal_block_message(user: dict) -> str:
    reason = (user.get('restriction_reason') or '').strip()
    expires_at = user.get('restriction_expires_at')
    msg = "Les retraits sont actuellement suspendus sur ce compte."
    if reason:
        msg += f" Motif : {reason}."
    if expires_at:
        msg += f" Cette restriction est levée automatiquement le {expires_at[:10]}."
    return msg


def is_country_blocked(user: dict, country_code: str) -> bool:
    blocked = user.get('restricted_countries') or []
    return (country_code or '').upper() in {c.upper() for c in blocked}


def is_operator_blocked(user: dict, operator_code: str) -> bool:
    blocked = user.get('restricted_operators') or []
    operator_code = (operator_code or '').lower()
    return any(operator_code == o.lower() or operator_code in o.lower() for o in blocked)


# ── Actions admin (toutes journalisées) ──────────────
def set_restriction_level(user_id: str, level: str, reason: str = None, duration_hours: int = None):
    if level not in LEVELS:
        raise ValueError(f"Niveau de restriction invalide: {level}")

    update = {
        'restriction_level': level,
        'restriction_reason': (reason or '').strip()[:500] or None,
        'restriction_set_at': datetime.utcnow().isoformat(),
    }
    if level == 'no_withdrawal' and duration_hours:
        update['restriction_expires_at'] = (datetime.utcnow() + timedelta(hours=duration_hours)).isoformat()
    else:
        update['restriction_expires_at'] = None

    ok = sb_patch('users', 'id', user_id, update)
    if ok:
        log_admin_action('user_restriction_set', {
            'target_user_id': user_id, 'level': level, 'reason': reason,
            'duration_hours': duration_hours
        })
    return ok


def clear_restriction(user_id: str):
    ok = sb_patch('users', 'id', user_id, {
        'restriction_level': 'none', 'restriction_reason': None,
        'restriction_expires_at': None
    })
    if ok:
        log_admin_action('user_restriction_cleared', {'target_user_id': user_id})
    return ok


def set_country_restrictions(user_id: str, country_codes: list):
    country_codes = sorted({(c or '').upper() for c in country_codes if c})
    ok = sb_patch('users', 'id', user_id, {'restricted_countries': country_codes})
    if ok:
        log_admin_action('user_country_restriction_set', {'target_user_id': user_id, 'countries': country_codes})
    return ok


def set_operator_restrictions_bulk(user_ids: list, operator_codes: list, blocked: bool):
    """Applique (ou retire) une restriction d'opérateur à PLUSIEURS
    utilisateurs en une seule action admin — utile quand la fraude détectée
    suit un pattern par réseau plutôt que par compte isolé."""
    operator_codes = {(o or '').lower() for o in operator_codes if o}
    results = {}
    for uid in user_ids:
        from db.supabase import sb_get_one
        user = sb_get_one('users', 'id', uid)
        if not user:
            results[uid] = False
            continue
        current = set((user.get('restricted_operators') or []))
        new_set = (current | operator_codes) if blocked else (current - operator_codes)
        ok = sb_patch('users', 'id', uid, {'restricted_operators': sorted(new_set)})
        results[uid] = ok
    log_admin_action('user_operator_restriction_bulk', {
        'target_user_ids': user_ids, 'operators': sorted(operator_codes), 'blocked': blocked
    })
    return results
