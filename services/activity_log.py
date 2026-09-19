"""
services/activity_log.py — journal d'activité COMPLET, par utilisateur (à ne
pas confondre avec services/audit.py qui ne journalise que les actions des
ADMINS). Celui-ci capture ce que chaque marchand fait lui-même : connexions
réussies/échouées, création de paiement, demande de retrait, modification de
profil, activation/désactivation du 2FA, soumission KYC, création de clé
API...

Objectif explicite : pouvoir reconstituer, pour un compte donné, qui a fait
quoi, quand, depuis quelle IP — pour instruire un dossier de fraude en interne
et, si nécessaire, fournir un historique exploitable aux autorités
compétentes. Best-effort : n'interrompt jamais l'action elle-même si
l'écriture du journal échoue.
"""
import logging
from datetime import datetime

from flask import request

from db.supabase import sb_post, sb_get_eq
from extensions import get_client_ip

logger = logging.getLogger('flinpay.activity')


def log_user_activity(user_id: str, event_type: str, details: dict = None):
    try:
        sb_post('user_activity_log', {
            'user_id': user_id,
            'event_type': event_type,
            'details': details or {},
            'ip_address': get_client_ip(),
            'user_agent': (request.headers.get('User-Agent') or '')[:300],
            'created_at': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"[log_user_activity] échec d'écriture pour user={user_id}: {e}")


def get_user_activity(user_id: str, limit: int = 500):
    """Historique complet d'un utilisateur, du plus récent au plus ancien —
    utilisé par l'admin pour l'instruction d'un dossier (voir
    routes/admin/restrictions.py)."""
    return sb_get_eq('user_activity_log', 'user_id', user_id, extra_query=f'order=created_at.desc&limit={limit}')
