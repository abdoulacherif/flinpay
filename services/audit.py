"""
services/audit.py — journal d'audit des actions admin sensibles (KYC, comptes,
retraits, transactions, configuration du site...).

Toute action admin qui modifie une donnée doit appeler log_admin_action().
C'est la seule trace, après coup, de "qui a fait quoi" sur un compte admin
partagé — indispensable pour enquêter en cas de litige ou de compte admin
compromis. Best-effort : n'interrompt jamais l'action elle-même si
l'écriture du log échoue (mais l'échec est journalisé côté serveur).
"""
import logging
from datetime import datetime

from flask import request

from db.supabase import sb_post
from extensions import get_client_ip

logger = logging.getLogger('flinpay.audit')


def log_admin_action(action: str, details: dict = None):
    try:
        sb_post('admin_audit_log', {
            'admin_id': getattr(request, 'user_id', None),
            'action': action,
            'details': details or {},
            'ip_address': get_client_ip(),
            'created_at': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"[log_admin_action] échec d'écriture du journal d'audit: {e}")
