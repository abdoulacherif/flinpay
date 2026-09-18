"""
services/tracking.py — capture les métadonnées du visiteur qui déclenche un
paiement (navigateur, IP, page d'origine), pour affichage dans l'historique
des transactions du marchand.
"""
from flask import request

from extensions import get_client_ip


def get_request_client_info():
    """Utilise get_client_ip() (extensions.py), qui passe par ProxyFix et donc
    reflète l'IP réelle du visiteur plutôt qu'un en-tête potentiellement
    falsifié par le client lui-même — voir la note dans extensions.py."""
    return {
        'user_agent': (request.headers.get('User-Agent') or '')[:500],
        'ip_address': get_client_ip()[:100],
        'referer_url': (request.headers.get('Referer') or '')[:500]
    }
