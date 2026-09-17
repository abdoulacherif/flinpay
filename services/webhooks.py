"""
services/webhooks.py — notifie les marchands (URL qu'ILS ont configurée) des
événements de paiement.

RISQUE DE SÉCURITÉ — SSRF (Server-Side Request Forgery)
-----------------------------------------------------------
`api_create_webhook` (dans les routes, à venir) permet à n'importe quel
marchand de saisir librement une URL. Ce module fait ensuite, depuis le
serveur Flinpay lui-même, une requête HTTP sortante vers cette URL à chaque
paiement. Sans protection, un marchand malveillant pourrait enregistrer comme
"webhook" une adresse interne :
  - http://169.254.169.254/... (métadonnées cloud — AWS/GCP/Azure — qui
    exposent souvent des identifiants)
  - http://localhost:xxxx ou http://127.0.0.1:xxxx (services internes)
  - une IP privée (10.x, 172.16-31.x, 192.168.x) du réseau interne de l'hébergeur
et se servir du serveur Flinpay comme relais pour sonder ou attaquer
l'infrastructure interne. `_is_safe_webhook_url()` bloque ces cibles avant
tout envoi. Cette même vérification doit être appliquée à la création/mise à
jour d'un webhook (routes/keys_webhooks.py), pas seulement à l'envoi, pour
rejeter l'URL dès la saisie plutôt que de la stocker puis de l'ignorer en
silence à chaque tentative d'envoi.
"""
import ipaddress
import logging
import socket
from urllib.parse import urlparse

import requests

logger = logging.getLogger('flinpay.webhooks')

WEBHOOK_TIMEOUT = 8
_BLOCKED_HOSTNAMES = {'localhost', 'metadata.google.internal'}


def _is_safe_webhook_url(url: str) -> bool:
    """Retourne False si l'URL ne doit PAS recevoir de requête sortante du
    serveur (schéma non http(s), hôte manquant, ou résolution vers une IP
    privée/loopback/link-local/multicast)."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False

    if parsed.scheme not in ('http', 'https'):
        return False
    hostname = (parsed.hostname or '').lower()
    if not hostname or hostname in _BLOCKED_HOSTNAMES:
        return False

    try:
        # Résout le nom d'hôte pour vérifier l'IP RÉELLEMENT contactée — un
        # attaquant pourrait sinon utiliser un nom de domaine public dont le
        # DNS pointe vers une IP interne (DNS rebinding).
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    for info in addr_info:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return False

    return True


def dispatch_merchant_webhooks(user_id, event, payload):
    """Best-effort, non bloquant : un webhook marchand qui échoue ne doit
    jamais empêcher le traitement du paiement lui-même."""
    from db.supabase import sb_get_eq  # import différé pour éviter tout cycle avec db/
    hooks = sb_get_eq('webhooks', 'user_id', user_id, extra_query='active=eq.true')
    for h in hooks:
        if event not in (h.get('events') or []):
            continue
        url = h.get('url', '')
        if not _is_safe_webhook_url(url):
            logger.warning(f"[dispatch_merchant_webhooks] URL bloquée (cible interne/non autorisée) pour user={user_id}")
            continue
        try:
            requests.post(
                url, json={'event': event, 'data': payload},
                timeout=WEBHOOK_TIMEOUT,
                allow_redirects=False,  # empêche un contournement par redirection
                                        # (URL publique au moment de la création,
                                        # qui redirige ensuite vers une cible interne)
            )
        except requests.RequestException as e:
            logger.info(f"[dispatch_merchant_webhooks] échec d'envoi pour user={user_id}: {e}")


def test_merchant_webhook(url: str):
    """Utilisé par la route 'tester ce webhook' — mêmes protections SSRF que
    l'envoi réel."""
    if not _is_safe_webhook_url(url):
        return {'ok': False, 'error': "Cette URL n'est pas autorisée (cible interne ou schéma non supporté)"}
    try:
        r = requests.post(
            url,
            json={'event': 'test', 'data': {'message': 'Ceci est un test envoyé depuis Flinpay'}},
            timeout=WEBHOOK_TIMEOUT,
            allow_redirects=False,
        )
        return {'ok': True, 'status_code': r.status_code}
    except requests.RequestException as e:
        return {'ok': False, 'error': str(e)}
