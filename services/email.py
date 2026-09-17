"""
services/email.py — envoi d'emails transactionnels via SMTP.

RÈGLE DE SÉCURITÉ — injection d'en-têtes email
-------------------------------------------------
`msg['Subject']`, `msg['To']` etc. sont des en-têtes SMTP. Si une valeur
insérée dedans (prénom, montant, nom de client...) contient un retour à la
ligne, un attaquant peut injecter de nouveaux en-têtes ou même un nouveau
corps de message (ex: ajouter discrètement un `Bcc:` vers sa propre adresse,
ou changer le `Subject:` pour du phishing). `_clean_header()` supprime tout
caractère de contrôle avant toute insertion dans un en-tête.
"""
import logging
import re
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.utils import parseaddr

from config import config

logger = logging.getLogger('flinpay.email')

_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def _clean_header(value: str, max_len: int = 200) -> str:
    """Retire tout retour à la ligne / caractère de contrôle d'une valeur avant
    de l'insérer dans un en-tête SMTP (protection contre l'injection d'en-têtes)."""
    value = str(value or '')
    value = re.sub(r'[\r\n\x00-\x1f]', ' ', value).strip()
    return value[:max_len]


def _is_valid_email(email: str) -> bool:
    email = (email or '').strip()
    if not email or len(email) > 254 or not _EMAIL_RE.match(email):
        return False
    # parseaddr rejette aussi certaines formes malformées que la regex laisse passer
    return bool(parseaddr(email)[1])


def _smtp_configured() -> bool:
    return bool(config.EMAIL_ADDRESS and config.EMAIL_APP_PASSWORD)


def _send(to_email: str, subject: str, body: str) -> bool:
    if not _smtp_configured():
        logger.warning("[email] SMTP non configuré (EMAIL_ADDRESS/EMAIL_APP_PASSWORD manquants), email non envoyé")
        return False
    if not _is_valid_email(to_email):
        logger.warning("[email] adresse destinataire invalide, envoi annulé")
        return False
    try:
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = _clean_header(subject)
        msg['From'] = config.EMAIL_ADDRESS
        msg['To'] = to_email
        with smtplib.SMTP('smtp.gmail.com', 587, timeout=10) as server:
            server.starttls()
            server.login(config.EMAIL_ADDRESS, config.EMAIL_APP_PASSWORD)
            server.send_message(msg)
        return True
    except smtplib.SMTPException as e:
        logger.error(f"[email] échec envoi SMTP: {e}")
        return False


def send_verification_email(to_email, firstname, token):
    """Best-effort : ne lève jamais d'exception, un échec d'envoi ne doit
    jamais faire planter le flux d'inscription."""
    firstname = _clean_header(firstname, max_len=100)
    verify_url = f'https://www.flinpay.cfd/verify-email/{token}'
    body = (
        f"Bonjour {firstname},\n\n"
        f"Merci de vous être inscrit sur Flinpay. Confirmez votre adresse email en "
        f"cliquant sur ce lien :\n\n{verify_url}\n\n"
        f"Si vous n'êtes pas à l'origine de cette inscription, ignorez cet email.\n\n"
        f"— L'équipe Flinpay"
    )
    _send(to_email, "Confirmez votre adresse email — Flinpay", body)


def send_payment_notification_email(merchant, tx):
    """Envoie un email au marchand quand il reçoit un paiement. Best-effort :
    ne bloque jamais le traitement du paiement si l'email échoue."""
    to_email = (merchant or {}).get('email')
    if not to_email:
        return
    amount = tx.get('amount')
    currency = _clean_header(tx.get('currency') or 'XOF', max_len=10)
    firstname = _clean_header((merchant.get('firstname') or ''), max_len=100)
    client_name = _clean_header(tx.get('client_name', '—'), max_len=200)
    client_phone = _clean_header(tx.get('client_phone', '—'), max_len=30)
    token = _clean_header(tx.get('token', '—'), max_len=60)
    body = (
        f"Bonjour {firstname},\n\n"
        f"Vous venez de recevoir un paiement sur Flinpay :\n\n"
        f"Montant : {amount} {currency}\n"
        f"Client : {client_name}\n"
        f"Téléphone : {client_phone}\n"
        f"Référence : {token}\n"
        f"Date : {datetime.utcnow().strftime('%d/%m/%Y %H:%M')} UTC\n\n"
        f"Connectez-vous à votre dashboard Flinpay pour voir le détail complet.\n\n"
        f"— L'équipe Flinpay"
    )
    _send(to_email, f"Nouveau paiement reçu — {amount} {currency}", body)
