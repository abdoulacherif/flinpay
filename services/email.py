import logging
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import parseaddr

from config import config

logger = logging.getLogger('flinpay.email')

_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

def _clean_header(value: str, max_len: int = 200) -> str:
    value = str(value or '')
    value = re.sub(r'[\r\n\x00-\x1f]', ' ', value).strip()
    return value[:max_len]

def _is_valid_email(email: str) -> bool:
    email = (email or '').strip()
    if not email or len(email) > 254 or not _EMAIL_RE.match(email):
        return False
    return bool(parseaddr(email)[1])

def _smtp_configured() -> bool:
    return bool(config.EMAIL_ADDRESS and config.EMAIL_APP_PASSWORD)

def _send(to_email: str, subject: str, text_body: str, html_body: str = None) -> bool:
    if not _smtp_configured():
        logger.warning("[email] SMTP non configuré")
        return False
    if not _is_valid_email(to_email):
        logger.warning("[email] Adresse destinataire invalide")
        return False

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = _clean_header(subject)
        msg['From'] = f"Flinpay <{config.EMAIL_ADDRESS}>"
        msg['To'] = to_email

        msg.attach(MIMEText(text_body, 'plain', 'utf-8'))
        if html_body:
            msg.attach(MIMEText(html_body, 'html', 'utf-8'))

        with smtplib.SMTP('smtp.gmail.com', 587, timeout=10) as server:
            server.starttls()
            server.login(config.EMAIL_ADDRESS, config.EMAIL_APP_PASSWORD)
            server.send_message(msg)
        return True
    except smtplib.SMTPException as e:
        logger.error(f"[email] échec envoi SMTP: {e}")
        return False


def send_verification_email(to_email, firstname, token):
    firstname = _clean_header(firstname, max_len=100)
    verify_url = f'https://www.flinpay.cfd/verify-email/{token}'
    
    text = (
        f"Bonjour {firstname},\n\n"
        f"Merci de vous être inscrit sur Flinpay. Confirmez votre adresse email en "
        f"cliquant sur ce lien :\n\n{verify_url}\n\n"
        f"Si vous n'êtes pas à l'origine de cette inscription, ignorez cet email.\n\n"
        f"— L'équipe Flinpay"
    )
    
    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #0A6CFF;">Bienvenue sur Flinpay</h2>
        <p>Bonjour {firstname},</p>
        <p>Merci de vous être inscrit. Confirmez votre adresse email pour activer votre compte :</p>
        <a href="{verify_url}" style="display:inline-block; padding:12px 24px; background:#0A6CFF; color:white; text-decoration:none; border-radius:8px; font-weight:bold; margin: 20px 0;">
            Confirmer mon email
        </a>
        <p style="font-size: 13px; color: #666;">Si le bouton ne fonctionne pas, copiez ce lien : <br>{verify_url}</p>
        <p style="font-size: 13px; color: #666;">Si vous n'êtes pas à l'origine de cette inscription, ignorez cet email.</p>
    </div>
    """
    _send(to_email, "Confirmez votre adresse email — Flinpay", text, html)


def send_login_magic_link_email(to_email, firstname, magic_url, backup_code):
    firstname = _clean_header(firstname, max_len=100)
    
    text = (
        f"Bonjour {firstname},\n\n"
        f"Voici votre lien de connexion sécurisé :\n{magic_url}\n\n"
        f"Code de secours : {backup_code}\n\n"
        f"Ce lien expire dans 15 minutes.\n\n— L'équipe Flinpay"
    )
    
    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #0A6CFF;">Connexion sécurisée</h2>
        <p>Bonjour {firstname},</p>
        <p>Vous avez demandé à vous connecter à Flinpay. Cliquez sur le bouton ci-dessous :</p>
        <a href="{magic_url}" style="display:inline-block; padding:12px 24px; background:#0A6CFF; color:white; text-decoration:none; border-radius:8px; font-weight:bold; margin: 20px 0;">
            Me connecter
        </a>
        <p style="font-size: 13px; color: #666;">Ce lien expire dans 15 minutes. Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.</p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
        <p style="font-size: 14px;">Votre code de secours :</p>
        <p style="font-size: 24px; font-family: monospace; letter-spacing: 4px; font-weight: bold; background: #f4f4f4; padding: 10px; display: inline-block; border-radius: 6px;">{backup_code}</p>
    </div>
    """
    _send(to_email, "Votre lien de connexion sécurisé Flinpay", text, html)


def send_password_reset_email(to_email, firstname, reset_url):
    firstname = _clean_header(firstname, max_len=100)
    
    text = (
        f"Bonjour {firstname},\n\n"
        f"Vous avez demandé à réinitialiser votre mot de passe Flinpay.\n"
        f"Cliquez sur ce lien pour choisir un nouveau mot de passe :\n\n"
        f"{reset_url}\n\n"
        f"Ce lien expire dans 1 heure. Si vous n'êtes pas à l'origine de cette "
        f"demande, ignorez cet email — votre mot de passe restera inchangé.\n\n"
        f"— L'équipe Flinpay"
    )
    
    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #0A6CFF;">Réinitialisation de mot de passe</h2>
        <p>Bonjour {firstname},</p>
        <p>Vous avez demandé à réinitialiser votre mot de passe Flinpay.</p>
        <a href="{reset_url}" style="display:inline-block; padding:12px 24px; background:#0A6CFF; color:white; text-decoration:none; border-radius:8px; font-weight:bold; margin: 20px 0;">
            Choisir un nouveau mot de passe
        </a>
        <p style="font-size: 13px; color: #666;">Ce lien expire dans 1 heure. Si vous n'êtes pas à l'origine de cette demande, ignorez cet email — votre mot de passe restera inchangé.</p>
        <p style="font-size: 13px; color: #666;">Si le bouton ne fonctionne pas, copiez ce lien : <br>{reset_url}</p>
    </div>
    """
    _send(to_email, "Réinitialisation de votre mot de passe — Flinpay", text, html)


def send_payment_notification_email(merchant, tx):
    to_email = (merchant or {}).get('email')
    if not to_email:
        return
    amount = tx.get('amount')
    currency = _clean_header(tx.get('currency') or 'XOF', max_len=10)
    firstname = _clean_header((merchant.get('firstname') or ''), max_len=100)
    client_name = _clean_header(tx.get('client_name', '—'), max_len=200)
    
    text = (
        f"Bonjour {firstname},\n\n"
        f"Vous venez de recevoir un paiement de {amount} {currency} de {client_name}.\n\n"
        f"Connectez-vous à votre dashboard pour voir le détail.\n\n— L'équipe Flinpay"
    )
    _send(to_email, f"Nouveau paiement reçu — {amount} {currency}", text)