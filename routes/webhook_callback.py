"""
routes/webhook_callback.py — réception du webhook SoleasPay entrant (paiement
confirmé/remboursé côté opérateur mobile money).

C'est la route la plus sensible de toute l'application : elle est PUBLIQUE
(SoleasPay ne peut pas envoyer de cookie de session) et peut déclencher un
crédit de solde marchand. Toute sa sécurité repose sur :
  1. La vérification de signature (soleaspay_verify_callback_signature),
     comparée en temps constant — voir services/soleaspay.py.
  2. sb_patch_if_pending, qui garantit qu'un même paiement ne peut être
     crédité qu'une seule fois même si SoleasPay renvoie le même webhook
     plusieurs fois (ce qui arrive en pratique : la plupart des fournisseurs
     de paiement retentent l'envoi si votre serveur ne répond pas assez vite).
"""
import logging
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify

from extensions import limiter
from db.supabase import sb_get_eq, sb_get_one, sb_patch, sb_patch_if_pending, sb_post
from services.billing import get_user_by_id, get_subscription_price
from services.soleaspay import soleaspay_verify_callback_signature
from services.transactions import settle_transaction
from config import config

logger = logging.getLogger('flinpay.routes.webhook_callback')

webhook_callback_bp = Blueprint('webhook_callback', __name__)


@webhook_callback_bp.route('/webhook/soleaspay', methods=['POST'])
@limiter.limit('120 per minute')
def webhook_soleaspay():
    signature = request.headers.get('x-private-key', '')
    payload = request.get_json(silent=True) or {}
    # On ne journalise plus le payload/les en-têtes complets (ils peuvent
    # contenir la signature et des données de paiement) — seulement au niveau
    # DEBUG, désactivé par défaut en production (voir extensions.py).
    logger.debug(f"[webhook_soleaspay] reçu, status={payload.get('status')}")

    if not soleaspay_verify_callback_signature(signature):
        logger.warning("[webhook_soleaspay] signature invalide — requête rejetée")
        return jsonify({'ok': False, 'error': 'Signature invalide'}), 401

    remote_status = payload.get('status')  # SUCCESS | RECEIVED | REFUND
    tx_data = payload.get('data', {})
    external_reference = tx_data.get('external_reference')  # notre order_id/token

    if not external_reference or not remote_status:
        return jsonify({'ok': False, 'error': 'Payload incomplet'}), 400

    status_map = {'SUCCESS': 'paid', 'REFUND': 'failed'}

    # Cas 1 : c'est un paiement d'abonnement Pro (pas une transaction normale)
    pending_users = sb_get_eq('users', 'pending_upgrade_checkout_id', external_reference)
    if pending_users:
        if status_map.get(remote_status) == 'paid':
            u = pending_users[0]
            sb_patch('users', 'id', u['id'], {
                'plan': 'pro',
                'plan_expires_at': (datetime.utcnow() + timedelta(days=30)).isoformat(),
                'pending_upgrade_checkout_id': None
            })
            if u.get('referred_by'):
                commission = round(get_subscription_price() * config.REFERRAL_COMMISSION_RATE, 2)
                sb_post('referral_earnings', {
                    'referrer_id': u['referred_by'], 'referred_id': u['id'], 'amount': commission,
                    'source': 'subscription', 'created_at': datetime.utcnow().isoformat()
                })
                referrer = get_user_by_id(u['referred_by'])
                new_balance = (referrer.get('referral_balance') or 0) + commission
                sb_patch('users', 'id', u['referred_by'], {'referral_balance': new_balance})
        return jsonify({'ok': True, 'note': 'abonnement traité'}), 200

    # Cas 2 : transaction normale
    tx = sb_get_one('transactions', 'token', external_reference)
    if not tx:
        return jsonify({'ok': True, 'note': 'transaction inconnue'}), 200

    new_status = status_map.get(remote_status, tx.get('status'))
    update = {'status': new_status}
    if new_status == 'paid':
        update['paid_at'] = datetime.utcnow().isoformat()

    # Transition atomique — voir la docstring en tête de fichier.
    if not sb_patch_if_pending('transactions', 'token', tx['token'], update):
        return jsonify({'ok': True, 'note': 'déjà traitée'}), 200

    settle_transaction(tx, new_status)
    return jsonify({'ok': True}), 200
