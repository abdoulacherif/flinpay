"""
routes/webhook_callback.py — réception des événements de paiement entrants
(collection confirmée/échouée, paiement d'abonnement confirmé).

CHANGEMENT DE SÉCURITÉ IMPORTANT PAR RAPPORT À L'ANCIENNE INTÉGRATION
--------------------------------------------------------------------------
L'ancien webhook portait une signature (header x-private-key, vérifiée en
temps constant). La documentation de la nouvelle passerelle NE DÉCRIT AUCUNE
SIGNATURE pour son webhook — elle recommande explicitement de le traiter
comme un simple déclencheur et de revérifier l'état réel via un appel
authentifié à l'API avant toute action sensible.

Ce fichier suit donc ce principe à la lettre : le payload entrant n'est
JAMAIS utilisé comme source de vérité pour son propre statut. Il sert
uniquement à savoir QUELLE transaction re-vérifier ; le statut réellement
appliqué vient toujours d'un appel à gateway.collection_status(), authentifié
avec nos propres identifiants. Un attaquant qui poste un payload forgé avec
un statut "COMPLETED" ne peut donc rien obtenir : on ignore ce champ et on
va chercher la vérité nous-mêmes.

Cette route reste malgré tout rate-limitée et répond toujours HTTP 200 très
vite (même sur payload incomplet/inconnu) — c'est le comportement attendu
d'un endpoint de webhook : ne jamais laisser l'émetteur retenter en boucle
pour un cas qu'on ne pourra de toute façon jamais traiter.
"""
import logging
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify

from config import config
from extensions import limiter
from db.supabase import sb_get_eq, sb_get_one, sb_patch, sb_patch_if_pending, sb_patch_if_field_equals, sb_post
from services.billing import get_user_by_id, get_subscription_price
from services import gateway
from services.transactions import settle_transaction
from services.activity_log import log_user_activity

logger = logging.getLogger('flinpay.routes.webhook_callback')

webhook_callback_bp = Blueprint('webhook_callback', __name__)


def _handle_subscription_event(user: dict, subscription_reference: str):
    """Un événement pointe vers un abonnement en attente de confirmation
    (users.pending_upgrade_checkout_id). On revérifie l'état réel du dernier
    paiement de cet abonnement avant de faire quoi que ce soit — jamais sur
    la seule foi du webhook."""
    try:
        payments = gateway.subscription_payments(subscription_reference)
    except gateway.GatewayError as e:
        logger.info(f"[webhook] vérification abonnement impossible ({subscription_reference}): {e}")
        return

    items = payments if isinstance(payments, list) else payments.get('items', payments.get('data', []))
    has_paid = any((p.get('status') == 'PAID') for p in (items or []))
    if not has_paid:
        return

    # Transition atomique : seule la requête qui trouve encore
    # pending_upgrade_checkout_id == subscription_reference applique la mise à
    # niveau — empêche un double traitement si deux événements arrivent en
    # même temps pour le même abonnement.
    won = sb_patch_if_field_equals('users', 'id', user['id'], 'pending_upgrade_checkout_id', subscription_reference, {
        'plan': 'pro',
        'plan_expires_at': (datetime.utcnow() + timedelta(days=30)).isoformat(),
        'pending_upgrade_checkout_id': None,
    })
    if not won:
        return  # déjà traité par un autre appel concurrent

    log_user_activity(user['id'], 'subscription_confirmed', {'reference': subscription_reference})

    if user.get('referred_by'):
        commission = round(get_subscription_price() * config.REFERRAL_COMMISSION_RATE, 2)
        sb_post('referral_earnings', {
            'referrer_id': user['referred_by'], 'referred_id': user['id'], 'amount': commission,
            'source': 'subscription', 'created_at': datetime.utcnow().isoformat()
        })
        referrer = get_user_by_id(user['referred_by'])
        new_balance = (referrer.get('referral_balance') or 0) + commission
        sb_patch('users', 'id', user['referred_by'], {'referral_balance': new_balance})


@webhook_callback_bp.route('/webhook/payment-events', methods=['POST'])
@limiter.limit('120 per minute')
def webhook_payment_events():
    payload = request.get_json(silent=True) or {}
    # On ne journalise jamais le payload complet, même en DEBUG : on ne lui
    # fait pas confiance de toute façon, autant ne pas le conserver.
    logger.debug(f"[webhook] reçu, operation={payload.get('operation')}")

    transaction_reference = payload.get('transaction_reference')
    if not transaction_reference:
        return jsonify({'received': True}), 200

    # Cas 1 : référence d'abonnement en attente de confirmation.
    pending_users = sb_get_eq('users', 'pending_upgrade_checkout_id', transaction_reference)
    if pending_users:
        _handle_subscription_event(pending_users[0], transaction_reference)
        return jsonify({'received': True}), 200

    # Cas 2 : transaction de collection normale.
    tx = sb_get_one('transactions', 'gateway_reference', transaction_reference)
    if not tx:
        return jsonify({'received': True}), 200

    if tx['status'] != 'pending':
        return jsonify({'received': True}), 200

    # Revérification défensive : jamais le statut du payload, toujours celui
    # renvoyé par un appel authentifié à la passerelle.
    try:
        status_data = gateway.collection_status(transaction_reference)
    except gateway.GatewayError as e:
        logger.info(f"[webhook] statut indisponible pour {transaction_reference}: {e}")
        return jsonify({'received': True}), 200

    new_status = gateway.map_remote_status(status_data.get('status'))
    if new_status == tx['status']:
        return jsonify({'received': True}), 200

    update = {'status': new_status}
    if new_status == 'paid':
        update['paid_at'] = datetime.utcnow().isoformat()

    # Transition atomique — voir la docstring en tête de fichier.
    if not sb_patch_if_pending('transactions', 'token', tx['token'], update):
        return jsonify({'received': True}), 200

    settle_transaction(tx, new_status)
    return jsonify({'received': True}), 200


# NOTE — décaissements (retraits) : la documentation ne détaille pas de
# webhook dédié aux disbursements ; les statuts de payout restent mis à jour
# manuellement par un admin (routes/admin/payouts.py) après vérification
# via gateway.disbursement_status(). Si un webhook de disbursement existe
# réellement côté passerelle, ajouter ici un traitement symétrique au cas
# collection ci-dessus (même principe : ne jamais faire confiance au
# payload, toujours revérifier via disbursement_status()).
