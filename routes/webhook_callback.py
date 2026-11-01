import hashlib
import hmac
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


def _verify_private_key() -> bool:
    token = config.GATEWAY_WEBHOOK_TOKEN
    if not token:
        return True
    provided = request.headers.get('x-private-key', '')
    expected = hashlib.sha256(token.encode()).hexdigest()
    return hmac.compare_digest(provided, expected)


def _handle_subscription_event(user: dict, subscription_reference: str):
    try:
        payments = gateway.subscription_payments(subscription_reference)
    except gateway.GatewayError as e:
        logger.info(f"[webhook] abonnement introuvable: {e}")
        return

    items = payments if isinstance(payments, list) else payments.get('items', payments.get('data', []))
    has_paid = any((p.get('status') == 'PAID') for p in (items or []))
    if not has_paid:
        return

    won = sb_patch_if_field_equals('users', 'id', user['id'], 'pending_upgrade_checkout_id', subscription_reference, {
        'plan': 'pro',
        'plan_expires_at': (datetime.utcnow() + timedelta(days=30)).isoformat(),
        'pending_upgrade_checkout_id': None,
    })
    if not won:
        return

    log_user_activity(user['id'], 'subscription_confirmed', {'reference': subscription_reference})

    if user.get('referred_by'):
        commission = round(get_subscription_price() * config.REFERRAL_COMMISSION_RATE, 2)
        already_paid = sb_get_eq(
            'referral_earnings', 'referred_id', user['id'],
            extra_query=f"referrer_id=eq.{user['referred_by']}&source=eq.subscription",
        )
        if not already_paid:
            sb_post('referral_earnings', {
                'referrer_id': user['referred_by'], 'referred_id': user['id'],
                'amount': commission, 'source': 'subscription',
                'created_at': datetime.utcnow().isoformat(),
            })
            referrer = get_user_by_id(user['referred_by'])
            new_balance = (referrer.get('referral_balance') or 0) + commission
            sb_patch('users', 'id', user['referred_by'], {'referral_balance': new_balance})


@webhook_callback_bp.route('/webhook/payment-events', methods=['POST'])
@limiter.limit('120 per minute')
def webhook_payment_events():
    if not _verify_private_key():
        logger.warning("[webhook] x-private-key invalide")
        return jsonify({'received': True}), 200

    payload = request.get_json(silent=True) or {}
    transaction_reference = payload.get('transaction_reference')
    if not transaction_reference:
        return jsonify({'received': True}), 200

    pending_users = sb_get_eq('users', 'pending_upgrade_checkout_id', transaction_reference)
    if pending_users:
        _handle_subscription_event(pending_users[0], transaction_reference)
        return jsonify({'received': True}), 200

    tx = sb_get_one('transactions', 'gateway_reference', transaction_reference)
    if not tx:
        return jsonify({'received': True}), 200

    if tx['status'] != 'pending':
        return jsonify({'received': True}), 200

    try:
        created_at = datetime.fromisoformat(tx['created_at'].replace('Z', '+00:00')).replace(tzinfo=None)
        if (datetime.utcnow() - created_at) > timedelta(hours=24):
            return jsonify({'received': True}), 200
    except (ValueError, TypeError):
        return jsonify({'received': True}), 200

    try:
        status_data = gateway.collection_status(transaction_reference)
    except gateway.GatewayError as e:
        logger.info(f"[webhook] statut indisponible: {e}")
        return jsonify({'received': True}), 200

    new_status = gateway.map_remote_status(status_data.get('status'))
    if new_status == tx['status']:
        return jsonify({'received': True}), 200

    update = {'status': new_status}
    if new_status == 'paid':
        update['paid_at'] = datetime.utcnow().isoformat()

    if not sb_patch_if_pending('transactions', 'token', tx['token'], update):
        return jsonify({'received': True}), 200

    settle_transaction(tx, new_status)
    return jsonify({'received': True}), 200