import logging
from datetime import datetime

from db.supabase import sb_patch, sb_post, sb_get_eq
from services.billing import credit_user_balance

logger = logging.getLogger('flinpay.transactions')


def settle_transaction(tx: dict, new_status: str):
    """Applique les effets de bord d'un changement de statut de transaction.
    Appelé UNIQUEMENT après avoir gagné la transition atomique
    (sb_patch_if_pending a renvoyé True)."""

    if new_status == 'paid':
        try:
            amount = float(tx.get('amount') or 0)
            currency = tx.get('currency') or 'XOF'
            credit_user_balance(tx['user_id'], currency, amount)

            from services.billing import credit_fp_for_transaction
            credit_fp_for_transaction(tx['user_id'], amount, tx['token'])
        except Exception as e:
            logger.error(f"[settle_transaction] credit failed for {tx.get('token')}: {e}")

        # Notification (best-effort)
        try:
            from services.email import send_payment_notification_email
            from services.billing import get_user_by_id
            merchant = get_user_by_id(tx['user_id'])
            if merchant:
                send_payment_notification_email(merchant, tx)
        except Exception:
            pass

    # ── Webhooks marchand (payment.success / payment.failed) ──
    try:
        from services.webhooks import dispatch_merchant_webhooks
        event = 'payment.success' if new_status == 'paid' else 'payment.failed'
        dispatch_merchant_webhooks(tx['user_id'], event, tx)
    except Exception as e:
        logger.warning(f"[settle_transaction] webhook dispatch failed: {e}")