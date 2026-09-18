"""
services/transactions.py — applique les effets de bord d'un changement de
statut de transaction (crédit du solde marchand, rapprochement facture,
webhook marchand, email de notification).

Centralisé ici et appelé par LES TROIS chemins qui peuvent faire passer une
transaction à 'paid' (synchro manuelle, polling client, webhook SoleasPay) —
voir routes/payments.py et routes/webhook_callback.py. Chacun de ces trois
appelants doit d'abord passer par sb_patch_if_pending() pour garantir que
settle_transaction() ne s'exécute qu'UNE SEULE FOIS par transaction, même si
deux chemins arrivent en même temps (protection contre le double crédit).
"""
import logging

from db.supabase import sb_get_one, sb_patch_multi
from services.billing import get_user_by_id, credit_user_balance
from services.email import send_payment_notification_email
from services.webhooks import dispatch_merchant_webhooks
from services.invoices import mark_invoice_paid_if_applicable

logger = logging.getLogger('flinpay.services.transactions')


def settle_transaction(tx: dict, new_status: str):
    if new_status == 'paid' and tx.get('payment_link_token'):
        link = sb_get_one('payment_links', 'token', tx['payment_link_token'])
        if link:
            sb_patch_multi('payment_links', {'token': tx['payment_link_token']}, {'paid_count': (link.get('paid_count') or 0) + 1})

    if new_status == 'paid':
        mark_invoice_paid_if_applicable(tx)

    if new_status == 'paid' and tx.get('user_id'):
        merchant = get_user_by_id(tx['user_id'])
        credit_user_balance(tx['user_id'], tx.get('currency') or 'XOF', tx.get('amount') or 0)
        send_payment_notification_email(merchant, tx)

    if new_status in ('paid', 'failed') and tx.get('user_id'):
        dispatch_merchant_webhooks(tx['user_id'], 'payment.success' if new_status == 'paid' else 'payment.failed', {
            'token': tx.get('token'), 'order_id': tx.get('order_id'), 'amount': tx.get('amount'),
            'status': new_status, 'client_name': tx.get('client_name'), 'client_phone': tx.get('client_phone')
        })
