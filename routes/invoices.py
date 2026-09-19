"""
routes/invoices.py — factures : gestion côté marchand (cookie de session) et
paiement côté client final (public, sans session).
"""
import logging
import uuid as uuid_lib
from datetime import datetime

from flask import Blueprint, request, jsonify, render_template

from config import config
from extensions import limiter
from db.supabase import sb_get_eq, sb_get_one, sb_post, sb_patch_multi, sb_delete_multi
from services.auth import user_required, get_current_user, csrf_protect
from services.restrictions import is_login_blocked, is_country_blocked, is_operator_blocked
from services.activity_log import log_user_activity
from services.billing import get_user_by_id, get_currency_for_country, check_quota, amount_with_markup
from services import gateway
from services import fx
from services.invoices import generate_invoice_number, compute_invoice_amount, clean_invoice_items
from services.tracking import get_request_client_info

logger = logging.getLogger('flinpay.routes.invoices')

invoices_bp = Blueprint('invoices', __name__)


@invoices_bp.route('/invoices')
@user_required
def invoices_page():
    return render_template('invoices.html', user=get_current_user())


@invoices_bp.route('/api/invoices', methods=['GET'])
@user_required
def api_get_invoices():
    invoices = sb_get_eq('invoices', 'user_id', request.user_id, extra_query='order=created_at.desc')
    return jsonify({'ok': True, 'invoices': invoices})


@invoices_bp.route('/api/invoices', methods=['POST'])
@user_required
@csrf_protect
def api_create_invoice():
    data = request.get_json() or {}
    client_name = (data.get('client_name') or '').strip()[:200]
    if not client_name:
        return jsonify({'ok': False, 'error': 'Le nom du client est requis'}), 400

    cleaned_items, err = clean_invoice_items(data.get('items') or [])
    if err:
        return jsonify({'ok': False, 'error': err}), 400

    amount = compute_invoice_amount(cleaned_items)
    if amount < config.GATEWAY_MIN_AMOUNT:
        return jsonify({'ok': False, 'error': f'Montant total minimum : {config.GATEWAY_MIN_AMOUNT} XOF'}), 400

    token = 'inv_' + uuid_lib.uuid4().hex[:12]
    row = sb_post('invoices', {
        'token': token, 'user_id': request.user_id,
        'invoice_number': generate_invoice_number(request.user_id),
        'client_name': client_name,
        'client_email': (data.get('client_email') or '').strip()[:200] or None,
        'client_phone': (data.get('client_phone') or '').strip()[:30] or None,
        'items': cleaned_items, 'currency': 'XOF', 'amount': amount, 'status': 'draft',
        'due_date': data.get('due_date') or None,
        'notes': (data.get('notes') or '').strip()[:1000] or None,
        'created_at': datetime.utcnow().isoformat()
    })
    if not row or (isinstance(row, dict) and row.get('_error')):
        return jsonify({'ok': False, 'error': 'Erreur lors de la création de la facture'}), 500
    return jsonify({'ok': True, 'invoice': row[0] if isinstance(row, list) else row})


@invoices_bp.route('/api/invoices/<token>', methods=['PUT'])
@user_required
@csrf_protect
def api_update_invoice(token):
    invoice = sb_get_one('invoices', 'token', token)
    if not invoice or invoice.get('user_id') != request.user_id:
        return jsonify({'ok': False, 'error': 'Introuvable'}), 404
    if invoice.get('status') == 'paid':
        return jsonify({'ok': False, 'error': 'Une facture payée ne peut plus être modifiée'}), 400

    data = request.get_json() or {}
    allowed = {}
    if 'status' in data and data['status'] in ('draft', 'sent', 'cancelled'):
        allowed['status'] = data['status']
        if data['status'] == 'sent' and not invoice.get('sent_at'):
            allowed['sent_at'] = datetime.utcnow().isoformat()
    if 'client_name' in data and (data.get('client_name') or '').strip():
        allowed['client_name'] = data['client_name'].strip()[:200]
    if 'client_email' in data:
        allowed['client_email'] = (data.get('client_email') or '').strip()[:200] or None
    if 'client_phone' in data:
        allowed['client_phone'] = (data.get('client_phone') or '').strip()[:30] or None
    if 'due_date' in data:
        allowed['due_date'] = data.get('due_date') or None
    if 'notes' in data:
        allowed['notes'] = (data.get('notes') or '').strip()[:1000] or None
    if 'items' in data:
        cleaned_items, err = clean_invoice_items(data.get('items') or [])
        if err:
            return jsonify({'ok': False, 'error': err}), 400
        allowed['items'] = cleaned_items
        allowed['amount'] = compute_invoice_amount(cleaned_items)

    if not allowed:
        return jsonify({'ok': False, 'error': 'Aucun champ à mettre à jour'}), 400

    ok = sb_patch_multi('invoices', {'token': token, 'user_id': request.user_id}, allowed)
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la mise à jour'}), 500
    return jsonify({'ok': True})


@invoices_bp.route('/api/invoices/<token>', methods=['DELETE'])
@user_required
@csrf_protect
def api_delete_invoice(token):
    ok = sb_delete_multi('invoices', {'token': token, 'user_id': request.user_id})
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la suppression'}), 500
    return jsonify({'ok': True})


# ── Page publique : facture ─────────────────────────
@invoices_bp.route('/invoice/<token>')
def invoice_view(token):
    invoice = sb_get_one('invoices', 'token', token)
    merchant = get_user_by_id(invoice['user_id']) if invoice else {}
    return render_template('invoice_view.html', invoice=invoice, merchant=merchant, token=token,
                            countries_operators=gateway.build_countries_operators([c['code'] for c in config.COUNTRIES]),
                            available_countries=config.COUNTRIES)


@invoices_bp.route('/api/invoice-pay/<token>', methods=['POST'])
@limiter.limit('30 per minute')
def api_invoice_pay(token):
    invoice = sb_get_one('invoices', 'token', token)
    if not invoice:
        return jsonify({'ok': False, 'error': 'Facture introuvable'}), 404
    if invoice.get('status') == 'paid':
        return jsonify({'ok': False, 'error': 'Cette facture est déjà payée'}), 400
    if invoice.get('status') == 'cancelled':
        return jsonify({'ok': False, 'error': 'Cette facture a été annulée'}), 400

    allowed, quota_error = check_quota(invoice['user_id'])
    if not allowed:
        return jsonify({'ok': False, 'error': quota_error}), 403

    data = request.get_json() or {}
    phone = (data.get('phone') or invoice.get('client_phone') or '').strip()
    operator = data.get('operator', '')
    customer_country = data.get('country', '')
    if not phone:
        return jsonify({'ok': False, 'error': 'Numéro de téléphone requis'}), 400
    if not customer_country:
        return jsonify({'ok': False, 'error': 'Pays requis'}), 400

    amount = invoice['amount']
    merchant = get_user_by_id(invoice['user_id'])
    merchant_currency = get_currency_for_country(merchant.get('country'))

    if is_login_blocked(merchant) or is_country_blocked(merchant, customer_country) or is_operator_blocked(merchant, operator):
        log_user_activity(invoice['user_id'], 'payment_blocked', {'country': customer_country, 'operator': operator, 'via': 'invoice'})
        return jsonify({'ok': False, 'error': "Ce moyen de paiement est actuellement indisponible pour ce marchand"}), 403

    service = gateway.find_service(customer_country, operator, for_operation='collect')
    if not service:
        return jsonify({'ok': False, 'error': "Opérateur indisponible pour ce pays"}), 400

    base_price = amount if merchant_currency == service['currency'] else fx.convert(amount, merchant_currency, service['currency'])
    if base_price is None:
        return jsonify({'ok': False, 'error': f"Ce moyen de paiement ({service['currency']}) n'est pas encore compatible avec cette facture ({merchant_currency})"}), 400
    base_amount = amount_with_markup(base_price)

    result = gateway.collect_payment(
        base_amount=base_amount, currency=service['currency'], service=service,
        customer_wallet=phone, description=f"Facture {invoice['invoice_number']}",
        invoice_reference=invoice['invoice_number'],
    )
    if not result['ok']:
        return jsonify({'ok': False, 'error': result['error']}), 502

    tx_token = 'fp_tx_' + uuid_lib.uuid4().hex[:20]
    customer_name = invoice.get('client_name') or 'Client'

    tx = sb_post('transactions', {
        'token': tx_token, 'order_id': invoice['invoice_number'], 'amount': base_price,
        'client_amount': result['customer_charge'], 'fee_amount': round(result['customer_charge'] - base_price, 2),
        'client_name': customer_name, 'client_phone': phone, 'country': merchant.get('country', ''),
        'currency': service['currency'], 'status': 'pending', 'environment': 'production',
        'user_id': invoice['user_id'], 'operator': operator,
        'gateway_reference': result['transaction_reference'], 'invoice_token': token,
        **get_request_client_info(),
        'created_at': datetime.utcnow().isoformat()
    })
    if not tx or (isinstance(tx, dict) and tx.get('_error')):
        return jsonify({'ok': False, 'error': 'Erreur lors de la création du paiement'}), 500

    log_user_activity(invoice['user_id'], 'payment_created', {'token': tx_token, 'amount': base_price, 'via': 'invoice'})
    return jsonify({
        'ok': True, 'tx_token': tx_token,
        'confirmation_helper': result.get('confirmation_helper'),
        'message': 'Une confirmation de paiement a été envoyée sur le téléphone du client.'
    })
