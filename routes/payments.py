"""
routes/payments.py — cœur du système de paiement : API directe (clé API),
liens de paiement publics, suivi de statut.

Réécrit pour le nouveau flux de la passerelle de paiement : chaque
encaissement se fait en intent -> execute (voir services/gateway.collect_payment),
puis le statut est interrogé par polling (jamais fait confiance à un webhook
seul, voir services/gateway.py et routes/webhook_callback.py).

Avant toute création de paiement, on vérifie aussi les restrictions
anti-fraude du marchand (services/restrictions.py) : pays ou opérateur
bloqués spécifiquement pour ce compte. Un compte no_login/banned ne peut de
toute façon plus se connecter (@user_required s'en charge) ni utiliser de
clé API (vérifié ici pour /api/pay, qui ne passe pas par une session).

Deux familles de routes, avec des modèles d'auth différents :
  - Routes marchand (cookie de session) : gestion des liens de paiement,
    export CSV, synchro manuelle — protégées par @user_required (+ @csrf_protect).
  - Routes publiques (aucune session) : /pay/<token>, /api/pay-link/<token>,
    /api/pay-status/<token> — utilisées par le CLIENT du marchand pour payer.
  - Route API pure (clé API Bearer) : /api/pay — utilisée par les serveurs
    des marchands eux-mêmes ; pas de cookie, donc pas de CSRF à prévoir.
"""
import csv
import hashlib
import io
import logging
import uuid as uuid_lib
from datetime import datetime

from flask import Blueprint, request, jsonify, render_template, Response

from config import config
from extensions import limiter
from db.supabase import (
    sb_get_eq, sb_get_one, sb_post, sb_patch, sb_patch_multi,
    sb_patch_if_pending, sb_delete_multi, sb_storage_upload, sb_storage_public_url,
)
from services.auth import user_required, get_current_user, csrf_protect
from services.billing import (
    get_user_by_id, get_currency_for_country, check_quota,
    link_amount_with_markup, api_amount_with_markup,
)
from services.restrictions import is_login_blocked, is_country_blocked, is_operator_blocked
from services.activity_log import log_user_activity
from services import gateway
from services import fx
from services.transactions import settle_transaction
from services.tracking import get_request_client_info

logger = logging.getLogger('flinpay.routes.payments')

payments_bp = Blueprint('payments', __name__)


def _localize_merchant_price(price, merchant_currency, service_currency):
    """Convertit le prix du marchand vers la devise du service choisi par le
    client. Retourne None si la paire de devises n'est pas convertible (voir
    services/fx.py) — l'appelant doit alors refuser proprement plutôt que de
    deviner un taux."""
    if merchant_currency == service_currency:
        return price
    return fx.convert(price, merchant_currency, service_currency)


def _check_merchant_restrictions(merchant: dict, country_code: str, operator_code: str):
    """Retourne un message d'erreur si ce marchand n'est pas autorisé à
    encaisser sur ce corridor pays/opérateur précis (restriction anti-fraude
    ciblée, voir services/restrictions.py), sinon None. Le blocage
    no_login/banned global est déjà couvert ailleurs (@user_required pour les
    routes en session, vérifié explicitement ici pour /api/pay qui utilise
    une clé API et ne passe pas par cette dépendance)."""
    if is_login_blocked(merchant):
        return "Ce compte marchand est actuellement restreint."
    if is_country_blocked(merchant, country_code):
        return "Ce corridor pays est actuellement indisponible pour ce compte."
    if is_operator_blocked(merchant, operator_code):
        return "Cet opérateur est actuellement indisponible pour ce compte."
    return None


# ── API directe (authentification par clé API) ──────
@payments_bp.route('/api/pay', methods=['POST'])
@limiter.limit('60 per minute')
def api_pay():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'ok': False, 'error': 'Clé API requise'}), 401
    provided_key = auth.replace('Bearer ', '', 1).strip()
    key_hash = hashlib.sha256(provided_key.encode()).hexdigest()

    key_row = sb_get_one('api_keys', 'key_hash', key_hash)
    if not key_row or not key_row.get('active'):
        return jsonify({'ok': False, 'error': 'Clé API invalide ou révoquée'}), 401
    user_id = key_row['user_id']
    environment = key_row.get('environment', 'live')
    sb_patch('api_keys', 'id', key_row['id'], {'last_used_at': datetime.utcnow().isoformat()})

    merchant = get_user_by_id(user_id)
    if not merchant:
        return jsonify({'ok': False, 'error': 'Compte marchand introuvable'}), 401

    data = request.get_json()
    if not data:
        return jsonify({'ok': False, 'error': 'Données manquantes'}), 400

    for field in ['amount', 'phone', 'client_name', 'order_id']:
        if not data.get(field):
            return jsonify({'ok': False, 'error': f'Champ manquant: {field}'}), 400
    try:
        amount = float(data['amount'])
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'Montant invalide'}), 400
    if amount <= 0:
        return jsonify({'ok': False, 'error': 'Montant invalide'}), 400

    if environment != 'sandbox':
        allowed, quota_error = check_quota(user_id)
        if not allowed:
            return jsonify({'ok': False, 'error': quota_error}), 403

    token = 'fp_tx_' + uuid_lib.uuid4().hex[:20]
    env_label = 'sandbox' if environment == 'sandbox' else 'production'

    country_code = data.get('country', '')
    merchant_currency = next((c['currency'] for c in config.COUNTRIES if c['code'] == country_code), 'XOF')
    operator = data.get('operator', '')

    if env_label == 'production':
        restriction_error = _check_merchant_restrictions(merchant, country_code, operator)
        if restriction_error:
            log_user_activity(user_id, 'payment_blocked', {'country': country_code, 'operator': operator, 'via': 'api'})
            return jsonify({'ok': False, 'error': restriction_error}), 403

    client_info = get_request_client_info()
    tx_payload = {
        'token': token,
        'order_id': str(data['order_id'])[:120],
        'amount': amount,
        'client_name': str(data['client_name'])[:120],
        'client_phone': str(data['phone'])[:30],
        'country': country_code,
        'currency': merchant_currency,
        'status': 'pending',
        'environment': env_label,
        'user_id': user_id,
        'operator': operator,
        'user_agent': (str(data.get('customer_user_agent') or client_info['user_agent']))[:500],
        'ip_address': (str(data.get('customer_ip') or client_info['ip_address']))[:100],
        'referer_url': (str(data.get('customer_referrer') or client_info['referer_url']))[:500],
        'created_at': datetime.utcnow().isoformat()
    }

    if env_label == 'production':
        service = gateway.find_service(country_code, operator, for_operation='collect')
        if not service:
            return jsonify({'ok': False, 'error': f"Opérateur '{operator}' non disponible pour le pays '{country_code}'"}), 400

        base_price = _localize_merchant_price(amount, merchant_currency, service['currency'])
        if base_price is None:
            return jsonify({'ok': False, 'error': f"Devise {service['currency']} non compatible avec {merchant_currency} pour le moment"}), 400
        base_amount = api_amount_with_markup(base_price, operator)

        result = gateway.collect_payment(
            base_amount=base_amount, currency=service['currency'], service=service,
            customer_wallet=data['phone'], description=f"Commande {data['order_id']}",
            invoice_reference=data['order_id'],
        )
        if not result['ok']:
            return jsonify({'ok': False, 'error': result['error']}), 502

        tx_payload['currency'] = service['currency']
        tx_payload['gateway_reference'] = result['transaction_reference']
        tx_payload['client_amount'] = result['customer_charge']
        tx_payload['amount'] = base_price  # le marchand reçoit son prix plein, jamais la marge Flinpay
        tx_payload['fee_amount'] = round(result['customer_charge'] - base_price, 2)

    tx = sb_post('transactions', tx_payload)
    if not tx or (isinstance(tx, dict) and tx.get('_error')):
        logger.error(f"[api_pay] échec création transaction pour user={user_id}")
        return jsonify({'ok': False, 'error': 'Erreur lors de la création de la transaction'}), 500

    log_user_activity(user_id, 'payment_created', {'token': token, 'amount': tx_payload['amount'], 'via': 'api'})
    return jsonify({
        'ok': True, 'token': token, 'order_id': data['order_id'], 'amount': tx_payload['amount'], 'status': 'pending',
        'message': 'Une notification a été envoyée sur le téléphone du client pour confirmer le paiement.'
    })


# ── Historique / gestion (marchand connecté) ────────
@payments_bp.route('/transactions')
@user_required
def transactions_page():
    return render_template('transactions.html', user=get_current_user())


@payments_bp.route('/sandbox')
@user_required
def sandbox():
    return render_template('sandbox.html', user=get_current_user())


@payments_bp.route('/api/transactions', methods=['GET'])
@user_required
def api_get_transactions():
    txs = sb_get_eq('transactions', 'user_id', request.user_id, extra_query='order=created_at.desc&limit=100')
    return jsonify({'ok': True, 'transactions': txs})


@payments_bp.route('/api/transactions/export', methods=['GET'])
@user_required
def api_export_transactions():
    txs = sb_get_eq('transactions', 'user_id', request.user_id, extra_query='order=created_at.desc')
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Client', 'Montant', 'Statut', 'Pays', 'Date'])
    for tx in txs:
        writer.writerow([tx.get('token', ''), tx.get('client_name', ''), tx.get('amount', ''),
                          tx.get('status', ''), tx.get('country', ''), tx.get('created_at', '')])
    log_user_activity(request.user_id, 'transactions_exported', {'count': len(txs)})
    return Response(output.getvalue(), mimetype='text/csv',
                     headers={'Content-Disposition': 'attachment; filename=transactions_flinpay.csv'})


def _resolve_transaction_status(tx):
    """Interroge le statut réel auprès de la passerelle et retourne le
    nouveau statut interne. N'applique PAS les effets de bord ici — voir
    l'appelant, qui doit d'abord gagner la transition atomique via
    sb_patch_if_pending avant d'appeler settle_transaction()."""
    if not tx.get('gateway_reference'):
        return tx['status']
    try:
        status_data = gateway.collection_status(tx['gateway_reference'])
    except gateway.GatewayError as e:
        logger.info(f"[payments] statut indisponible pour {tx['token']}: {e}")
        return tx['status']
    return gateway.map_remote_status(status_data.get('status'))


@payments_bp.route('/api/transactions/<token>/sync', methods=['POST'])
@user_required
@csrf_protect
def api_sync_transaction(token):
    tx = sb_get_one('transactions', 'token', token)
    if not tx or tx.get('user_id') != request.user_id:
        return jsonify({'ok': False, 'error': 'Introuvable'}), 404
    if not tx.get('gateway_reference'):
        return jsonify({'ok': False, 'error': "Pas de paiement associé à cette transaction"}), 400

    new_status = _resolve_transaction_status(tx)
    if new_status != tx['status']:
        update = {'status': new_status}
        if new_status == 'paid':
            update['paid_at'] = datetime.utcnow().isoformat()
        # Transition atomique : seule la requête qui fait réellement basculer
        # le statut depuis 'pending' applique les effets de bord — empêche le
        # double crédit si le webhook de la passerelle arrive en même temps.
        if sb_patch_if_pending('transactions', 'token', token, update):
            settle_transaction(tx, new_status)

    return jsonify({'ok': True, 'status': new_status})


# ── Liens de paiement (gestion, marchand connecté) ──
@payments_bp.route('/payment-links')
@user_required
def payment_links_page():
    return render_template('payment_links.html', user=get_current_user())


@payments_bp.route('/api/payment-links', methods=['GET'])
@user_required
def api_get_payment_links():
    links = sb_get_eq('payment_links', 'user_id', request.user_id, extra_query='order=created_at.desc')
    for l in links:
        if l.get('image_path'):
            l['image_url'] = sb_storage_public_url('payment-link-images', l['image_path'])
    return jsonify({'ok': True, 'links': links})


@payments_bp.route('/api/payment-links', methods=['POST'])
@user_required
@csrf_protect
def api_create_payment_link():
    data = request.form
    name = (data.get('name') or '').strip()[:120]
    if not name:
        return jsonify({'ok': False, 'error': 'Le nom est requis'}), 400

    amount_type = data.get('amount_type') if data.get('amount_type') in ('fixed', 'flexible') else 'fixed'
    amount, min_amount = None, None
    if amount_type == 'fixed':
        try:
            amount = float(data.get('amount'))
        except (TypeError, ValueError):
            return jsonify({'ok': False, 'error': 'Montant invalide'}), 400
        if amount < config.GATEWAY_MIN_AMOUNT:
            return jsonify({'ok': False, 'error': f'Montant minimum : {config.GATEWAY_MIN_AMOUNT}'}), 400
    else:
        raw_min = data.get('min_amount')
        if raw_min:
            try:
                min_amount = float(raw_min)
            except (TypeError, ValueError):
                return jsonify({'ok': False, 'error': 'Montant minimum invalide'}), 400
            if min_amount < config.GATEWAY_MIN_AMOUNT:
                return jsonify({'ok': False, 'error': f'Montant minimum : {config.GATEWAY_MIN_AMOUNT}'}), 400

    image_path = None
    file = request.files.get('image')
    if file and file.filename:
        ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
        if ext not in ('jpg', 'jpeg', 'png', 'webp'):
            return jsonify({'ok': False, 'error': 'Image: formats acceptés jpg, png, webp'}), 400
        file_bytes = file.read()
        if len(file_bytes) > 5 * 1024 * 1024:
            return jsonify({'ok': False, 'error': 'Image trop volumineuse (5 Mo max)'}), 400
        image_path = f"{request.user_id}/{uuid_lib.uuid4().hex[:12]}.{ext}"
        uploaded = sb_storage_upload('payment-link-images', image_path, file_bytes, file.mimetype or 'image/jpeg')
        if not uploaded['ok']:
            return jsonify({'ok': False, 'error': f"Erreur upload image: {uploaded['detail']}"}), 500

    token = 'pay_' + uuid_lib.uuid4().hex[:12]
    payload = {
        'token': token, 'user_id': request.user_id, 'name': name, 'amount': amount,
        'amount_type': amount_type, 'min_amount': min_amount,
        'description': (data.get('description') or '').strip()[:500],
        'usage_limit': int(data['usage_limit']) if data.get('usage_limit') else None,
        'expires_at': data.get('expires_at') or None,
        'redirect_url': (data.get('redirect_url') or '').strip()[:500] or None,
        'thank_you_message': (data.get('thank_you_message') or '').strip()[:500] or None,
        'image_path': image_path, 'active': True, 'views': 0, 'paid_count': 0,
        'created_at': datetime.utcnow().isoformat()
    }
    link = sb_post('payment_links', payload)
    if not link or (isinstance(link, dict) and link.get('_error')):
        return jsonify({'ok': False, 'error': 'Erreur lors de la création du lien'}), 500
    log_user_activity(request.user_id, 'payment_link_created', {'token': token, 'name': name})
    return jsonify({'ok': True, 'link': link[0] if isinstance(link, list) else link})


@payments_bp.route('/api/payment-links/<token>', methods=['PUT'])
@user_required
@csrf_protect
def api_update_payment_link(token):
    data = request.get_json() or {}
    allowed = {}

    if 'active' in data:
        allowed['active'] = bool(data['active'])
    if 'name' in data and isinstance(data['name'], str) and data['name'].strip():
        allowed['name'] = data['name'].strip()[:120]
    if 'description' in data:
        allowed['description'] = (data.get('description') or '').strip()[:500]
    if 'redirect_url' in data:
        allowed['redirect_url'] = (data.get('redirect_url') or '').strip()[:500] or None
    if 'thank_you_message' in data:
        allowed['thank_you_message'] = (data.get('thank_you_message') or '').strip()[:500] or None
    if 'expires_at' in data:
        allowed['expires_at'] = data.get('expires_at') or None
    if 'usage_limit' in data:
        raw_limit = data.get('usage_limit')
        allowed['usage_limit'] = int(raw_limit) if raw_limit else None
    if 'amount_type' in data and data['amount_type'] in ('fixed', 'flexible'):
        allowed['amount_type'] = data['amount_type']
        if data['amount_type'] == 'fixed':
            if 'amount' in data:
                try:
                    amt = float(data.get('amount'))
                except (TypeError, ValueError):
                    return jsonify({'ok': False, 'error': 'Montant invalide'}), 400
                if amt < config.GATEWAY_MIN_AMOUNT:
                    return jsonify({'ok': False, 'error': f'Montant minimum : {config.GATEWAY_MIN_AMOUNT}'}), 400
                allowed['amount'] = amt
            allowed['min_amount'] = None
        else:
            raw_min = data.get('min_amount')
            if raw_min:
                try:
                    min_amt = float(raw_min)
                except (TypeError, ValueError):
                    return jsonify({'ok': False, 'error': 'Montant minimum invalide'}), 400
                if min_amt < config.GATEWAY_MIN_AMOUNT:
                    return jsonify({'ok': False, 'error': f'Montant minimum : {config.GATEWAY_MIN_AMOUNT}'}), 400
                allowed['min_amount'] = min_amt
            else:
                allowed['min_amount'] = None
            allowed['amount'] = None

    if not allowed:
        return jsonify({'ok': False, 'error': 'Aucun champ à mettre à jour'}), 400

    ok = sb_patch_multi('payment_links', {'token': token, 'user_id': request.user_id}, allowed)
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la mise à jour'}), 500
    return jsonify({'ok': True})


@payments_bp.route('/api/payment-links/<token>', methods=['DELETE'])
@user_required
@csrf_protect
def api_delete_payment_link(token):
    ok = sb_delete_multi('payment_links', {'token': token, 'user_id': request.user_id})
    if not ok:
        return jsonify({'ok': False, 'error': 'Erreur lors de la suppression'}), 500
    return jsonify({'ok': True})


# ── Pages publiques : paiement via un lien ──────────
def _link_status(link):
    """Retourne (valide, raison) pour un lien de paiement."""
    if not link:
        return False, 'introuvable'
    if not link.get('active', True):
        return False, 'inactif'
    if link.get('expires_at'):
        try:
            if datetime.utcnow().date() > datetime.fromisoformat(link['expires_at']).date():
                return False, 'expire'
        except (ValueError, TypeError):
            pass
    if link.get('usage_limit') and (link.get('paid_count') or 0) >= link['usage_limit']:
        return False, 'limite'
    return True, ''


@payments_bp.route('/pay/<token>')
def pay_page(token):
    link = sb_get_one('payment_links', 'token', token)
    valid, reason = _link_status(link)
    if link and valid:
        sb_patch_multi('payment_links', {'token': token}, {'views': (link.get('views') or 0) + 1})
    image_url = sb_storage_public_url('payment-link-images', link['image_path']) if (link and link.get('image_path')) else None
    merchant_currency = get_currency_for_country(get_user_by_id(link['user_id']).get('country')) if link else 'XOF'
    return render_template('pay.html', link=link, valid=valid, reason=reason, token=token, i