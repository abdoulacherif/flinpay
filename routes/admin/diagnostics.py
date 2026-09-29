"""
routes/admin/diagnostics.py — test de bout en bout de la connexion à la
passerelle de paiement, réservé aux admins. Permet de savoir EN UN CLIC si
l'authentification OAuth2 fonctionne, si le catalogue répond, et si les
devis de frais sont accessibles — sans avoir à lire les logs Vercel.

Ne renvoie JAMAIS de secret (ni client_secret, ni token) : uniquement des
comptes, des codes de service et des messages d'erreur.
"""
import logging

from flask import Blueprint, jsonify

from services.auth import admin_required
from services.audit import log_admin_action
from services import gateway

logger = logging.getLogger('flinpay.routes.admin.diagnostics')

admin_diagnostics_bp = Blueprint('admin_diagnostics', __name__)


def _run(name, fn):
    try:
        detail = fn()
        return {'step': name, 'ok': True, 'detail': detail}
    except gateway.GatewayError as e:
        return {
            'step': name, 'ok': False, 'error': str(e),
            'status_code': e.status_code,
            'gateway_response': e.detail if isinstance(e.detail, dict) else None,
        }
    except Exception as e:
        logger.exception(f"[diagnostics] étape {name} en échec inattendu")
        return {'step': name, 'ok': False, 'error': f"{type(e).__name__}: {e}"}


@admin_diagnostics_bp.route('/api/admin/gateway-check', methods=['GET'])
@admin_required
def api_gateway_check():
    # Repart d'un état propre : on veut tester les vrais appels, pas le cache.
    gateway._catalogue_cache.clear()
    gateway._invalidate_token()

    steps = []

    def step_token():
        gateway._get_access_token()
        return {'token_endpoint': gateway._token_cache.get('token_endpoint')}
    steps.append(_run("1. Authentification OAuth2", step_token))
    if not steps[-1]['ok']:
        log_admin_action('gateway_check', {'ok': False, 'failed_at': steps[-1]['step']})
        return jsonify({'ok': False, 'steps': steps})

    def step_countries():
        countries = gateway.list_countries()
        return {'count': len(countries), 'codes': [c.get('code') for c in countries]}
    steps.append(_run("2. Liste des pays", step_countries))

    services_holder = {}

    def step_services():
        services = gateway.list_services('CM')
        services_holder['services'] = services
        return {
            'count': len(services),
            'services': [
                {'code': s.get('code'), 'currency': s.get('currency'),
                 'collect': bool(s.get('is_can_collect')), 'disburse': bool(s.get('is_can_disburse')),
                 'otp': bool(s.get('is_need_otp'))}
                for s in services
            ],
        }
    steps.append(_run("3. Services actifs (Cameroun)", step_services))

    def step_fee_quote():
        services = services_holder.get('services') or []
        target = next((s for s in services if s.get('is_can_collect')), None)
        if not target:
            raise gateway.GatewayError("Aucun service de collecte disponible pour tester le devis de frais")
        quote = gateway.get_fee_quote(target['id'], 1000, target.get('currency') or 'XAF')
        return {'service': target.get('code'), 'fee_amount': quote.get('feeAmount'), 'payable_amount': quote.get('payableAmount')}
    steps.append(_run("4. Devis de frais", step_fee_quote))

    all_ok = all(s['ok'] for s in steps)
    log_admin_action('gateway_check', {'ok': all_ok})
    return jsonify({'ok': all_ok, 'steps': steps})
