"""
routes/admin/__init__.py — point d'entrée unique du package admin. Regroupe
tous les blueprints admin (core, users, payments, payouts, kyc, config, audit)
pour qu'app.py n'ait qu'une seule ligne à ajouter par blueprint.

Tous ces blueprints partagent la même protection : @admin_required (JWT valide
+ flag is_admin revérifié en base à chaque requête — voir services/auth.py) et
@csrf_protect sur toute route qui modifie une donnée.
"""
from routes.admin.core import admin_core_bp
from routes.admin.users import admin_users_bp
from routes.admin.payments import admin_payments_bp
from routes.admin.payouts import admin_payouts_bp
from routes.admin.kyc import admin_kyc_bp
from routes.admin.config import admin_config_bp
from routes.admin.audit import admin_audit_bp
from routes.admin.restrictions import admin_restrictions_bp

admin_blueprints = [
    admin_core_bp,
    admin_users_bp,
    admin_payments_bp,
    admin_payouts_bp,
    admin_kyc_bp,
    admin_config_bp,
    admin_audit_bp,
    admin_restrictions_bp,
]
