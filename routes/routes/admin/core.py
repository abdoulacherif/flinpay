"""
routes/admin/core.py — pages d'entrée de l'espace admin.

Il n'existe PAS de flux de connexion admin distinct : un admin se connecte
avec le même formulaire /login que n'importe quel marchand (voir
routes/auth.py), et c'est le flag `is_admin` en base — revérifié à CHAQUE
requête par @admin_required (services/auth.py) — qui débloque l'accès à ces
routes. /admin/login n'existe plus que comme redirection de compatibilité
pour d'anciens liens.

RECOMMANDATION DE DURCISSEMENT SUPPLÉMENTAIRE (hors périmètre du code)
------------------------------------------------------------------------
Vu qu'un compte admin peut approuver des KYC, gérer tous les soldes et créer
des retraits pour n'importe quel marchand, il mérite une protection au-delà
de ce que ce fichier peut faire à lui seul :
  - Forcer le 2FA (déjà implémenté pour tous les comptes, voir routes/auth.py)
    à être OBLIGATOIRE pour tout compte où is_admin=true, plutôt qu'optionnel.
  - Envisager de restreindre l'accès à /admin/* par IP (VPN d'entreprise) au
    niveau du reverse proxy, en plus de l'authentification applicative.
"""
from flask import Blueprint, render_template, redirect, url_for, make_response

from services.auth import admin_required, get_current_user

admin_core_bp = Blueprint('admin_core', __name__)


@admin_core_bp.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    return redirect(url_for('public.login_page'))


@admin_core_bp.route('/admin/logout')
def admin_logout():
    resp = make_response(redirect(url_for('public.login_page')))
    resp.delete_cookie('fp_user_token')
    resp.delete_cookie('fp_csrf_token')
    return resp


@admin_core_bp.route('/admin')
@admin_required
def admin():
    return render_template('admin.html', user=get_current_user())
