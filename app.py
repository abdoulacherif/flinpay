"""
Point d'entrée de Flinpay.

Ce fichier ne contient plus aucune route ni logique métier : c'est uniquement
l'assemblage de l'application (config + extensions + blueprints). Les routes
seront enregistrées ici au fur et à mesure qu'on découpe le reste de app.py
d'origine en modules (routes/, services/, db/) — la structure est prête à les
recevoir.
"""
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from config import config
from extensions import init_extensions, logger


def create_app():
    app = Flask(__name__)

    # ── Configuration ───────────────────────────────
    app.config['SECRET_KEY'] = config.SECRET_KEY
    app.config['SESSION_COOKIE_SECURE'] = config.SESSION_COOKIE_SECURE
    app.config['SESSION_COOKIE_HTTPONLY'] = config.SESSION_COOKIE_HTTPONLY
    app.config['SESSION_COOKIE_SAMESITE'] = config.SESSION_COOKIE_SAMESITE
    # Empêche Flask de renvoyer une trace complète (et donc potentiellement des
    # détails internes) sur une erreur 500 en production.
    app.config['PROPAGATE_EXCEPTIONS'] = config.DEBUG

    # ── Proxy de confiance ──────────────────────────
    # Si l'app tourne derrière un reverse proxy (Render, Nginx, load balancer),
    # ProxyFix lui fait confiance UNIQUEMENT pour réécrire request.remote_addr
    # à partir de X-Forwarded-For — sans ça, get_client_ip() dans extensions.py
    # ferait confiance à un en-tête qu'un client malveillant peut falsifier
    # lui-même, ce qui casserait tout rate-limiting et verrouillage de compte
    # basé sur l'IP. x_for=1 signifie : "je ne fais confiance qu'au premier
    # proxy immédiatement devant moi" — à ajuster selon l'infra réelle.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    init_extensions(app)

    # ── Blueprints ──────────────────────────────────
    # À enregistrer au fur et à mesure du découpage des routes d'origine.
    # Exemple une fois les modules créés :
    #
    #   from routes.public import public_bp
    #   from routes.auth import auth_bp
    #   from routes.dashboard import dashboard_bp
    #   from routes.payments import payments_bp
    #   from routes.invoices import invoices_bp
    #   from routes.payouts import payouts_bp
    #   from routes.keys_webhooks import keys_webhooks_bp
    #   from routes.kyc import kyc_bp
    #   from routes.webhook_callback import webhook_callback_bp
    #   from routes.admin import admin_bp
    #
    #   for bp in (public_bp, auth_bp, dashboard_bp, payments_bp, invoices_bp,
    #              payouts_bp, keys_webhooks_bp, kyc_bp, webhook_callback_bp, admin_bp):
    #       app.register_blueprint(bp)

    @app.errorhandler(404)
    def not_found(e):
        from flask import render_template
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def server_error(e):
        from flask import jsonify
        orig = getattr(e, 'original_exception', e)
        # On journalise l'erreur complète côté serveur (avec la stack trace),
        # mais on ne renvoie JAMAIS le détail de l'exception au client : ça
        # peut révéler des chemins internes, des noms de tables, des bouts de
        # requête SQL... autant d'informations utiles à un attaquant.
        logger.exception(f"Erreur 500 sur {getattr(e, 'original_exception', e)}")
        if config.DEBUG:
            return jsonify({'error': str(orig), 'type': type(orig).__name__}), 500
        return jsonify({'error': 'Une erreur interne est survenue. Réessayez plus tard.'}), 500

    return app


app = create_app()


if __name__ == '__main__':
    if config.IS_PRODUCTION:
        # En production, ne jamais utiliser le serveur de développement Flask
        # (app.run) : il n'est pas conçu pour tenir une charge réelle et son
        # debugger, s'il reste actif, permet l'exécution de code arbitraire.
        # Utiliser un vrai serveur WSGI, par exemple :
        #   gunicorn -w 4 -b 0.0.0.0:5000 app:app
        logger.warning(
            "app.run() est utilisé en environnement de production. "
            "Préférez `gunicorn -w 4 -b 0.0.0.0:5000 app:app` pour un vrai déploiement."
        )
    app.run(debug=config.DEBUG, host='0.0.0.0', port=5000)
