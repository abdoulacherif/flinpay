from flask import Flask, jsonify, redirect, render_template, request
from flask_wtf.csrf import CSRFError
from werkzeug.middleware.proxy_fix import ProxyFix

from config import config
from extensions import init_extensions, logger, csrf


_CSRF_EXEMPT_ENDPOINTS = frozenset({
    'webhook_callback.webhook_payment_events',
    'payments.api_pay',
    'payments.api_pay_link',
    'payments.api_pay_status',
    'payments.pay_page',
    'payments.pay_thank_you',
    'invoices.api_invoice_pay',
    'invoices.invoice_view',
    'public.index',
    'public.register',
    'public.login_page',
    'public.docs',
    'public.favicon',
    'public.flinpay_widget_js',
    'auth.api_login',
    'auth.api_login_2fa',
    'auth.api_login_email_link',
    'auth.api_login_verify_link',
    'auth.api_logout',
    'auth.verify_email',
    'auth.api_resend_verification',
    'auth.api_register',
})


def _host_is_allowed(host: str) -> bool:
    """Retourne True si le host est autorisé, en acceptant les suffixes Vercel."""
    if not host:
        return False
    if host in config.ALLOWED_HOSTS:
        return True
    for suffix in getattr(config, 'ALLOWED_HOST_SUFFIXES', ()):
        if host.endswith(suffix):
            return True
    return False


def create_app():
    app = Flask(__name__)

    app.config.update(
        SECRET_KEY=config.SECRET_KEY,
        SESSION_COOKIE_SECURE=config.SESSION_COOKIE_SECURE,
        SESSION_COOKIE_HTTPONLY=config.SESSION_COOKIE_HTTPONLY,
        SESSION_COOKIE_SAMESITE=config.SESSION_COOKIE_SAMESITE,
        SESSION_COOKIE_NAME=config.SESSION_COOKIE_NAME,
        PERMANENT_SESSION_LIFETIME=config.PERMANENT_SESSION_LIFETIME_SECONDS,
        SESSION_REFRESH_EACH_REQUEST=False,
        MAX_CONTENT_LENGTH=config.MAX_CONTENT_LENGTH,
        PROPAGATE_EXCEPTIONS=config.DEBUG and not config.IS_PRODUCTION,
        PREFERRED_URL_SCHEME='https',
    )

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    @app.before_request
    def _enforce_host():
        host = (request.host or '').split(':')[0].lower()
        if not _host_is_allowed(host):
            logger.warning("Host rejected", extra={'host': host, 'path': request.path})
            return 'Bad Request', 400

    @app.before_request
    def _canonical_redirect():
        host = (request.host or '').split(':')[0].lower()
        if host == 'flinpay.cfd' and not request.path.startswith('/webhook/'):
            qs = f'?{request.query_string.decode()}' if request.query_string else ''
            return redirect(f'https://www.flinpay.cfd{request.path}{qs}', code=301)

    init_extensions(app)

    from routes.public import public_bp
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.payments import payments_bp
    from routes.invoices import invoices_bp
    from routes.payouts import payouts_bp
    from routes.keys_webhooks import keys_webhooks_bp
    from routes.kyc import kyc_bp
    from routes.webhook_callback import webhook_callback_bp
    from routes.rewards import rewards_bp
    from routes.admin import admin_blueprints

    for bp in (public_bp, auth_bp, dashboard_bp, payments_bp, invoices_bp,
               payouts_bp, keys_webhooks_bp, kyc_bp, webhook_callback_bp,
               rewards_bp, *admin_blueprints):
        app.register_blueprint(bp)

    @app.before_request
    def _csrf_guard():
        if request.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
            return
        if request.endpoint in _CSRF_EXEMPT_ENDPOINTS:
            return
        try:
            csrf.protect()
        except CSRFError:
            return jsonify({'ok': False, 'error': 'Jeton de sécurité invalide ou expiré'}), 400

    @app.errorhandler(404)
    def _404(e):
        return render_template('404.html'), 404

    @app.errorhandler(413)
    def _413(e):
        return jsonify({'ok': False, 'error': 'Fichier trop volumineux'}), 413

    @app.errorhandler(429)
    def _429(e):
        return jsonify({'ok': False, 'error': 'Trop de requêtes, réessayez plus tard'}), 429

    @app.errorhandler(500)
    def _500(e):
        orig = getattr(e, 'original_exception', e)
        logger.error(f"Erreur 500: {orig!r}", exc_info=orig)
        if config.DEBUG and not config.IS_PRODUCTION:
            return jsonify({'error': str(orig), 'type': type(orig).__name__}), 500
        return jsonify({'ok': False, 'error': 'Une erreur interne est survenue.'}), 500

    return app


app = create_app()


if __name__ == '__main__':
    if config.IS_PRODUCTION:
        raise RuntimeError("Do not use app.run() in production — use gunicorn.")
    app.run(debug=True, host='127.0.0.1', port=5000)