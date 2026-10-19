import logging
import re
import secrets
import uuid
import os
from datetime import datetime

from flask import Flask, g, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_wtf.csrf import CSRFProtect
from pythonjsonlogger import jsonlogger

from config import config

_PII_PATTERNS = [
    (re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+'), '[EMAIL_REDACTED]'),
    (re.compile(r'(\+?\d[\d\s\-().]{7,}\d)'), '[PHONE_REDACTED]'),
    (re.compile(r'(?i)(bearer\s+)[\w\-._~+/]+=*'), r'\1[REDACTED]'),
    (re.compile(
        r'(?i)("?(?:password|secret|token|api[_-]?key|authorization)"?\s*[:=]\s*"?)[^"\s,}]+'
    ), r'\1[REDACTED]'),
]


class _PIIRedactor(logging.Filter):
    def filter(self, record):
        try:
            msg = record.getMessage()
            for pattern, repl in _PII_PATTERNS:
                msg = pattern.sub(repl, msg)
            record.msg = msg
            record.args = ()
        except Exception:
            pass
        return True


def _setup_logging():
    handler = logging.StreamHandler()
    handler.setFormatter(jsonlogger.JsonFormatter(
        '%(asctime)s %(levelname)s %(name)s %(message)s',
        rename_fields={'asctime': 'ts', 'levelname': 'level', 'name': 'logger'},
    ))
    handler.addFilter(_PIIRedactor())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.DEBUG if config.DEBUG else logging.INFO)


_setup_logging()
logger = logging.getLogger('flinpay')


def get_client_ip() -> str:
    return request.remote_addr or 'unknown'


def init_cors(app):
    CORS(
        app,
        origins=config.ALLOWED_ORIGINS,
        methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allow_headers=['Content-Type', 'X-CSRF-Token', 'X-Request-ID'],
        expose_headers=['X-Request-ID', 'Retry-After'],
        supports_credentials=True,
        max_age=600,
    )


# Instance CSRF globale (réutilisable dans app.py)
csrf = CSRFProtect()


def init_csrf(app):
    app.config['WTF_CSRF_SECRET_KEY'] = os.getenv('WTF_CSRF_SECRET_KEY', config.SECRET_KEY)
    app.config['WTF_CSRF_TIME_LIMIT'] = 3600
    app.config['WTF_CSRF_SSL_STRICT'] = config.IS_PRODUCTION
    app.config['WTF_CSRF_HEADERS'] = ['X-CSRF-Token', 'X-CSRFToken']
    # Vérification manuelle dans app.py pour pouvoir exempter les routes publiques
    app.config['WTF_CSRF_CHECK_DEFAULT'] = False
    csrf.init_app(app)


def _rate_limit_key():
    try:
        from services.auth import get_current_user_optional
        user = get_current_user_optional()
        if user and user.get('id'):
            return f"user:{user['id']}"
    except Exception:
        pass
    return f"ip:{get_client_ip()}"


limiter = Limiter(
    key_func=_rate_limit_key,
    default_limits=['200 per minute', '3000 per hour'],
    storage_uri=config.LIMITER_STORAGE_URI,
    headers_enabled=True,
    strategy='fixed-window',
    swallow_errors=True,
)


def init_limiter(app):
    limiter.init_app(app)


CSP_BASE = (
    "default-src 'self'; "
    "script-src 'self' 'nonce-{nonce}' 'strict-dynamic' https://cdnjs.cloudflare.com; "
    "style-src 'self' 'nonce-{nonce}' https://fonts.googleapis.com; "
    "img-src 'self' data: blob: https://*.supabase.co; "
    "font-src 'self' data: https://fonts.gstatic.com; "
    "connect-src 'self' https://www.flinpay.cfd https://flinpay.cfd https://*.supabase.co; "
    "frame-src 'self'; "
    "frame-ancestors 'self'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "object-src 'none'; "
    "upgrade-insecure-requests;"
)

CSP_EMBEDDABLE = CSP_BASE.replace(
    "frame-ancestors 'self';",
    "frame-ancestors 'self' https://www.flinpay.cfd https://flinpay.cfd;"
)


def _is_embeddable_path(path: str) -> bool:
    return path.startswith('/pay/') or path.startswith('/invoice/')


def _is_static_path(path: str) -> bool:
    return path.startswith('/static/') or path in ('/favicon.ico', '/widget.js', '/robots.txt')


def init_security_headers(app):
    @app.after_request
    def _apply(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['X-XSS-Protection'] = '0'
        response.headers['Permissions-Policy'] = (
            'accelerometer=(), camera=(), geolocation=(), gyroscope=(), '
            'magnetometer=(), microphone=(), payment=(), usb=(), serial=(), '
            'bluetooth=(), clipboard-read=(), clipboard-write=(self), '
            'interest-cohort=(), browsing-topics=(), document-domain=(), '
            'fullscreen=(self)'
        )
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
        response.headers.pop('Server', None)
        response.headers.pop('X-Powered-By', None)

        if config.IS_PRODUCTION:
            response.headers['Strict-Transport-Security'] = (
                'max-age=63072000; includeSubDomains; preload'
            )

        nonce = getattr(g, 'csp_nonce', '') or ''
        policy = CSP_EMBEDDABLE if _is_embeddable_path(request.path) else CSP_BASE
        response.headers['Content-Security-Policy'] = policy.format(nonce=nonce)

        if _is_embeddable_path(request.path):
            response.headers.pop('X-Frame-Options', None)
        else:
            response.headers['X-Frame-Options'] = 'DENY'

        if _is_static_path(request.path):
            response.headers.setdefault('Cache-Control', 'public, max-age=3600')
        else:
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
            response.headers['Pragma'] = 'no-cache'

        return response


def init_request_context(app):
    @app.before_request
    def _assign():
        incoming = request.headers.get('X-Request-ID', '')
        if incoming and re.fullmatch(r'[a-f0-9\-]{8,64}', incoming):
            g.request_id = incoming
        else:
            g.request_id = uuid.uuid4().hex
        g.csp_nonce = secrets.token_urlsafe(16)

    @app.after_request
    def _expose(response):
        response.headers['X-Request-ID'] = getattr(g, 'request_id', '')
        return response


def init_template_helpers(app):
    @app.context_processor
    def _globals():
        return {
            'current_year': datetime.utcnow().year,
            'csp_nonce': getattr(g, 'csp_nonce', ''),
        }

    @app.template_filter('split')
    def _split(value, sep=','):
        return (value or '').split(sep)


def init_extensions(app: Flask):
    init_cors(app)
    init_csrf(app)
    init_limiter(app)
    init_request_context(app)
    init_security_headers(app)
    init_template_helpers(app)