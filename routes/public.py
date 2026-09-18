"""
routes/public.py — routes accessibles sans authentification : page d'accueil,
pages login/register (le HTML, pas l'API), documentation, script du widget
"Payer avec Flinpay" embarquable sur un site tiers.
"""
from flask import Blueprint, render_template, Response

from config import config
from db.supabase import sb_get

public_bp = Blueprint('public', __name__)


def get_site_config():
    data = sb_get('site_config')
    return {item['key']: item['value'] for item in data}


@public_bp.route('/')
def index():
    cfg = get_site_config()
    stats = sb_get('stats', 'order=order_index.asc')
    features = sb_get('features', 'is_visible=eq.true&order=order_index.asc')
    plans = sb_get('pricing_plans', 'is_visible=eq.true&order=order_index.asc')
    testimonials = sb_get('testimonials', 'is_visible=eq.true&order=order_index.asc')
    return render_template(
        'index.html', cfg=cfg, stats=stats, features=features, plans=plans,
        testimonials=testimonials, countries=config.COUNTRIES
    )


@public_bp.route('/register')
def register():
    return render_template('register.html')


@public_bp.route('/login')
def login_page():
    return render_template('login.html')


@public_bp.route('/docs')
def docs():
    return render_template('docs.html')


@public_bp.route('/favicon.ico')
def favicon():
    return '', 204


# ── Widget "Payer avec Flinpay" ─────────────────────
# Contenu statique servi tel quel — aucune donnée utilisateur n'entre dans ce
# fichier, donc pas de surface d'attaque particulière ici. La sécurité réelle
# du paiement se joue côté serveur, dans routes/payments.py, quand l'iframe
# soumet le formulaire de paiement — jamais dans ce script côté client.
FLINPAY_WIDGET_JS = r"""
(function(){
  var ORIGIN = "https://www.flinpay.cfd";

  function injectStyles(){
    if(document.getElementById('flinpay-widget-styles')) return;
    var css = `
      .flinpay-btn{
        display:inline-flex;align-items:center;gap:8px;
        background:#1A3CFF;color:#fff;border:none;border-radius:10px;
        padding:12px 20px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Inter,sans-serif;
        font-weight:700;font-size:0.95rem;cursor:pointer;transition:all .15s;
        box-shadow:0 4px 14px rgba(26,60,255,0.25);
      }
      .flinpay-btn:hover{background:#1430e0;transform:translateY(-1px)}
      .flinpay-btn:active{transform:translateY(0)}
      .flinpay-btn svg{width:18px;height:18px;flex-shrink:0}
      .flinpay-overlay{
        position:fixed;inset:0;background:rgba(8,9,16,0.6);z-index:999998;
        display:flex;align-items:center;justify-content:center;padding:20px;
        opacity:0;transition:opacity .2s;backdrop-filter:blur(3px)
      }
      .flinpay-overlay.show{opacity:1}
      .flinpay-modal{
        position:relative;width:100%;max-width:460px;height:min(680px,90vh);
        border-radius:20px;overflow:hidden;box-shadow:0 30px 80px rgba(0,0,0,0.4);
        transform:translateY(16px) scale(.98);transition:transform .25s cubic-bezier(.16,1,.3,1)
      }
      .flinpay-overlay.show .flinpay-modal{transform:translateY(0) scale(1)}
      .flinpay-modal iframe{width:100%;height:100%;border:none;background:#141420}
      .flinpay-close{
        position:absolute;top:10px;right:10px;z-index:2;
        width:34px;height:34px;border-radius:50%;border:none;
        background:rgba(0,0,0,0.35);color:#fff;font-size:18px;cursor:pointer;
        display:flex;align-items:center;justify-content:center;line-height:1
      }
      .flinpay-close:hover{background:rgba(0,0,0,0.55)}
      .flinpay-loading{
        position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
        background:#141420;color:rgba(255,255,255,.5);font-family:sans-serif;font-size:.85rem
      }
    `;
    var style=document.createElement('style');
    style.id='flinpay-widget-styles';
    style.textContent=css;
    document.head.appendChild(style);
  }

  function openCheckout(linkToken){
    var overlay=document.createElement('div');
    overlay.className='flinpay-overlay';
    overlay.innerHTML=
      '<div class="flinpay-modal">'+
        '<div class="flinpay-loading">Chargement du paiement…</div>'+
        '<button class="flinpay-close" aria-label="Fermer">✕</button>'+
        '<iframe src="'+ORIGIN+'/pay/'+encodeURIComponent(linkToken)+'?embed=1" allow="clipboard-write"></iframe>'+
      '</div>';
    document.body.appendChild(overlay);
    document.body.style.overflow='hidden';
    requestAnimationFrame(function(){ overlay.classList.add('show'); });

    var iframe=overlay.querySelector('iframe');
    var loading=overlay.querySelector('.flinpay-loading');
    iframe.addEventListener('load', function(){ loading.style.display='none'; });

    function close(){
      overlay.classList.remove('show');
      document.body.style.overflow='';
      setTimeout(function(){ overlay.remove(); }, 200);
      document.removeEventListener('keydown', onKey);
    }
    function onKey(e){ if(e.key==='Escape') close(); }
    document.addEventListener('keydown', onKey);
    overlay.querySelector('.flinpay-close').addEventListener('click', close);
    overlay.addEventListener('click', function(e){ if(e.target===overlay) close(); });

    window.addEventListener('message', function(e){
      if(e.origin!==ORIGIN) return;
      if(e.data && e.data.flinpay==='payment_success'){
        setTimeout(close, 1500);
      }
    });
  }

  function renderButtons(){
    var nodes=document.querySelectorAll('[data-flinpay-link]:not([data-flinpay-ready])');
    nodes.forEach(function(el){
      el.setAttribute('data-flinpay-ready','1');
      var linkToken=el.getAttribute('data-flinpay-link');
      var label=el.getAttribute('data-flinpay-label') || 'Payer avec Flinpay';
      el.classList.add('flinpay-btn');
      el.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="5" width="20" height="14" rx="2"/><line x1="2" y1="10" x2="22" y2="10"/></svg><span>'+label+'</span>';
      el.addEventListener('click', function(ev){
        ev.preventDefault();
        openCheckout(linkToken);
      });
    });
  }

  injectStyles();
  if(document.readyState==='loading'){
    document.addEventListener('DOMContentLoaded', renderButtons);
  }else{
    renderButtons();
  }
  window.FlinpayWidget = { render: renderButtons };
})();
"""


@public_bp.route('/widget.js')
def flinpay_widget_js():
    resp = Response(FLINPAY_WIDGET_JS, mimetype='application/javascript')
    resp.headers['Cache-Control'] = 'public, max-age=3600'
    return resp
