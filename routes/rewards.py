import logging
from flask import Blueprint, jsonify, render_template, request
from services.auth import user_required, get_current_user
from db.supabase import sb_get_eq

logger = logging.getLogger('flinpay.routes.rewards')
rewards_bp = Blueprint('rewards', __name__)


@rewards_bp.route('/rewards')
@user_required
def rewards_page():
    return render_template('rewards.html', user=get_current_user())


@rewards_bp.route('/api/rewards')
@user_required
def api_rewards():
    user = get_current_user()
    if not user:
        return jsonify({'ok': False, 'error': 'Non autorisé'}), 401

    fp_balance = float(user.get('fp_balance') or 0)
    xof_equiv = round(fp_balance * 250.0, 2)

    history = sb_get_eq(
        'fp_history', 'user_id', request.user_id,
        extra_query='order=created_at.desc&limit=50'
    )

    return jsonify({
        'ok': True,
        'fp_balance': fp_balance,
        'xof_equivalent': xof_equiv,
        'history': history,
    })