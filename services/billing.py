import logging
from datetime import datetime

from db.supabase import sb_get_eq, sb_get_one, sb_post, sb_patch

logger = logging.getLogger('flinpay.billing')

# ── Récompenses FP ──────────────────────────────────
# Règle : 500 000 XOF collectés = 2 000 FP.
# 1 XOF collecté = 0,004 FP ; 1 FP = 250 XOF.
FP_PER_XOF_COLLECTED = 0.004
FP_TO_XOF_RATE = 250.0


def compute_fp_reward(amount_collected_xof: float) -> float:
    """Retourne le nombre de FP à créditer pour un montant XOF collecté."""
    try:
        amount = float(amount_collected_xof or 0)
    except (TypeError, ValueError):
        return 0.0
    if amount <= 0:
        return 0.0
    return round(amount * FP_PER_XOF_COLLECTED, 2)


def credit_fp_for_transaction(user_id: str, amount_xof: float, transaction_token: str):
    """Crédite les FP au marchand pour une collecte payée. Idempotent :
    ne crédite pas deux fois le même token."""
    fp = compute_fp_reward(amount_xof)
    if fp <= 0:
        return 0.0

    try:
        existing = sb_get_eq('fp_history', 'transaction_token', transaction_token)
        if existing:
            return 0.0

        sb_post('fp_history', {
            'user_id': user_id,
            'amount_fp': fp,
            'source_amount': float(amount_xof),
            'source_currency': 'XOF',
            'transaction_token': transaction_token,
            'created_at': datetime.utcnow().isoformat(),
        })

        user = sb_get_one('users', 'id', user_id)
        if user:
            new_balance = float(user.get('fp_balance') or 0) + fp
            sb_patch('users', 'id', user_id, {'fp_balance': round(new_balance, 2)})

        return fp
    except Exception as e:
        logger.warning(f"[credit_fp_for_transaction] failed: {e}")
        return 0.0