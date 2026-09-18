"""
services/invoices.py — logique de facturation partagée entre routes/invoices.py
(gestion des factures) et routes/payments.py (rapprochement paiement -> facture
quand un paiement lié à une facture passe à 'paid'). Séparé dans un module de
service pour éviter un import circulaire entre ces deux blueprints.
"""
from datetime import datetime

from db.supabase import sb_get_eq, sb_patch_multi


def generate_invoice_number(user_id):
    """Numérotation simple et séquentielle par marchand : INV-0001, INV-0002, ..."""
    existing = sb_get_eq('invoices', 'user_id', user_id, extra_query='order=id.desc&limit=1')
    next_num = 1
    if existing:
        last_num = existing[0].get('invoice_number', '')
        try:
            next_num = int(last_num.split('-')[-1]) + 1
        except (ValueError, IndexError):
            next_num = len(sb_get_eq('invoices', 'user_id', user_id)) + 1
    return f'INV-{next_num:04d}'


def mark_invoice_paid_if_applicable(tx):
    """Si la transaction est liée à une facture et vient de passer à 'paid',
    marque la facture correspondante comme payée."""
    invoice_token = tx.get('invoice_token')
    if not invoice_token:
        return
    invoice = sb_get_eq('invoices', 'token', invoice_token)
    if invoice and invoice[0].get('status') != 'paid':
        sb_patch_multi('invoices', {'token': invoice_token}, {
            'status': 'paid',
            'paid_at': datetime.utcnow().isoformat()
        })


def compute_invoice_amount(items):
    total = 0.0
    for it in items:
        try:
            total += float(it.get('quantity', 1)) * float(it.get('unit_price', 0))
        except (TypeError, ValueError):
            continue
    return round(total, 2)


def clean_invoice_items(items):
    """Valide et nettoie une liste d'articles de facture. Retourne (items_valides,
    message_erreur_ou_None). Centralisé ici pour que la création ET la
    modification d'une facture appliquent exactement les mêmes règles."""
    if not isinstance(items, list) or not items:
        return None, 'Ajoutez au moins un article'
    cleaned = []
    for it in items:
        desc = (it.get('description') or '').strip()[:300]
        try:
            qty = float(it.get('quantity', 1))
            price = float(it.get('unit_price', 0))
        except (TypeError, ValueError):
            return None, 'Quantité ou prix invalide'
        if not desc or qty <= 0 or price < 0:
            return None, 'Article invalide (description, quantité ou prix)'
        cleaned.append({'description': desc, 'quantity': qty, 'unit_price': price})
    return cleaned, None
