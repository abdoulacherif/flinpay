"""
services/fx.py — conversion entre devises.

La nouvelle API du prestataire de paiement n'expose aucun endpoint de
conversion de change (vérifié dans la documentation fournie). On ne peut donc
plus convertir dynamiquement entre devises comme avant.

Ce qu'on peut faire honnêtement : XAF et XOF sont deux instances du franc CFA
à parité FIXE et garantie 1:1 (BEAC / BCEAO). Pour cette seule paire, une
conversion 1:1 est exacte, pas une estimation. Pour toute autre paire
(notamment tout ce qui implique le CDF, franc congolais, dont le taux flotte
réellement), on refuse explicitement la conversion plutôt que d'inventer un
taux — un taux faux ferait perdre de l'argent soit au marchand, soit à
Flinpay, silencieusement.
"""

# Parités fixes garanties, PAS des taux de marché.
_FIXED_PARITIES = {
    ('XAF', 'XOF'): 1.0,
    ('XOF', 'XAF'): 1.0,
}


def can_convert(from_currency: str, to_currency: str) -> bool:
    if from_currency == to_currency:
        return True
    return (from_currency, to_currency) in _FIXED_PARITIES


def convert(amount: float, from_currency: str, to_currency: str):
    """Retourne le montant converti, ou None si la paire n'est pas prise en
    charge (à traiter explicitement par l'appelant — ne jamais deviner)."""
    if from_currency == to_currency:
        return round(float(amount), 2)
    rate = _FIXED_PARITIES.get((from_currency, to_currency))
    if rate is None:
        return None
    return round(float(amount) * rate, 2)
