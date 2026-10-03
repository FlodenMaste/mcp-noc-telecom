"""
Mecanisme de validation humaine obligatoire pour toute action a impact.

Conforme a l'exigence du cahier des charges (A.6) : "chaque execution
d'outil requiert le consentement explicite de l'utilisateur, les
annotations de type destructiveHint n'etant pas considerees comme des
barrieres suffisantes" et (B.4 autres projets) "l'option d'autorisation
permanente (always allow) est bannie".

A ce stade du projet, tous les outils developpes sont en LECTURE SEULE
(snmp_get, get_syslog_message) : ce mecanisme n'est donc pas encore
appele en production, mais il est pret pour les futurs outils de
pilotage (ex: isolate_endpoint, block_ip) qui en auront besoin.
"""

from server.security.audit_log import log_action


class ConsentRefusedError(Exception):
    pass


def require_human_consent(action_description: str, user: str, tool: str, dry_run: bool = False) -> bool:
    """
    Demande une confirmation explicite avant d'executer une action a
    impact. Ne propose JAMAIS d'option "toujours autoriser" (always
    allow), conformement a l'exigence du cahier des charges.

    En mode dry_run=True, simule la demande sans bloquer (utile pour
    les tests automatises) et journalise la simulation.
    """
    if dry_run:
        log_action(
            user=user, tool=tool, params={"action": action_description},
            status="DRY_RUN", detail="Simulation sans execution reelle",
        )
        return True

    print(f"\n[VALIDATION HUMAINE REQUISE]")
    print(f"Outil : {tool}")
    print(f"Action proposee : {action_description}")
    response = input("Confirmer cette action ? (oui/non) : ").strip().lower()
    approved = response in ("oui", "o", "yes", "y")

    log_action(
        user=user, tool=tool, params={"action": action_description},
        status="VALIDEE_HUMAIN" if approved else "REFUSEE_HUMAIN",
        detail=f"Reponse operateur : '{response}'",
    )

    if not approved:
        raise ConsentRefusedError(f"Action refusee par l'utilisateur : {action_description}")

    return True
