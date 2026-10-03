"""
Script de demonstration complet de la couche securite du serveur MCP.
A executer devant le jury pour illustrer :
  1. Le RBAC (acces refuse si role insuffisant)
  2. La neutralisation d'une tentative d'injection de prompt
  3. Le journal d'audit qui trace tout

Usage : python3 demo_securite.py
"""

import jwt as pyjwt
from datetime import datetime, timedelta, timezone

from server.config import JWT_SECRET, JWT_ALGORITHM
from server.security.auth import AccessDeniedError
from server.tools.supervision import snmp_get
from server.tools.demo_attack import get_syslog_message


def make_token(role):
    payload = {
        "user": f"demo-{role}", "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def separateur(titre):
    print("\n" + "=" * 70)
    print(f"  {titre}")
    print("=" * 70)


if __name__ == "__main__":
    separateur("DEMO 1 : RBAC - acces refuse (role insuffisant)")
    print("Un jeton avec un role invalide tente d'appeler un outil protege...")
    try:
        fake_token = pyjwt.encode(
            {"user": "intrus", "role": "role_inexistant",
             "exp": datetime.now(timezone.utc) + timedelta(minutes=10)},
            JWT_SECRET, algorithm=JWT_ALGORITHM,
        )
        snmp_get(fake_token, router="r1")
    except AccessDeniedError as e:
        print(f"-> ACCES REFUSE (comme attendu) : {e}")

    separateur("DEMO 2 : RBAC - acces autorise (role operateur)")
    token = make_token("operateur")
    result = snmp_get(token, router="r1")
    print(f"-> Acces autorise. Succes : {result['success']}")

    separateur("DEMO 3 : Syslog normal, aucune alerte")
    result = get_syslog_message(token, scenario="normal")
    print(f"Message : {result['message_neutralise']}")
    print(f"-> Injection detectee : {result['injection_detectee']}")

    separateur("DEMO 4 : Syslog PIEGE - tentative d'injection de prompt")
    print("Un equipement compromis tente d'injecter des instructions cachees...")
    result = get_syslog_message(token, scenario="piege")
    print(f"Message NEUTRALISE : {result['message_neutralise']}")
    print(f"-> Injection detectee : {result['injection_detectee']}")
    print(f"-> Nombre de patterns suspects bloques : {result['nombre_patterns_suspects']}")

    separateur("DEMO 5 : Journal d'audit complet de cette session")
    with open("audit.log") as f:
        for ligne in f.readlines()[-5:]:
            print(ligne.strip())

    print("\n" + "=" * 70)
    print("  FIN DE LA DEMONSTRATION")
    print("=" * 70)
