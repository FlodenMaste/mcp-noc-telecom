import subprocess

from server.security.auth import require_role

SNMP_USER = "mcpreadonly"
SNMP_AUTH_PASS = "AuthPass2026!"
SNMP_PRIV_PASS = "PrivPass2026!"

KNOWN_ROUTERS = {
    "r1": "192.168.1.1",
    "r2": "2.2.2.2",
    "r3": "3.3.3.3",
}


@require_role("operateur")
def snmp_get(router: str, oid: str = ".1.3.6.1.2.1.1") -> dict:
    if router not in KNOWN_ROUTERS:
        return {
            "success": False,
            "error": f"Routeur inconnu : '{router}'. Valeurs possibles : {list(KNOWN_ROUTERS)}",
        }

    target_ip = KNOWN_ROUTERS[router]

    command = [
        "docker", "exec", "clab-mcp-noc-lab-client",
        "snmpwalk", "-v3", "-l", "authPriv",
        "-u", SNMP_USER,
        "-a", "SHA", "-A", SNMP_AUTH_PASS,
        "-x", "AES", "-X", SNMP_PRIV_PASS,
        target_ip, oid,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Timeout : le routeur n'a pas repondu."}

    if result.returncode != 0:
        return {
            "success": False,
            "error": f"Echec de la requete SNMP : {result.stderr.strip()}",
        }

    return {
        "success": True,
        "router": router,
        "oid": oid,
        "raw_output": result.stdout.strip(),
    }


# --- Version securisee de snmp_get, avec neutralisation des sorties ---
from server.security.sanitizer import sanitize_untrusted_output


@require_role("operateur")
def snmp_get_secure(router: str, oid: str = ".1.3.6.1.2.1.1") -> dict:
    """
    Identique a snmp_get, mais fait passer la sortie de l'equipement
    reseau (entree non fiable) par la couche de neutralisation avant
    de la retourner au LLM.
    """
    raw_result = snmp_get.__wrapped__(router, oid)

    if not raw_result.get("success"):
        return raw_result

    analysis = sanitize_untrusted_output(
        raw_result["raw_output"], source=f"snmp-{router}"
    )

    if analysis["is_flagged"]:
        from server.security.audit_log import log_action
        log_action(
            user="systeme",
            tool="snmp_get_secure",
            params={"router": router},
            status="ALERTE_INJECTION_NEUTRALISEE",
            detail=f"Patterns detectes : {analysis['flags_detected']}",
        )

    return {
        "success": True,
        "router": router,
        "oid": oid,
        "output": analysis["sanitized_text"],
        "injection_detectee": analysis["is_flagged"],
    }
