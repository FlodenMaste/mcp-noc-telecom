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
