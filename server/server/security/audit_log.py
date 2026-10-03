import json
import logging
from datetime import datetime, timezone
from pathlib import Path

AUDIT_LOG_PATH = Path(__file__).resolve().parent.parent.parent / "audit.log"

logger = logging.getLogger("mcp_audit")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.FileHandler(AUDIT_LOG_PATH, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


def log_action(user: str, tool: str, params: dict, status: str, detail: str = ""):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": user,
        "tool": tool,
        "params": {k: v for k, v in params.items()},
        "status": status,
        "detail": detail,
    }
    logger.info(json.dumps(entry, ensure_ascii=False))
