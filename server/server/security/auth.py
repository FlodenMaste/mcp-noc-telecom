import functools
import jwt

from server.config import JWT_SECRET, JWT_ALGORITHM, role_satisfies
from server.security.audit_log import log_action


class AccessDeniedError(Exception):
    pass


def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise AccessDeniedError("Jeton expire. Veuillez en generer un nouveau.")
    except jwt.InvalidTokenError:
        raise AccessDeniedError("Jeton invalide ou signature incorrecte.")

    if "user" not in payload or "role" not in payload:
        raise AccessDeniedError("Jeton mal forme (user/role manquant).")

    return payload


def require_role(required_role: str):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(token: str, *args, **kwargs):
            tool_name = func.__name__

            try:
                payload = verify_token(token)
            except AccessDeniedError as e:
                log_action(
                    user="inconnu",
                    tool=tool_name,
                    params=kwargs,
                    status="REFUSE",
                    detail=str(e),
                )
                raise

            user = payload["user"]
            user_role = payload["role"]

            if not role_satisfies(user_role, required_role):
                detail = (
                    f"Role '{user_role}' insuffisant "
                    f"(role '{required_role}' requis pour '{tool_name}')."
                )
                log_action(
                    user=user, tool=tool_name, params=kwargs,
                    status="REFUSE", detail=detail,
                )
                raise AccessDeniedError(detail)

            log_action(
                user=user, tool=tool_name, params=kwargs,
                status="AUTORISE", detail=f"role={user_role}",
            )

            return func(*args, **kwargs)

        return wrapper
    return decorator
