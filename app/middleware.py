"""
CBAC Middleware
===============
Intercepts every /api/* request, resolves identity from the Bearer JWT,
evaluates the policy engine, enforces the decision, and writes the audit log.
"""

from fastapi import Request
from fastapi.responses import JSONResponse
from jose import JWTError

from app.auth import decode_token
from app.database import (
    fetch_active_policies,
    fetch_user,
    get_db,
    record_trusted_device,
    write_access_log,
)
from app.engine import evaluate_policies, extract_request_context, user_location_cache

# Maps internal decision values to HTTP status codes and user-facing messages.
# Adding a new rule type only requires a new entry here — middleware logic unchanged.
_DECISION_RESPONSES = {
    "BLOCK": {
        "status_code": 403,
        "messages": {
            "business_hours_only": "Blocked: Outside allowed access hours.",
            "impossible_travel":   "Blocked: Impossible Travel Detected.",
            "identity_check":      "Blocked: Identity verification failed.",
        },
        "default_message": "Blocked: Access denied by policy.",
    },
    "MFA_CHALLENGE": {
        "status_code": 401,
        "messages": {
            "device_fingerprint_change": "Challenge: Unrecognized device. MFA Required.",
        },
        "default_message": "Challenge: Additional verification required.",
    },
}


async def cbac_middleware(request: Request, call_next):
    """
    CBAC gateway middleware — attached to the FastAPI app in app/main.py.

    Flow:
      1. Skip non-/api/* paths (login, dashboard, static files).
      2. Skip /api/logs to prevent recursive log growth.
      3. Extract context (IP, country, UA, time, unix timestamp).
      4. Extract and verify Bearer JWT  →  401 on failure.
      5. Resolve user from DB           →  401 if not found / inactive.
      6. Load active policies from DB.
      7. evaluate_policies() — pure, receives cache as argument.
      8. Write one row to access_logs regardless of outcome.
      9. Enforce:  BLOCK → 403  |  MFA_CHALLENGE → 401  |  ALLOW → pass through.
     10. On ALLOW: update velocity cache; enroll device if first-time.
    """
    if not request.url.path.startswith("/api/"):
        return await call_next(request)

    if request.url.path == "/api/logs":
        return await call_next(request)

    # 3. Context
    ctx = extract_request_context(request)

    # 4. JWT identity
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        with get_db() as conn:
            write_access_log(
                conn,
                user_id=None, username=None,
                ip_address=ctx["ip"], country=ctx["country"], city=ctx.get("city"),
                action="BLOCK", policy_name="identity_check",
                reason="Missing or malformed Authorization header.",
            )
        return JSONResponse(
            status_code=401,
            content={"status": "error", "message": "Missing or malformed Authorization header."},
        )

    token = auth_header[7:]
    try:
        payload = decode_token(token)
    except Exception:
        with get_db() as conn:
            write_access_log(
                conn,
                user_id=None, username=None,
                ip_address=ctx["ip"], country=ctx["country"], city=ctx.get("city"),
                action="BLOCK", policy_name="identity_check",
                reason="Invalid or expired JWT.",
            )
        return JSONResponse(
            status_code=401,
            content={"status": "error", "message": "Invalid or expired token."},
        )

    user_id = payload.get("sub")

    with get_db() as conn:
        # 5. User lookup
        user = fetch_user(conn, user_id)
        if user is None:
            write_access_log(
                conn,
                user_id=None, username=None,
                ip_address=ctx["ip"], country=ctx["country"], city=ctx.get("city"),
                action="BLOCK", policy_name="identity_check",
                reason=f"Unknown or inactive user id='{user_id}'.",
            )
            return JSONResponse(
                status_code=401,
                content={"status": "error", "message": "Unknown or inactive user."},
            )

        # 6. Load policies
        policies = fetch_active_policies(conn)

        # 7. Evaluate
        result = evaluate_policies(ctx, user, policies, user_location_cache)

        print(
            f"[CBAC] {request.method} {request.url.path}"
            f" | user={user['username']} ip={ctx['ip']}"
            f" location={ctx.get('city','?')}, {ctx['country']}"
            f" hour={ctx['hour']:02d}"
            f" | {result['decision']} ({result['policy_name'] or 'default-allow'})"
            f" | {result['reason']}"
        )

        # 8. Audit log
        write_access_log(
            conn,
            user_id=user["id"], username=user["username"],
            ip_address=ctx["ip"], country=ctx["country"], city=ctx.get("city"),
            action=result["decision"],
            policy_name=result["policy_name"],
            reason=result["reason"],
        )

        # 9. Enforce
        if result["decision"] in _DECISION_RESPONSES:
            cfg     = _DECISION_RESPONSES[result["decision"]]
            message = cfg["messages"].get(result["policy_name"], cfg["default_message"])
            return JSONResponse(
                status_code=cfg["status_code"],
                content={
                    "status":  result["decision"].lower(),
                    "message": message,
                    "policy":  result["policy_name"],
                    "detail":  result["reason"],
                },
            )

        # 10. ALLOW — update velocity cache; enroll device if first request
        user_location_cache[str(user_id)] = {
            "country":   ctx["country"],
            "timestamp": ctx["timestamp"],
        }
        if user["last_user_agent"] is None:
            record_trusted_device(conn, user_id, ctx["user_agent"])
            print(f"[CBAC]  -> Enrolled trusted device for '{user['username']}'")

    return await call_next(request)
