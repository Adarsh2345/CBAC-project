"""
CBAC Policy Engine
==================
Pure functions only — no I/O, no database, no global state mutations.
Everything is passed in as arguments so the entire module is unit-testable
with plain Python dicts and no test fixtures.

Geo-IP is resolved via ip-api.com (free, no API key required).
Results are cached in _geo_cache for GEO_CACHE_TTL_SECONDS to avoid
hitting the API on every request.
"""

import json
import time
from datetime import datetime

import httpx
from fastapi import Request

# ---------------------------------------------------------------------------
# In-memory velocity cache  (simulates Redis)
# ---------------------------------------------------------------------------

# { user_id (str): {"country": str, "timestamp": float} }
# Written by the middleware AFTER a successful ALLOW decision, never inside
# the engine itself — keeps the engine free of side-effects.
user_location_cache: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Real geo-IP via ip-api.com
# ---------------------------------------------------------------------------

# Cache resolved geo data for 1 hour so the same IP doesn't trigger a new
# HTTP call on every request. Private/loopback IPs are resolved instantly
# to a local fallback without any network call.
GEO_CACHE_TTL_SECONDS = 3600

_geo_cache: dict[str, dict] = {}

# IP ranges that are private/loopback — no point calling a geo API for these.
_PRIVATE_PREFIXES = ("127.", "10.", "192.168.", "::1", "0.0.0.0")

_GEO_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,query"


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES) or ip == "unknown"


def lookup_geo(ip: str) -> dict:
    """
    Return geo data for an IP address.

    For private/loopback IPs returns a local placeholder so development
    requests are never misidentified as foreign.

    For public IPs, calls ip-api.com (free tier: 45 req/min, no key needed).
    Result is cached for GEO_CACHE_TTL_SECONDS.

    Returns:
        {
            "country":      str,   e.g. "United States"
            "country_code": str,   e.g. "US"
            "city":         str,   e.g. "New York"
        }
    """
    # Private/loopback → local placeholder, no network call
    if _is_private(ip):
        return {"country": "Local Network", "country_code": "LO", "city": "localhost"}

    # Cache hit?
    cached = _geo_cache.get(ip)
    if cached and (time.time() - cached["_fetched_at"]) < GEO_CACHE_TTL_SECONDS:
        return {k: v for k, v in cached.items() if k != "_fetched_at"}

    # Live lookup
    try:
        resp = httpx.get(_GEO_API_URL.format(ip=ip), timeout=3.0)
        data = resp.json()
        if data.get("status") == "success":
            geo = {
                "country":      data.get("country",     "Unknown"),
                "country_code": data.get("countryCode", "??"),
                "city":         data.get("city",        "Unknown"),
            }
        else:
            geo = {"country": "Unknown", "country_code": "??", "city": "Unknown"}
    except Exception:
        # Network failure — fail open (don't block the user just because
        # the geo API is down). Log as Unknown so the audit trail is honest.
        geo = {"country": "Unknown", "country_code": "??", "city": "Unknown"}

    _geo_cache[ip] = {**geo, "_fetched_at": time.time()}
    return geo


# ---------------------------------------------------------------------------
# Context extractor
# ---------------------------------------------------------------------------

def extract_request_context(request: Request) -> dict:
    """
    Pull observable signals from an incoming HTTP request.

    Returns a plain dict so the engine can be called with any dict-like
    object in tests — no FastAPI Request object required in unit tests.

    The geo lookup is performed here (not inside evaluate_policies) so the
    engine stays pure — it receives resolved data, never calls the network.
    """
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        ip = forwarded_for.split(",")[0].strip()
    else:
        ip = request.client.host if request.client else "unknown"

    user_agent = request.headers.get("user-agent", "unknown")
    now = datetime.now()
    geo = lookup_geo(ip)

    return {
        "ip":           ip,
        "country":      geo["country"],
        "country_code": geo["country_code"],
        "city":         geo["city"],
        "user_agent":   user_agent,
        "server_time":  now,
        "hour":         now.hour,
        "timestamp":    time.time(),
    }


# ---------------------------------------------------------------------------
# Policy Engine
# ---------------------------------------------------------------------------

def evaluate_policies(
    ctx: dict,
    user: dict,
    policies: list,
    location_cache: dict,
) -> dict:
    """
    Walk each enabled policy in priority order; return the first match.

    Parameters
    ----------
    ctx            : dict from extract_request_context() or a plain test dict
    user           : sqlite3.Row or dict with keys: id, last_user_agent
    policies       : list of sqlite3.Row or dicts with keys:
                     rule_type, parameters (JSON str), action, policy_name
    location_cache : the caller's velocity cache dict (never mutated here)

    Returns
    -------
    {
        "decision":    "ALLOW" | "BLOCK" | "MFA_CHALLENGE",
        "policy_name": str | None,
        "reason":      str,
    }

    Rule details
    ------------
    TIME      — fires BLOCK when hour is outside [start_hour, end_hour)
    VELOCITY  — fires BLOCK when country changed faster than max_minutes allows
    DEVICE    — fires MFA_CHALLENGE when enrolled UA differs from incoming UA
    """
    user_id = str(user["id"])

    for policy in policies:
        params = json.loads(policy["parameters"])
        rule   = policy["rule_type"]
        action = policy["action"]
        name   = policy["policy_name"]

        # ── Rule 1: TIME ─────────────────────────────────────────────────
        if rule == "TIME":
            start = params.get("start_hour", 9)
            end   = params.get("end_hour",   17)
            if not (start <= ctx["hour"] < end):
                return {
                    "decision":    action,
                    "policy_name": name,
                    "reason": (
                        f"Outside allowed access hours "
                        f"({start:02d}:00-{end:02d}:00). "
                        f"Current hour: {ctx['hour']:02d}."
                    ),
                }

        # ── Rule 2: VELOCITY ─────────────────────────────────────────────
        elif rule == "VELOCITY":
            last = location_cache.get(user_id)
            if last is not None:
                elapsed     = ctx["timestamp"] - last["timestamp"]
                max_seconds = params.get("max_minutes", 10) * 60
                if last["country"] != ctx["country"] and elapsed < max_seconds:
                    return {
                        "decision":    action,
                        "policy_name": name,
                        "reason": (
                            f"Impossible travel detected. "
                            f"Last seen in {last['country']} "
                            f"{elapsed:.1f}s ago; "
                            f"now requesting from {ctx['country']}."
                        ),
                    }

        # ── Rule 3: DEVICE ───────────────────────────────────────────────
        elif rule == "DEVICE":
            trusted = user["last_user_agent"]
            if trusted is not None and trusted != ctx["user_agent"]:
                return {
                    "decision":    action,
                    "policy_name": name,
                    "reason": (
                        f"Unrecognized device. "
                        f"Trusted: '{trusted}'. "
                        f"Incoming: '{ctx['user_agent']}'."
                    ),
                }

    return {"decision": "ALLOW", "policy_name": None, "reason": "All policies passed."}
