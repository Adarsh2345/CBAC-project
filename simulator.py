"""
CBAC Traffic Simulator
======================
Generates realistic mixed traffic against the Zero-Trust API Gateway.

Usage:
    python simulator.py              # default port 8000
    python simulator.py --port 8080
    python simulator.py --port 8080 --delay-min 0.2 --delay-max 1.0

Requires:  pip install requests
"""

import argparse
import random
import sys
import time

import requests

# ── ANSI colours ─────────────────────────────────────────────────────────────
RESET  = "\033[0m";  BOLD   = "\033[1m";  DIM    = "\033[2m"
GREEN  = "\033[92m"; RED    = "\033[91m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; PURPLE = "\033[95m"; WHITE  = "\033[97m"
GREY   = "\033[90m"

def c(colour, text): return f"{colour}{text}{RESET}"


# ── User profiles ─────────────────────────────────────────────────────────────
USERS = [
    {"username": "demo",  "password": "demo1234",
     "user_agent": "DemoApp/2.0 (Windows NT 10.0)"},
    {"username": "alice", "password": "alice1234",
     "user_agent": "Mozilla/5.0 (Windows NT 10.0) TrustedBrowser/1.0"},
]

# ── IP map ────────────────────────────────────────────────────────────────────
IPS = {
    "USA":       ["127.0.0.1", "203.0.113.10", "198.51.100.5"],
    "Japan":     ["8.8.8.8"],
    "UK":        ["9.9.9.9"],
    "Australia": ["1.1.1.1"],
    "Germany":   ["4.4.4.4"],
    "Canada":    ["208.67.222.222"],
}

ROGUE_AGENTS = [
    "sqlmap/1.7.8", "Nikto/2.1.6", "python-requests/2.31 AutoScanner",
    "curl/7.0-EvilBot", "Go-http-client/2.0 C2Beacon",
    "Mozilla/5.0 (compatible; MegaCrawler/3.0)",
]


# ── Token cache ───────────────────────────────────────────────────────────────
_TOKENS: dict[str, str] = {}


def authenticate_all(base_url: str):
    """Log in every user profile once and cache their JWT tokens."""
    print(c(GREY, "  Authenticating user profiles..."))
    for user in USERS:
        try:
            resp = requests.post(
                f"{base_url}/auth/login",
                json={"username": user["username"], "password": user["password"]},
                timeout=5,
            )
            resp.raise_for_status()
            _TOKENS[user["username"]] = resp.json()["access_token"]
            print(f"    {c(GREEN, 'OK')}  {user['username']}")
        except Exception as exc:
            print(c(RED, f"    FAIL  {user['username']}: {exc}"))
            sys.exit(1)
    print()


# ── Request helper ────────────────────────────────────────────────────────────

def _request(base_url, username, user_agent, forwarded_ip):
    return requests.get(
        f"{base_url}/api/payroll",
        headers={
            "Authorization":   f"Bearer {_TOKENS.get(username, '')}",
            "User-Agent":       user_agent,
            "X-Forwarded-For":  forwarded_ip,
        },
        timeout=5,
    )


def _resp_json(resp):
    try:    return resp.json()
    except: return {}


def _print_result(scenario, user, ip, status, body):
    if status == 200:
        badge = c(GREEN,  "  ALLOW   ")
    elif status == 403:
        badge = c(RED,    "  BLOCK   ")
    elif status == 401 and "mfa" in body.get("status", "").lower():
        badge = c(YELLOW, " CHALLENGE")
    else:
        badge = c(YELLOW, f"  {status}      ")

    policy  = body.get("policy") or ""
    message = body.get("message", "")
    detail  = f"{c(GREY, policy + ' - ') if policy else ''}{message}"
    print(
        f"  {badge}  "
        f"{c(CYAN, f'{user:<8}')}"
        f"  {c(WHITE, f'{ip:<20}')}"
        f"  {c(DIM, scenario + ':'):<30}"
        f"  {detail}"
    )


# ── Scenarios ─────────────────────────────────────────────────────────────────

def simulate_normal_traffic(base_url):
    user = random.choice(USERS)
    ip   = random.choice(IPS["USA"])
    resp = _request(base_url, user["username"], user["user_agent"], ip)
    _print_result("normal_traffic", user["username"], ip, resp.status_code, _resp_json(resp))


def simulate_impossible_travel(base_url):
    user       = random.choice(USERS)
    usa_ip     = random.choice(IPS["USA"])
    foreign_ip = random.choice(IPS["Japan"] + IPS["UK"] + IPS["Australia"])
    country    = next(k for k, v in IPS.items() if foreign_ip in v)

    resp1 = _request(base_url, user["username"], user["user_agent"], usa_ip)
    _print_result("travel leg-1 (USA)", user["username"], usa_ip,
                  resp1.status_code, _resp_json(resp1))
    time.sleep(0.5)
    resp2 = _request(base_url, user["username"], user["user_agent"], foreign_ip)
    _print_result(f"travel leg-2 ({country})", user["username"], foreign_ip,
                  resp2.status_code, _resp_json(resp2))


def simulate_device_spoofing(base_url):
    """Always targets alice — she has a pre-enrolled trusted device."""
    user     = next(u for u in USERS if u["username"] == "alice")
    rogue_ua = random.choice(ROGUE_AGENTS)
    ip       = random.choice(IPS["USA"])
    resp     = _request(base_url, user["username"], rogue_ua, ip)
    _print_result("device_spoofing", user["username"], ip, resp.status_code, _resp_json(resp))


def simulate_unknown_user(base_url):
    """Sends a deliberately invalid JWT token."""
    ip   = random.choice(IPS["USA"])
    resp = requests.get(
        f"{base_url}/api/payroll",
        headers={
            "Authorization":   "Bearer invalid.jwt.token",
            "User-Agent":       "LegitBrowser/1.0",
            "X-Forwarded-For":  ip,
        },
        timeout=5,
    )
    _print_result("invalid_token", "anon", ip, resp.status_code, _resp_json(resp))


# ── Weighted pool ─────────────────────────────────────────────────────────────
SCENARIOS = [
    (simulate_normal_traffic,    "Normal traffic",    5),
    (simulate_impossible_travel, "Impossible travel", 2),
    (simulate_device_spoofing,   "Device spoofing",   2),
    (simulate_unknown_user,      "Invalid token",     1),
]
_POOL = [fn for fn, _, w in SCENARIOS for _ in range(w)]


def print_banner(base_url, delay_min, delay_max):
    print()
    print(c(BOLD + PURPLE, "  +------------------------------------------------+"))
    print(c(BOLD + PURPLE, "  |    CBAC Gateway -- Traffic Simulator  v2.0     |"))
    print(c(BOLD + PURPLE, "  +------------------------------------------------+"))
    print()
    print(f"  {c(GREY, 'Target   :')} {c(CYAN, base_url)}")
    print(f"  {c(GREY, 'Interval :')} {c(WHITE, f'{delay_min}s - {delay_max}s random')}")
    print()
    print(c(GREY, "  " + "-" * 90))
    print(f"  {'RESULT':<12} {'USER':<10} {'IP':<22} {'SCENARIO':<28} DETAIL")
    print(c(GREY, "  " + "-" * 90))
    print()


def main():
    parser = argparse.ArgumentParser(description="CBAC traffic simulator")
    parser.add_argument("--port",      type=int,   default=8000)
    parser.add_argument("--delay-min", type=float, default=0.5)
    parser.add_argument("--delay-max", type=float, default=2.0)
    args = parser.parse_args()

    base_url = f"http://localhost:{args.port}"

    try:
        requests.get(f"{base_url}/health", timeout=3).raise_for_status()
    except Exception as exc:
        print(c(RED, f"\n  [ERROR] Cannot reach {base_url}/health\n  {exc}\n"))
        sys.exit(1)

    print_banner(base_url, args.delay_min, args.delay_max)
    authenticate_all(base_url)
    print(c(GREEN, "  All profiles authenticated. Starting simulation...\n"))

    count = 0
    try:
        while True:
            fn = random.choice(_POOL)
            count += 1
            name = next(n for f, n, _ in SCENARIOS if f == fn)
            print(c(GREY, f"  [{count:>4}]  ") + c(BOLD + WHITE, name))
            try:
                fn(base_url)
            except requests.exceptions.ConnectionError:
                print(c(RED, "         [!] Connection refused."))
            except Exception as exc:
                print(c(RED, f"         [!] {exc}"))
            print()
            time.sleep(random.uniform(args.delay_min, args.delay_max))
    except KeyboardInterrupt:
        print(c(GREY, f"\n  Stopped after {count} scenarios.\n"))


if __name__ == "__main__":
    main()
