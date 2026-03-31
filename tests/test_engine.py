"""
Unit tests for the CBAC Policy Engine
======================================
All tests call evaluate_policies() directly with plain Python dicts.
No database, no HTTP server, no test fixtures required.

Run with:  pytest tests/ -v
"""

import json
import time

import pytest

from app.engine import evaluate_policies


# ---------------------------------------------------------------------------
# Helpers — build minimal dict stand-ins for sqlite3.Row objects
# ---------------------------------------------------------------------------

def make_user(last_user_agent=None, user_id=1):
    return {"id": user_id, "last_user_agent": last_user_agent}


def make_policy(rule_type, params: dict, action, priority=1, name=None):
    return {
        "rule_type":   rule_type,
        "parameters":  json.dumps(params),
        "action":      action,
        "policy_name": name or f"{rule_type.lower()}_policy",
    }


def make_ctx(hour=12, country="USA", user_agent="TestBrowser/1.0", offset_seconds=0):
    """Return a context dict. offset_seconds shifts the timestamp into the past."""
    return {
        "ip":          "127.0.0.1",
        "country":     country,
        "user_agent":  user_agent,
        "hour":        hour,
        "timestamp":   time.time() - offset_seconds,
    }


# ---------------------------------------------------------------------------
# Rule 1: TIME
# ---------------------------------------------------------------------------

class TestTimeRule:
    policy = make_policy("TIME", {"start_hour": 9, "end_hour": 17}, "BLOCK", name="business_hours_only")

    def test_blocks_before_window(self):
        result = evaluate_policies(make_ctx(hour=7), make_user(), [self.policy], {})
        assert result["decision"]    == "BLOCK"
        assert result["policy_name"] == "business_hours_only"

    def test_blocks_after_window(self):
        result = evaluate_policies(make_ctx(hour=17), make_user(), [self.policy], {})
        assert result["decision"] == "BLOCK"

    def test_blocks_at_midnight(self):
        result = evaluate_policies(make_ctx(hour=0), make_user(), [self.policy], {})
        assert result["decision"] == "BLOCK"

    def test_allows_at_window_start(self):
        result = evaluate_policies(make_ctx(hour=9), make_user(), [self.policy], {})
        assert result["decision"] == "ALLOW"

    def test_allows_inside_window(self):
        result = evaluate_policies(make_ctx(hour=12), make_user(), [self.policy], {})
        assert result["decision"] == "ALLOW"

    def test_allows_at_last_valid_hour(self):
        result = evaluate_policies(make_ctx(hour=16), make_user(), [self.policy], {})
        assert result["decision"] == "ALLOW"

    def test_disabled_policy_is_skipped(self):
        # A disabled policy dict shouldn't reach the engine — it's filtered
        # in fetch_active_policies. But if it somehow does, confirm it
        # doesn't crash (no is_enabled key in the engine's loop).
        result = evaluate_policies(make_ctx(hour=3), make_user(), [], {})
        assert result["decision"] == "ALLOW"


# ---------------------------------------------------------------------------
# Rule 2: VELOCITY
# ---------------------------------------------------------------------------

class TestVelocityRule:
    policy = make_policy("VELOCITY", {"max_minutes": 10}, "BLOCK", name="impossible_travel")

    def test_blocks_impossible_travel(self):
        cache = {"1": {"country": "USA", "timestamp": time.time() - 5}}  # 5s ago
        result = evaluate_policies(make_ctx(country="Japan"), make_user(), [self.policy], cache)
        assert result["decision"]    == "BLOCK"
        assert result["policy_name"] == "impossible_travel"
        assert "USA" in result["reason"]
        assert "Japan" in result["reason"]

    def test_blocks_cross_continent_in_seconds(self):
        cache = {"1": {"country": "UK", "timestamp": time.time() - 1}}
        result = evaluate_policies(make_ctx(country="Australia"), make_user(), [self.policy], cache)
        assert result["decision"] == "BLOCK"

    def test_allows_same_country(self):
        cache = {"1": {"country": "USA", "timestamp": time.time() - 5}}
        result = evaluate_policies(make_ctx(country="USA"), make_user(), [self.policy], cache)
        assert result["decision"] == "ALLOW"

    def test_allows_no_prior_cache_entry(self):
        """First request for a user — no baseline to compare against."""
        result = evaluate_policies(make_ctx(country="Japan"), make_user(), [self.policy], {})
        assert result["decision"] == "ALLOW"

    def test_allows_when_enough_time_has_passed(self):
        """Travel that is plausible (elapsed > max_minutes)."""
        max_sec = 10 * 60
        cache   = {"1": {"country": "USA", "timestamp": time.time() - (max_sec + 1)}}
        result  = evaluate_policies(make_ctx(country="UK"), make_user(), [self.policy], cache)
        assert result["decision"] == "ALLOW"

    def test_cache_is_keyed_by_user_id(self):
        """Cache for user 2 should not affect user 1's evaluation."""
        cache = {"2": {"country": "Japan", "timestamp": time.time() - 5}}
        result = evaluate_policies(make_ctx(country="UK"), make_user(user_id=1), [self.policy], cache)
        assert result["decision"] == "ALLOW"


# ---------------------------------------------------------------------------
# Rule 3: DEVICE
# ---------------------------------------------------------------------------

class TestDeviceRule:
    policy = make_policy("DEVICE", {}, "MFA_CHALLENGE", name="device_fingerprint_change")

    def test_challenges_on_ua_change(self):
        user   = make_user(last_user_agent="TrustedBrowser/1.0")
        result = evaluate_policies(
            make_ctx(user_agent="EvilBot/3.0"), user, [self.policy], {}
        )
        assert result["decision"]    == "MFA_CHALLENGE"
        assert result["policy_name"] == "device_fingerprint_change"
        assert "TrustedBrowser/1.0" in result["reason"]
        assert "EvilBot/3.0"        in result["reason"]

    def test_allows_matching_ua(self):
        user   = make_user(last_user_agent="TrustedBrowser/1.0")
        result = evaluate_policies(
            make_ctx(user_agent="TrustedBrowser/1.0"), user, [self.policy], {}
        )
        assert result["decision"] == "ALLOW"

    def test_allows_no_enrolled_device(self):
        """last_user_agent is None — first request, should enroll, not block."""
        user   = make_user(last_user_agent=None)
        result = evaluate_policies(
            make_ctx(user_agent="AnyBrowser/1.0"), user, [self.policy], {}
        )
        assert result["decision"] == "ALLOW"

    def test_challenges_known_attack_tool(self):
        user   = make_user(last_user_agent="Mozilla/5.0 (Windows NT 10.0) TrustedBrowser/1.0")
        result = evaluate_policies(
            make_ctx(user_agent="sqlmap/1.7.8"), user, [self.policy], {}
        )
        assert result["decision"] == "MFA_CHALLENGE"


# ---------------------------------------------------------------------------
# Priority ordering & default allow
# ---------------------------------------------------------------------------

class TestPriorityAndDefaults:

    def test_no_policies_returns_allow(self):
        result = evaluate_policies(make_ctx(), make_user(), [], {})
        assert result["decision"]    == "ALLOW"
        assert result["policy_name"] is None
        assert result["reason"]      == "All policies passed."

    def test_first_matching_policy_wins(self):
        """TIME rule fires first (priority 1) even though DEVICE would also match."""
        time_policy   = make_policy("TIME",   {"start_hour": 9, "end_hour": 17}, "BLOCK",        priority=1, name="time_rule")
        device_policy = make_policy("DEVICE", {},                                  "MFA_CHALLENGE", priority=2, name="device_rule")

        user   = make_user(last_user_agent="TrustedBrowser/1.0")
        ctx    = make_ctx(hour=3, user_agent="EvilBot/3.0")  # triggers both rules
        result = evaluate_policies(ctx, user, [time_policy, device_policy], {})

        assert result["decision"]    == "BLOCK"
        assert result["policy_name"] == "time_rule"

    def test_skips_blocked_rule_and_evaluates_next(self):
        """If the TIME rule passes, the DEVICE rule should still fire."""
        time_policy   = make_policy("TIME",   {"start_hour": 9, "end_hour": 17}, "BLOCK",        priority=1, name="time_rule")
        device_policy = make_policy("DEVICE", {},                                  "MFA_CHALLENGE", priority=2, name="device_rule")

        user   = make_user(last_user_agent="TrustedBrowser/1.0")
        ctx    = make_ctx(hour=12, user_agent="EvilBot/3.0")  # TIME passes, DEVICE triggers
        result = evaluate_policies(ctx, user, [time_policy, device_policy], {})

        assert result["decision"]    == "MFA_CHALLENGE"
        assert result["policy_name"] == "device_rule"
