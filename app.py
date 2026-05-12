import os
import json
import base64
import re
import time
import threading
import requests
from collections import deque
from dotenv import load_dotenv

# Load .env BEFORE Sentry init so SENTRY_DSN is available in local dev.
load_dotenv()

# ============================================================
# SENTRY ERROR MONITORING — initialized BEFORE Flask
# ------------------------------------------------------------
# Must run before `app = Flask(__name__)` so Sentry's FlaskIntegration
# can hook into the WSGI app at construction time and capture every
# unhandled exception with full request context (URL, method, headers,
# user, payload).
#
# Behavior:
#   - If SENTRY_DSN env var is set: Sentry SDK initializes and reports
#     errors. The init wraps Flask, requests, and stdlib logging.
#   - If SENTRY_DSN is missing (e.g. local dev without a key): we log
#     a single line and continue. The app runs identically; we just
#     don't get error reports. NEVER crashes the app on missing DSN.
#   - If sentry_sdk is not installed: same fail-soft behavior.
#
# The DSN itself is treated as a "shared secret" (it's not truly secret
# — it appears in the browser bundle for frontend Sentry — but we read
# it from env on the backend so we can rotate without code changes).
# ============================================================
_SENTRY_OK = False
_SENTRY_ERR = ""
try:
    _sentry_dsn = (os.getenv("SENTRY_DSN") or "").strip()
    if _sentry_dsn:
        import sentry_sdk
        from sentry_sdk.integrations.flask import FlaskIntegration
        sentry_sdk.init(
            dsn=_sentry_dsn,
            # Environment tag — useful for filtering prod vs dev errors in
            # Sentry's UI. Defaults to 'production' since this code lives
            # on Render; override locally via SENTRY_ENVIRONMENT=development.
            environment=os.getenv("SENTRY_ENVIRONMENT", "production"),
            # Release tag — lets Sentry group errors by deploy. If we ever
            # wire a git SHA via env var, this surfaces it. Falls back to
            # an empty string (Sentry will assign a default) if not set.
            release=os.getenv("SENTRY_RELEASE", ""),
            integrations=[FlaskIntegration()],
            # Sample rates:
            #   traces_sample_rate=0   — performance/tracing OFF. We only
            #     want errors right now; tracing costs quota and adds noise.
            #   profiles_sample_rate=0 — profiling OFF for the same reason.
            traces_sample_rate=0.0,
            profiles_sample_rate=0.0,
            # PII handling: send_default_pii=False means Sentry will NOT
            # auto-attach IP addresses or request bodies. We add user_id
            # context manually elsewhere when useful, never raw PII.
            send_default_pii=False,
            # Capture stdlib logging at ERROR level too (Flask's default
            # logger). WARNINGs are dropped to keep quota in check.
            # NOTE: print() calls are NOT captured — only `logging.error`.
            attach_stacktrace=True,
            # Drop noisy errors we don't care about. Add patterns here as
            # they surface in production. Match against the exception type
            # name OR the message string.
            ignore_errors=[
                # KeyboardInterrupt only fires during local dev (Ctrl+C).
                "KeyboardInterrupt",
                # SystemExit fires during Render graceful shutdowns.
                "SystemExit",
            ],
        )
        _SENTRY_OK = True
        print(f"[sentry] initialized — environment={os.getenv('SENTRY_ENVIRONMENT', 'production')}")
    else:
        _SENTRY_ERR = "SENTRY_DSN not set"
        print(f"[sentry] {_SENTRY_ERR} — error monitoring disabled")
except Exception as _sentry_err:
    _SENTRY_ERR = f"init_failed: {str(_sentry_err)[:160]}"
    print(f"[sentry] {_SENTRY_ERR}")

from flask import Flask, jsonify, request, Response
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ============================================================
# OPTIONAL DEPENDENCIES — Clerk webhook + Supabase client
# ============================================================
# These imports and the supabase client init are wrapped in try/except so
# that if the libs are missing OR misconfigured, the rest of the app keeps
# working. The new /api/clerk-webhook endpoint will return a clear error,
# but anonymous users will not be affected.
_AUTH_DEPS_OK = False
_AUTH_DEPS_ERR = ""
_supabase_client = None
try:
    from svix.webhooks import Webhook as SvixWebhook  # for Clerk webhook signature verification
    from supabase import create_client as _create_supabase_client  # supabase-py
    import jwt as _jwt  # PyJWT — for verifying Clerk session JWTs networklessly via JWKS
    from jwt import PyJWKClient  # JWKS fetcher with built-in caching
    _AUTH_DEPS_OK = True
    print("[auth-deps] svix, supabase, PyJWT libs imported OK")
except Exception as _imp_err:
    _AUTH_DEPS_ERR = f"import_failed: {str(_imp_err)[:160]}"
    print(f"[auth-deps] {_AUTH_DEPS_ERR}")

def _get_supabase():
    """Lazy-init the Supabase client. Returns None if unavailable.
    Never raises — callers handle None as 'auth temporarily unavailable'."""
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client
    if not _AUTH_DEPS_OK:
        return None
    url = (os.getenv("SUPABASE_URL") or "").strip()
    key = (os.getenv("SUPABASE_SERVICE_KEY") or "").strip()
    if not url or not key:
        print("[supabase] SUPABASE_URL or SUPABASE_SERVICE_KEY missing")
        return None
    try:
        _supabase_client = _create_supabase_client(url, key)
        print("[supabase] client initialized")
        return _supabase_client
    except Exception as e:
        print(f"[supabase] init failed: {e}")
        return None


# ============================================================
# RAZORPAY SDK — optional dep, lazy client init
# ============================================================
# Same pattern as Supabase: import wrapped in try/except so missing libs
# don't crash the app. Razorpay endpoints return a clear error if the SDK
# isn't installed or keys aren't configured. Anonymous + free users are
# completely unaffected — only paid checkout/webhook routes use this.
# ============================================================
_RAZORPAY_DEPS_OK = False
_RAZORPAY_DEPS_ERR = ""
_razorpay_client = None
try:
    import razorpay as _razorpay
    _RAZORPAY_DEPS_OK = True
    print("[razorpay-deps] razorpay lib imported OK")
except Exception as _rzp_imp_err:
    _RAZORPAY_DEPS_ERR = f"import_failed: {str(_rzp_imp_err)[:160]}"
    print(f"[razorpay-deps] {_RAZORPAY_DEPS_ERR}")


def _get_razorpay():
    """Lazy-init the Razorpay client. Returns None if unavailable.
    Never raises — callers handle None as 'razorpay temporarily unavailable'."""
    global _razorpay_client
    if _razorpay_client is not None:
        return _razorpay_client
    if not _RAZORPAY_DEPS_OK:
        return None
    key_id = (os.getenv("RAZORPAY_KEY_ID") or "").strip()
    key_secret = (os.getenv("RAZORPAY_KEY_SECRET") or "").strip()
    if not key_id or not key_secret:
        print("[razorpay] RAZORPAY_KEY_ID or RAZORPAY_KEY_SECRET missing")
        return None
    # Sanity check: live keys start with rzp_live_, test with rzp_test_
    # We don't enforce this strictly (allow either) but warn if it's neither
    if not (key_id.startswith("rzp_live_") or key_id.startswith("rzp_test_")):
        print(f"[razorpay] WARN: RAZORPAY_KEY_ID has unexpected prefix: {key_id[:10]}...")
    try:
        _razorpay_client = _razorpay.Client(auth=(key_id, key_secret))
        print(f"[razorpay] client initialized (key_id prefix: {key_id[:9]}...)")
        return _razorpay_client
    except Exception as e:
        print(f"[razorpay] init failed: {e}")
        return None


# ============================================================
# TIER + CYCLE → RAZORPAY PLAN ID LOOKUP
# ============================================================
# Maps (tier, cycle) → env var name → plan_id string.
# Tier values: 'creator' | 'pro' | 'agency'   (free is not paid, no plan)
# Cycle values: 'monthly' | 'yearly'
#
# Returns the plan_id string from env vars, or None if missing.
# We DO NOT hard-code plan IDs — they live in env vars so test/live keys
# can be swapped without code changes.
# ============================================================
def _get_razorpay_plan_id(tier, cycle):
    """Return the Razorpay plan_id for a given tier+cycle, or None if missing.
    Never raises."""
    t = (tier or "").strip().lower()
    c = (cycle or "").strip().lower()
    valid_tiers = {"creator", "pro", "agency"}
    valid_cycles = {"monthly", "yearly"}
    if t not in valid_tiers or c not in valid_cycles:
        print(f"[razorpay] _get_razorpay_plan_id: invalid tier={tier} or cycle={cycle}")
        return None
    env_var = f"RAZORPAY_PLAN_{t.upper()}_{c.upper()}"
    plan_id = (os.getenv(env_var) or "").strip()
    if not plan_id:
        print(f"[razorpay] env var {env_var} not set")
        return None
    return plan_id


# ============================================================
# PAYPAL API — OAuth token cache + plan lookup helpers
# ============================================================
# PayPal uses OAuth: get an access_token using CLIENT_ID + SECRET, then use that
# token in subsequent requests. Token expires every ~9 hours. We cache in-memory
# and refresh when expired or near-expiry.
#
# We use the LIVE base URL. Sandbox would use api-m.sandbox.paypal.com, but
# we made the live-mode decision in the sprint plan.
#
# Anonymous + free users + Razorpay users are completely unaffected — only
# PayPal endpoints touch this code.
# ============================================================
_PAYPAL_API_BASE = "https://api-m.paypal.com"
_paypal_token_cache = {"token": None, "expires_at": 0}  # epoch seconds


def _get_paypal_access_token():
    """Get a valid PayPal API access token, fetching/refreshing if needed.
    Returns the token string, or None if PayPal credentials are missing or call failed.
    Never raises."""
    import time as _time
    # Use cached token if still valid (with 60s safety margin)
    now = _time.time()
    if _paypal_token_cache["token"] and _paypal_token_cache["expires_at"] > now + 60:
        return _paypal_token_cache["token"]

    client_id = (os.getenv("PAYPAL_CLIENT_ID") or "").strip()
    client_secret = (os.getenv("PAYPAL_CLIENT_SECRET") or "").strip()
    if not client_id or not client_secret:
        print("[paypal] PAYPAL_CLIENT_ID or PAYPAL_CLIENT_SECRET missing")
        return None

    try:
        import requests as _requests
        resp = _requests.post(
            f"{_PAYPAL_API_BASE}/v1/oauth2/token",
            auth=(client_id, client_secret),
            headers={"Accept": "application/json", "Accept-Language": "en_US"},
            data={"grant_type": "client_credentials"},
            timeout=15,
        )
        if resp.status_code != 200:
            print(f"[paypal] OAuth failed: HTTP {resp.status_code} body={resp.text[:200]}")
            return None
        data = resp.json()
        token = data.get("access_token", "")
        expires_in = int(data.get("expires_in", 0) or 0)
        if not token or expires_in <= 0:
            print(f"[paypal] OAuth response malformed: {data}")
            return None
        _paypal_token_cache["token"] = token
        _paypal_token_cache["expires_at"] = now + expires_in
        print(f"[paypal] OAuth token cached, expires in {expires_in}s")
        return token
    except Exception as e:
        print(f"[paypal] OAuth exception: {e}")
        return None


def _get_paypal_plan_id(tier, cycle):
    """Return the PayPal plan_id for a given tier+cycle, or None if missing.
    Never raises."""
    t = (tier or "").strip().lower()
    c = (cycle or "").strip().lower()
    valid_tiers = {"creator", "pro", "agency"}
    valid_cycles = {"monthly", "yearly"}
    if t not in valid_tiers or c not in valid_cycles:
        print(f"[paypal] _get_paypal_plan_id: invalid tier={tier} or cycle={cycle}")
        return None
    env_var = f"PAYPAL_PLAN_{t.upper()}_{c.upper()}"
    plan_id = (os.getenv(env_var) or "").strip()
    if not plan_id:
        print(f"[paypal] env var {env_var} not set")
        return None
    return plan_id


def _paypal_tier_from_plan_id(plan_id):
    """Reverse-lookup: given a PayPal plan_id, return (tier, cycle).
    Used by the webhook to determine which tier a user just bought.
    Returns ('creator'|'pro'|'agency'|'', 'monthly'|'yearly'|''). Never raises."""
    if not plan_id:
        return "", ""
    plan_id = plan_id.strip()
    for tier in ("creator", "pro", "agency"):
        for cycle in ("monthly", "yearly"):
            env_var = f"PAYPAL_PLAN_{tier.upper()}_{cycle.upper()}"
            if (os.getenv(env_var) or "").strip() == plan_id:
                return tier, cycle
    return "", ""


# ============================================================
# SUBSCRIPTION CONFLICT CHECK
# ============================================================
# Prevents users from accidentally double-subscribing — e.g. they have an
# active Razorpay subscription and click PayPal-Subscribe, which would
# create a parallel subscription and lose the link to their original one.
#
# Returns a conflict dict if user has a genuinely active subscription with
# a DIFFERENT provider OR a DIFFERENT tier than what they're trying to buy.
# Returns None if no conflict — user can proceed.
#
# "Genuinely active" = subscription_status='active' AND current_period_end
# is in the future. Cancelled/halted/expired/created users can re-subscribe.
#
# Same-tier-same-provider is also allowed (no-op, harmless retry).
# ============================================================
def _check_subscription_conflict(supa, user_id, requested_provider, requested_tier, requested_cycle):
    """Check if user already has an active subscription that conflicts with
    a new checkout request.

    Returns:
        None        — no conflict, user can proceed
        dict        — conflict found, with shape:
                      {"existing_provider": str, "existing_tier": str,
                       "existing_subscription_id": str, "current_period_end": str,
                       "reason": str}
    Never raises. On DB error, returns None (fail-open — better to allow than to
    block a paying user due to our infrastructure issue)."""
    if supa is None or not user_id:
        return None
    try:
        res = (supa.table("users")
               .select("tier, subscription_status, subscription_id, payment_provider, "
                       "current_period_end")
               .eq("id", user_id)
               .limit(1)
               .execute())
        if not res.data or len(res.data) == 0:
            return None  # no row yet — no conflict possible
        row = res.data[0]
    except Exception as e:
        print(f"[conflict-check] DB read failed for user={user_id}: {e}")
        return None  # fail-open

    status = (row.get("subscription_status") or "").strip().lower()
    existing_provider = (row.get("payment_provider") or "").strip().lower()
    existing_tier = (row.get("tier") or "free").strip().lower()
    existing_period_end = row.get("current_period_end") or ""

    # ----------------------------------------------------------------
    # New rule (Phase 2 Day 5 fix): block any new checkout while the
    # user still has paid access, regardless of subscription_status.
    #
    # Why: previously we only blocked when status='active', which meant
    # a 'cancelled' user with a future period_end could start a new
    # checkout. That overwrites the existing subscription_id / plan_id /
    # payment_provider on their user row — destroying our handle to the
    # original (still-billing-or-just-cancelled) subscription. The user
    # ends up in a confusing state: we can't show them their real
    # subscription, and our /api/me/cancel-subscription would call the
    # wrong provider's API.
    #
    # New behavior:
    #   - If user has tier='free' OR period has expired → no conflict.
    #     The lazy-create / webhook path handles transitions cleanly.
    #   - Otherwise (paid tier + future period_end): the user already
    #     has access. Force them to either wait for period_end or use
    #     My Account → Cancel to reset state explicitly.
    # ----------------------------------------------------------------

    # No paid access right now → no conflict
    if existing_tier == "free":
        return None
    if existing_period_end and not _is_period_active(existing_period_end):
        return None
    if not existing_period_end:
        # Paid tier but no period date — odd state (likely halted/expired
        # without a date stamp). Fall back to the old status-only check:
        # only block if currently active.
        if status != "active":
            return None

    # User has live paid access (period in the future). Allow ONLY the
    # narrow same-tier + same-provider + active retry case. Every other
    # case (different tier, different provider, cancelled, paused, halted,
    # created — anything) is blocked.
    requested_provider_norm = (requested_provider or "").strip().lower()
    requested_tier_norm = (requested_tier or "").strip().lower()
    is_same_tier_provider = (
        existing_provider == requested_provider_norm
        and existing_tier == requested_tier_norm
    )
    if status == "active" and is_same_tier_provider:
        # Legitimate retry of the exact same subscription — redundant request
        # is harmlessly orphaned at the provider's end.
        return None

    # Genuine conflict: user has live paid access, and the new checkout would
    # overwrite the existing subscription's metadata.
    return {
        "existing_provider": existing_provider,
        "existing_tier": existing_tier,
        "existing_subscription_id": (row.get("subscription_id") or "").strip(),
        "existing_subscription_status": status,
        "current_period_end": existing_period_end,
        "reason": (
            f"already_subscribed_to_{existing_tier}_via_{existing_provider}"
            if existing_provider and existing_tier else "already_subscribed"
        ),
    }


# ============================================================
# DEFENSIVE CANCEL — used by force_resubscribe path
# ------------------------------------------------------------
# When a user clicks "Resume subscription" or "Switch plan" from My
# Account (with force_resubscribe=true), we want to ensure the OLD
# subscription at the provider is definitively cancelled before
# creating a new one. The old sub is usually already cancelled (the
# user got here via the Manage modal which only shows Resume/Switch
# for cancelled state) — but a defensive double-cancel costs us
# one API call and guarantees zero chance of a stray rebill.
#
# Safe to call on already-cancelled subs — providers either no-op
# or return a benign error (which we swallow).
#
# Never raises. Logs loudly on real failures but doesn't block the
# caller — the new subscription should proceed regardless.
# ============================================================
def _defensive_cancel_existing(supa, user_id):
    """Read user row → if subscription_id + payment_provider exist, call
    cancel on that sub at the provider. Best-effort. Never raises."""
    if supa is None or not user_id:
        return
    try:
        res = (supa.table("users")
               .select("subscription_id, payment_provider, subscription_status")
               .eq("id", user_id)
               .limit(1)
               .execute())
        row = res.data[0] if res.data and len(res.data) > 0 else None
    except Exception as e:
        print(f"[defensive-cancel] DB read failed for user={user_id}: {e}")
        return
    if not row:
        return
    old_sub_id = (row.get("subscription_id") or "").strip()
    old_provider = (row.get("payment_provider") or "").strip().lower()
    if not old_sub_id or not old_provider:
        return  # nothing to cancel

    if old_provider == "razorpay":
        rzp = _get_razorpay()
        if rzp is None:
            print(f"[defensive-cancel] razorpay client unavailable; "
                  f"skipping for user={user_id}")
            return
        try:
            rzp.subscription.cancel(old_sub_id, {"cancel_at_cycle_end": 0})
            print(f"[defensive-cancel] razorpay cancel OK: user={user_id} "
                  f"sub={old_sub_id}")
        except Exception as e:
            # Already-cancelled / completed / halted subs throw here — that's
            # the expected case in this code path (we're in "resume cancelled"
            # mode). Swallow + log at info level so it doesn't look like a bug
            # in the Render log stream.
            err_short = str(e)[:120]
            # Common phrases providers return for already-terminal subs
            looks_terminal = any(s in err_short.lower() for s in (
                "cancelled", "canceled", "completed", "expired", "not found",
                "already", "halted"
            ))
            if looks_terminal:
                print(f"[defensive-cancel] razorpay sub already terminal "
                      f"(expected); proceeding: user={user_id} sub={old_sub_id}")
            else:
                # Genuinely unexpected error — log loudly
                print(f"[defensive-cancel] razorpay cancel UNEXPECTED error "
                      f"(proceeding anyway): user={user_id} sub={old_sub_id} "
                      f"err={err_short}")
    elif old_provider == "paypal":
        access_token = _get_paypal_access_token()
        if not access_token:
            print(f"[defensive-cancel] paypal token unavailable; "
                  f"skipping for user={user_id}")
            return
        try:
            import requests as _requests
            resp = _requests.post(
                f"{_PAYPAL_API_BASE}/v1/billing/subscriptions/{old_sub_id}/cancel",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json={"reason": "User initiated resubscribe via OnePost "
                                "My Account"},
                timeout=15,
            )
            # 204 = success, 422 = already terminal. Both are fine here.
            if resp.status_code in (204, 422):
                print(f"[defensive-cancel] paypal cancel OK "
                      f"(HTTP {resp.status_code}): user={user_id} "
                      f"sub={old_sub_id}")
            else:
                print(f"[defensive-cancel] paypal cancel unexpected status "
                      f"{resp.status_code}: user={user_id} sub={old_sub_id} "
                      f"body={resp.text[:160]}")
        except Exception as e:
            print(f"[defensive-cancel] paypal cancel exception "
                  f"(proceeding): user={user_id} sub={old_sub_id} err={e}")
    else:
        print(f"[defensive-cancel] unknown provider={old_provider!r} for "
              f"user={user_id}; skipping")


# ============================================================
# WEBHOOK STALENESS CHECK — CME-1 race condition fix
# ------------------------------------------------------------
# Background: webhook handlers used to apply DB updates by matching only
# eq("id", user_id). When a user switched providers or resumed/switched
# plans, an OLD subscription's delayed webhook could arrive AFTER the
# NEW subscription was already active, and silently clobber the new
# sub's metadata. Self-healed on next webhook for the new sub, but
# user-visible state was wrong for seconds-to-minutes.
#
# This helper centralizes the "should we apply this webhook?" decision
# so both providers' handlers stay consistent.
#
# Returns: (should_apply: bool, reason: str)
#   reason is used both for logging AND as the webhook_events.status value
#   when we choose to skip ("ignored_stale_sub", "ignored_stale_active",
#   "applied_no_match_warned" for the NULL sub_id case).
#
# Rules (decided in product session 2026-05-11):
#   1. If row.subscription_id matches incoming sub_id → APPLY (normal case).
#   2. If row.subscription_id is NULL/empty → APPLY but log warning.
#   3. If mismatch AND event is ACTIVATED AND row.status != 'active' →
#      APPLY (broader rule: a freshly-paid sub wins over any non-active
#      stale state). This lets users complete a switch in one shot.
#   4. If mismatch AND event is ACTIVATED AND row.status == 'active' →
#      SKIP (stale activation collision; row already activated on a
#      newer/different sub, don't downgrade it).
#   5. If mismatch AND event is NOT activation (cancelled/charged/halted/
#      paused/etc.) → SKIP (this is the CME-1 race we're fixing).
#
# Never raises. On DB read failure, fails OPEN (returns apply=True) so we
# don't block legitimate webhooks because of an infrastructure issue.
# ============================================================
def _should_apply_webhook(supa, user_id, incoming_sub_id, is_activation):
    """Determine whether a webhook should be applied to the user row.

    Args:
        supa: Supabase client
        user_id: str, the user_id from webhook payload
        incoming_sub_id: str, the subscription_id from the webhook event
        is_activation: bool, True if this is an ACTIVATED event (Razorpay
                       subscription.activated OR PayPal
                       BILLING.SUBSCRIPTION.ACTIVATED)

    Returns:
        (should_apply: bool, reason: str)
    """
    if not user_id:
        # No user_id (shouldn't happen — caller checks this first too).
        # Fail-open: caller will fall through to existing error path.
        return True, "no_user_id_fail_open"

    if not incoming_sub_id:
        # No sub_id in event (shouldn't happen for normal webhooks).
        # Fail-open and let the existing handler decide.
        return True, "no_incoming_sub_id_fail_open"

    # Read the current row state. Single query, only the fields we need.
    try:
        res = (supa.table("users")
               .select("subscription_id, subscription_status")
               .eq("id", user_id)
               .limit(1)
               .execute())
        if not res.data or len(res.data) == 0:
            # No row for this user_id. Fail-open: lazy-creation path elsewhere
            # may resolve this. The downstream UPDATE will be a no-op anyway.
            print(f"[stale-check] no user row for user={user_id} — applying anyway")
            return True, "applied_no_user_row"
        row = res.data[0]
    except Exception as e:
        # DB read failed. Fail-open: don't block a legit webhook for an
        # infra blip. The existing UPDATE will retry on its own connection.
        print(f"[stale-check] DB read failed user={user_id}: {e} — applying anyway")
        return True, "applied_db_read_failed"

    existing_sub_id = (row.get("subscription_id") or "").strip()
    existing_status = (row.get("subscription_status") or "").strip().lower()

    # Rule 2: row has no sub_id yet.
    if not existing_sub_id:
        print(f"[stale-check] WARNING user={user_id} has no subscription_id "
              f"on row; applying webhook for sub={incoming_sub_id} anyway "
              f"(possible orphan or pre-checkout state)")
        return True, "applied_no_match_warned"

    # Rule 1: sub_id matches — happy path.
    if existing_sub_id == incoming_sub_id:
        return True, "applied"

    # Mismatch territory — incoming event references a sub that's NOT the
    # one currently on the user's row.
    if is_activation:
        # Rule 3: activation wins UNLESS row is already active on a different sub.
        if existing_status == "active":
            # Rule 4: stale activation arrived for an old sub while a newer
            # sub is already active. Don't downgrade.
            print(f"[stale-check] SKIP stale activation for user={user_id}: "
                  f"incoming sub={incoming_sub_id} but row is already active "
                  f"on sub={existing_sub_id}")
            return False, "ignored_stale_active"
        # Rule 3 applies: row is created/cancelled/paused/halted/expired/etc.
        # — let the new activation overwrite.
        print(f"[stale-check] APPLY activation for user={user_id}: "
              f"row was {existing_status!r} on sub={existing_sub_id}, "
              f"new activation for sub={incoming_sub_id} takes precedence")
        return True, "applied_activation_overrides"

    # Rule 5: non-activation event for a stale sub. This is the CME-1 race.
    print(f"[stale-check] SKIP stale webhook for user={user_id}: "
          f"incoming sub={incoming_sub_id} != row sub={existing_sub_id} "
          f"(row status={existing_status!r})")
    return False, "ignored_stale_sub"


# ============================================================
# CME-2 — Per-user checkout rate limit
# ------------------------------------------------------------
# Defensive rate limit on the checkout-creation endpoints to prevent
# abuse: each call hits the provider's API (Razorpay/PayPal), creates a
# subscription record there, and writes to our users table. Without a
# limit, a malicious or buggy client could spam these calls and burn
# through provider API quotas, create orphan subs, and churn the row.
#
# Spec (decided in session 2026-05-12):
#   - Limit: 3 attempts per 5 minutes
#   - Scope: PER USER, PER PROVIDER (Razorpay and PayPal independent)
#   - Storage: in-memory sliding window (single Render instance, fine)
#   - Response: HTTP 429 + Retry-After header + JSON with retry_after_seconds
#   - Logging: every 429 logged so we can spot abuse in Render logs
#
# Sliding window vs fixed bucket: sliding avoids the "burst at boundary"
# problem where a fixed-window allows 2x the rate at boundaries. With a
# deque of timestamps we get true rate-over-window semantics.
#
# Thread safety: gunicorn runs Flask with multiple threads by default;
# a single global lock protects the dict. Lock contention is negligible
# at our QPS (rate-limit checks are sub-millisecond).
#
# Memory: each user-provider pair holds at most 3 timestamps. Even with
# 10k active users churning subscriptions, that's <500KB. Pruning of
# stale entries happens on each check (lazy cleanup).
#
# Restart behavior: in-memory state clears on Render restart. Worst
# case is that a user who just hit the limit gets 3 free retries
# immediately after a restart. Not a meaningful security gap given how
# rare restarts are.
# ============================================================
_CHECKOUT_RATE_LIMIT_MAX = 3            # max attempts in window
_CHECKOUT_RATE_LIMIT_WINDOW_SEC = 300   # 5 minutes
_checkout_rate_state = {}               # {(user_id, provider): deque[float]}
_checkout_rate_lock = threading.Lock()


def _check_checkout_rate_limit(user_id, provider):
    """Check whether this user has exceeded the checkout rate limit for
    the given provider. Slides the window forward, prunes old entries.

    Args:
        user_id: str, the Clerk user_id
        provider: str, 'razorpay' or 'paypal' (used as the key suffix)

    Returns:
        (allowed: bool, retry_after_seconds: int)
        - allowed=True  : within limit, retry_after=0, request can proceed
        - allowed=False : limit hit, retry_after tells when oldest entry expires

    Side effect when allowed: appends a timestamp to the user's window.
    (We record the attempt at the gate; if downstream code fails the
    request for some other reason, the slot is still consumed — that's
    intentional, prevents retry-loop bypasses.)
    """
    if not user_id:
        # Fail-open if we somehow got called without a user_id. The caller
        # auth check should reject the request before this point anyway.
        return True, 0

    key = (user_id, provider)
    now = time.monotonic()
    window_start = now - _CHECKOUT_RATE_LIMIT_WINDOW_SEC

    with _checkout_rate_lock:
        history = _checkout_rate_state.get(key)
        if history is None:
            history = deque(maxlen=_CHECKOUT_RATE_LIMIT_MAX + 1)
            _checkout_rate_state[key] = history

        # Prune timestamps that fell out of the sliding window
        while history and history[0] < window_start:
            history.popleft()

        # Decide: if we already have MAX entries inside the window, deny.
        if len(history) >= _CHECKOUT_RATE_LIMIT_MAX:
            # Retry-after: how many seconds until the oldest entry expires
            oldest = history[0]
            retry_after = int(oldest + _CHECKOUT_RATE_LIMIT_WINDOW_SEC - now) + 1
            return False, max(retry_after, 1)

        # Allowed — record this attempt and proceed
        history.append(now)
        return True, 0


def _format_retry_after(seconds):
    """Convert raw seconds into a humane "try again in ..." phrase.
    Examples:
        300 → "5 minutes"
        180 → "3 minutes"
        120 → "2 minutes"
         90 → "2 minutes"    (round up so we don't under-promise)
         60 → "1 minute"
         45 → "about a minute"
         20 → "20 seconds"
          5 → "a few seconds"
    Singular/plural handled. Always returns a non-empty string.
    """
    s = max(int(seconds or 0), 1)
    if s < 10:
        return "a few seconds"
    if s < 30:
        return f"{s} seconds"
    if s < 60:
        return "about a minute"
    # 60+ seconds: round UP to the nearest minute so the message is
    # never optimistic ("1 minute" when there's actually 90s left would
    # cause a second 429 from a trusting user — bad UX).
    minutes = (s + 59) // 60
    return "1 minute" if minutes == 1 else f"{minutes} minutes"


def _rate_limited_response(provider, retry_after_seconds):
    """Build the standard 429 response for a rate-limit hit. Includes
    Retry-After header (RFC 7231) so well-behaved clients back off, plus
    a structured JSON body for our frontend to render a clean toast."""
    humane = _format_retry_after(retry_after_seconds)
    body = {
        "ok": False,
        "error": "rate_limited",
        "detail": f"Too many checkout attempts. Try again in {humane}.",
        "retry_after_seconds": retry_after_seconds,  # raw value for programmatic use
        "retry_after_humane": humane,                 # human-readable form
        "provider": provider,
    }
    resp = jsonify(body)
    resp.status_code = 429
    resp.headers["Retry-After"] = str(retry_after_seconds)
    return resp


# ============================================================
# ANTI-ABUSE — Email normalization (Layer A: catches Tier 2 abuse)
# ============================================================
# Gmail and Googlemail treat dots and +aliases as identical:
#   yourname@gmail.com == your.name@gmail.com == yourname+anything@gmail.com
# All deliver to the same inbox. Anyone abusing free tier can rotate
# these forever without "creating" new accounts. We normalize all
# Gmail-family addresses to a canonical form and dedupe against it.
# ============================================================
_GMAIL_DOMAINS = {"gmail.com", "googlemail.com"}

def _normalize_email(email):
    """Return canonical form of an email for dedup purposes.
    For Gmail/Googlemail: strip dots from local part AND strip +aliases.
    For all other domains: lowercase only (no dot/alias normalization,
    because other providers treat foo@x.com and f.oo@x.com as different).

    Examples:
      'YourName@gmail.com'         → 'yourname@gmail.com'
      'your.name@gmail.com'        → 'yourname@gmail.com'
      'yourname+abuse1@gmail.com'  → 'yourname@gmail.com'
      'y.our.name+x@googlemail.com'→ 'yourname@gmail.com'
      'foo+bar@outlook.com'        → 'foo+bar@outlook.com' (unchanged — not Gmail)

    Returns lowercased input on any error (defensive, never raises).
    """
    try:
        if not email or "@" not in email:
            return (email or "").lower().strip()
        local, _, domain = email.lower().strip().partition("@")
        if domain in _GMAIL_DOMAINS:
            # Strip everything from + onwards (alias)
            local = local.split("+", 1)[0]
            # Strip all dots
            local = local.replace(".", "")
            # Always normalize the domain to gmail.com (treat googlemail same)
            return f"{local}@gmail.com"
        return f"{local}@{domain}"
    except Exception:
        return (email or "").lower().strip()


# ============================================================
# CLERK JWT VERIFICATION (networkless via JWKS)
# ============================================================
# Clerk session tokens are RS256-signed JWTs. We verify them
# locally using Clerk's public keys (JWKS) — no API call needed
# per request. PyJWKClient caches the keys for us automatically.
#
# This proves a request came from a real signed-in Clerk user.
# Without verification, any abuser could call /api/signup-metadata
# with a fake user_id and bypass our anti-abuse layers entirely.
# ============================================================
_jwks_client = None
_jwks_init_err = ""

def _get_jwks_client():
    """Lazy-init the PyJWKClient pointing at Clerk's JWKS URL.
    JWKS URL pattern: https://<frontend-api>/.well-known/jwks.json
    We derive the frontend API from the publishable key (base64-encoded inside it).

    Returns the client or None if init fails. Never raises.
    """
    global _jwks_client, _jwks_init_err
    if _jwks_client is not None:
        return _jwks_client
    if not _AUTH_DEPS_OK:
        _jwks_init_err = "auth_deps_unavailable"
        return None
    # Decode the publishable key to get the frontend API domain.
    # Format: pk_test_<base64-of-domain-with-trailing-$>
    pub_key = (os.getenv("CLERK_PUBLISHABLE_KEY") or "").strip()
    if not pub_key:
        # Fallback — use the key we hard-coded in index.html (test environment)
        pub_key = "pk_test_Zmxvd2luZy1raXR0ZW4tNjUuY2xlcmsuYWNjb3VudHMuZGV2JA"
    try:
        # Strip the pk_test_ or pk_live_ prefix
        b64_part = pub_key.split("_", 2)[-1]
        # Add padding if needed
        b64_part += "=" * (-len(b64_part) % 4)
        decoded = base64.b64decode(b64_part).decode("utf-8", errors="replace")
        # Decoded value ends in $ — strip it
        frontend_api = decoded.rstrip("$").strip()
        if not frontend_api or "." not in frontend_api:
            _jwks_init_err = f"bad_frontend_api: {frontend_api[:60]}"
            return None
        jwks_url = f"https://{frontend_api}/.well-known/jwks.json"
        # PyJWKClient caches for 5 min by default — fine for our needs
        _jwks_client = PyJWKClient(jwks_url, cache_keys=True, lifespan=300)
        print(f"[clerk-jwt] JWKS client initialized for {frontend_api}")
        return _jwks_client
    except Exception as e:
        _jwks_init_err = f"init_failed: {str(e)[:120]}"
        print(f"[clerk-jwt] {_jwks_init_err}")
        return None


def _verify_clerk_jwt(req):
    """Extract and verify the Clerk session JWT from the request.

    Returns:
        (user_id, error_msg) — user_id is None if verification fails.

    Looks for the JWT in:
        1. Authorization: Bearer <token> header (preferred)
        2. __session cookie (Clerk's default cookie)
    """
    # 1. Find the token
    token = ""
    auth_header = req.headers.get("Authorization", "") or ""
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
    if not token:
        token = (req.cookies.get("__session") or "").strip()
    if not token:
        return None, "no_token"

    # 2. Get the JWKS client
    jwks_client = _get_jwks_client()
    if jwks_client is None:
        return None, f"jwks_unavailable: {_jwks_init_err}"

    # 3. Verify the token
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        # Clerk session tokens are signed with RS256
        # We don't validate audience because Clerk's session tokens don't always include 'aud'
        # We DO validate signature, expiration, and issuer
        decoded = _jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_aud": False,  # Clerk session tokens don't always have aud
            },
            leeway=10,  # 10 second clock skew tolerance
        )
        user_id = decoded.get("sub", "")  # Clerk puts user_id in 'sub' claim
        if not user_id:
            return None, "no_sub_claim"
        return user_id, ""
    except _jwt.ExpiredSignatureError:
        return None, "token_expired"
    except _jwt.InvalidTokenError as e:
        return None, f"invalid_token: {str(e)[:80]}"
    except Exception as e:
        return None, f"verify_error: {str(e)[:80]}"


# ============================================================
# ANTI-ABUSE — Layers B (browser fingerprint) + C (IP rate-limit)
# ============================================================
# These are checked when the frontend calls /api/signup-metadata
# right after a Clerk signup completes. They use signals not
# available in the webhook (browser fingerprint, real client IP).
#
# Layer B: same browser fingerprint already linked to N+ accounts
#   → block 3rd account from same browser (configurable via SIGNUP_FP_LIMIT)
# Layer C: IP has had K+ signups in last 24h
#   → block (configurable via SIGNUP_IP_LIMIT_24H, default 5)
# ============================================================

def _check_signup_metadata_limits(supa, ip, fingerprint, current_user_id):
    """Run Layers B + C checks. Returns (allowed, reason).

    Args:
        supa: Supabase client (already validated non-None)
        ip: client IP address
        fingerprint: browser fingerprint string
        current_user_id: the Clerk user_id that just signed up
                         (excluded from dedup count — they're the new account)

    Returns:
        (True, "")                        if allowed
        (False, "blocked_fingerprint")    if Layer B triggered
        (False, "blocked_ip")             if Layer C triggered
        (True, "warn:<reason>")           if a check errored (fail open)
    """
    # ----- Layer B: fingerprint dedup -----
    fp_limit = int((os.getenv("SIGNUP_FP_LIMIT") or "2").strip())
    if fingerprint and fp_limit > 0:
        try:
            # Count how many OTHER users share this signup_fingerprint
            res = (supa.table("users")
                   .select("id", count="exact")
                   .eq("signup_fingerprint", fingerprint)
                   .neq("id", current_user_id)
                   .execute())
            existing_count = res.count or 0
            if existing_count >= fp_limit:
                print(f"[signup-metadata] [BLOCKED-FP] fingerprint={fingerprint[:20]}... "
                      f"already on {existing_count} accounts (limit={fp_limit})")
                return False, "blocked_fingerprint"
        except Exception as e:
            print(f"[signup-metadata] fingerprint check failed (proceeding): {e}")
            # fail open — don't block legit users on DB hiccups

    # ----- Layer C: IP rate-limit (signups per IP in last 24h) -----
    ip_limit = int((os.getenv("SIGNUP_IP_LIMIT_24H") or "5").strip())
    if ip and ip_limit > 0:
        try:
            # Count successful signup attempts from this IP in the last 24h
            cutoff_iso = _iso_24h_ago()
            res = (supa.table("signup_attempts")
                   .select("id", count="exact")
                   .eq("ip", ip)
                   .eq("result", "allowed")
                   .gte("attempted_at", cutoff_iso)
                   .execute())
            recent_count = res.count or 0
            if recent_count >= ip_limit:
                print(f"[signup-metadata] [BLOCKED-IP] ip={ip} "
                      f"had {recent_count} signups in last 24h (limit={ip_limit})")
                return False, "blocked_ip"
        except Exception as e:
            print(f"[signup-metadata] IP rate-limit check failed (proceeding): {e}")
            # fail open

    return True, ""


def _iso_24h_ago():
    """Return ISO 8601 timestamp for 24 hours ago, in UTC. Used for rate-limit windows."""
    from datetime import datetime, timezone, timedelta
    return (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()


def _record_signup_attempt(supa, ip, fingerprint, email, result):
    """Log a signup attempt to the signup_attempts table.
    Used for both rate-limiting (Layer C reads from here) and forensics.
    Never raises — if logging fails, we don't want to break the user's signup."""
    try:
        supa.table("signup_attempts").insert({
            "ip": ip or "unknown",
            "email_attempted": (email or "")[:200] or None,
            "fingerprint": (fingerprint or "")[:200] or None,
            "result": result,
        }).execute()
    except Exception as e:
        print(f"[signup-metadata] failed to record attempt: {e}")


# ============================================================
# AUTHENTICATED USER QUOTA SYSTEM (Supabase-backed)
# ============================================================
# These helpers manage daily_used + bonus_credits for signed-in users.
# Anonymous users continue to use the existing Apps Script flow — these
# are NOT called for them.
#
# Quota model:
#   - daily_used: how many of today's 3 daily slots have been used
#   - bonus_credits: persistent, granted on signup (default 2), consumed
#                    AFTER daily is exhausted. Never refills.
#   - daily_reset_at: date column. When it's < today, we reset daily_used = 0
#
# Consumption order: daily first, then bonus. Always.
# ============================================================
USER_DAILY_LIMIT = 3  # mirror of frontend DAILY_CAP — free tier daily quota


# ============================================================
# TIER LIMITS — single source of truth for free + paid tiers
# ============================================================
# Free uses daily quota (3/day) + bonus credits (2 lifetime, granted on signup).
# Paid tiers use monthly quota only — bonus_credits ignored, daily_used ignored.
# Adding a tier later = update this function + nothing else.
# ============================================================
def _get_tier_limits(tier):
    """Return quota limits for a given tier.
    Returns dict: {kind: 'daily'|'monthly', daily, monthly, bonus_eligible}
    Falls back to free for unknown tier strings (defensive)."""
    t = (tier or "free").strip().lower()
    if t == "free":
        return {"kind": "daily", "daily": USER_DAILY_LIMIT, "monthly": None, "bonus_eligible": True}
    if t == "creator":
        return {"kind": "monthly", "daily": None, "monthly": 240, "bonus_eligible": False}
    if t == "pro":
        return {"kind": "monthly", "daily": None, "monthly": 400, "bonus_eligible": False}
    if t == "agency":
        return {"kind": "monthly", "daily": None, "monthly": 2000, "bonus_eligible": False}
    print(f"[tier] unknown tier '{tier}' — falling back to free")
    return {"kind": "daily", "daily": USER_DAILY_LIMIT, "monthly": None, "bonus_eligible": True}


def _today_iso():
    """Today's date in YYYY-MM-DD format (UTC). Used for daily_reset_at comparisons."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).date().isoformat()


def _now_utc():
    """Current UTC datetime — used for period-end comparisons."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


def _is_period_active(current_period_end_str):
    """Check if a paid user's current billing period is still active.

    Returns True if period_end is in the future, False if expired or unset.
    Handles ISO strings (with or without 'Z' suffix), None, and garbage gracefully.

    Used as a defense-in-depth safety net: if a paid user's period has expired
    AND the webhook hasn't fired yet (Razorpay delay, Render asleep), the backend
    treats them as free for that request rather than serving infinite paid quota.
    """
    if not current_period_end_str:
        return False
    try:
        from datetime import datetime, timezone
        s = current_period_end_str
        if isinstance(s, str):
            # Supabase timestamptz can come back with 'Z' or '+00:00' — normalize
            s = s.replace("Z", "+00:00")
            dt = datetime.fromisoformat(s)
        else:
            dt = s
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt > _now_utc()
    except Exception as e:
        print(f"[tier] _is_period_active parse failed for {current_period_end_str}: {e}")
        return False


def _quota_fallback(user_id, reason):
    """Safe-defaults response when DB read fails. Fails open (allows generation)
    but with no quota tracking. Used as a safety net by _get_user_quota."""
    return {
        "ok": False, "user_id": user_id,
        "tier": "free", "kind": "daily",
        "daily_used": 0, "daily_limit": USER_DAILY_LIMIT,
        "bonus_credits": 0, "daily_remaining": USER_DAILY_LIMIT,
        "monthly_used": 0, "monthly_limit": 0, "monthly_remaining": 0,
        "current_period_end": "",
        "total_remaining": USER_DAILY_LIMIT, "allowed": True,
        "reason": reason
    }


def _get_user_quota(supa, user_id):
    """Read current quota state for an authenticated user.

    Branches on tier:
      - free: daily counter + bonus credits (existing behavior, unchanged)
      - creator/pro/agency: monthly counter, with period-end safety net

    Returns dict (extended for paid tiers; free shape preserves all old keys):
        {
          "ok": bool,
          "user_id": str,
          "tier": str,                  # 'free' | 'creator' | 'pro' | 'agency'
          "kind": str,                  # 'daily' | 'monthly'
          # Free-tier fields (zeroed for paid):
          "daily_used": int, "daily_limit": int, "bonus_credits": int, "daily_remaining": int,
          # Paid-tier fields (zeroed for free):
          "monthly_used": int, "monthly_limit": int, "monthly_remaining": int,
          "current_period_end": str,
          # Common:
          "total_remaining": int, "allowed": bool, "reason": str
        }

    Never raises. On DB error, returns ok=False with reason set.
    """
    try:
        res = (supa.table("users")
               .select("id, tier, daily_used, bonus_credits, daily_reset_at, "
                       "monthly_used, current_period_end, subscription_status")
               .eq("id", user_id)
               .limit(1)
               .execute())
        if not res.data or len(res.data) == 0:
            # User authenticated via JWT but no Supabase row found.
            # This happens when:
            #   - Webhook silently failed during signup
            #   - User signed up before webhook was configured
            #   - Network/Render-sleep caused webhook delivery to fail
            # Lazy creation: fetch user from Clerk API, create the row now.
            print(f"[quota] no_user_row for {user_id} — attempting lazy creation")
            created = _lazy_create_user(supa, user_id)
            if created:
                # Re-query to get the fresh row
                res = (supa.table("users")
                       .select("id, tier, daily_used, bonus_credits, daily_reset_at, "
                               "monthly_used, current_period_end, subscription_status")
                       .eq("id", user_id)
                       .limit(1)
                       .execute())
                if res.data and len(res.data) > 0:
                    print(f"[quota] lazy creation succeeded for {user_id}")
                    # Fall through to normal processing below
                else:
                    # Lazy creation reported success but row not findable — odd
                    print(f"[quota] lazy creation reported OK but row not found for {user_id}")
                    return _quota_fallback(user_id, "lazy_create_inconsistent")
            else:
                # Lazy creation failed (Clerk API down, abuse block, etc.)
                # Fall back to old behavior: allow but warn.
                print(f"[quota] lazy creation failed for {user_id}, falling back to no-tracking")
                return _quota_fallback(user_id, "no_user_row_lazy_failed")
        row = res.data[0]
        tier = (row.get("tier") or "free").strip().lower()
        # Surface subscription_status so the frontend can render nuanced UI
        # (e.g. "Active until Jun 9" for cancelled-but-still-paid users).
        # Empty string when user has no subscription history.
        sub_status = (row.get("subscription_status") or "").strip().lower()
        limits = _get_tier_limits(tier)

        # ---- Period-end safety net (defense-in-depth for paid tiers) ----
        # If user is paid but their period has expired AND webhook hasn't downgraded
        # them yet, treat as free for THIS request. The next webhook will normalize
        # the DB. Prevents stale-paid users from getting infinite quota if
        # subscription.completed event was delayed or lost.
        if limits["kind"] == "monthly":
            period_end = row.get("current_period_end")
            if not _is_period_active(period_end):
                print(f"[quota] [PERIOD-EXPIRED] user={user_id} tier={tier} "
                      f"period_end={period_end} — treating as free for this request")
                # Force free for THIS calculation only — don't write to DB.
                # The webhook is the authoritative source of truth for tier state.
                tier = "free"
                limits = _get_tier_limits(tier)

        # ---- Branch on tier kind ----
        if limits["kind"] == "daily":
            # FREE TIER PATH — preserves existing behavior exactly
            daily_used = int(row.get("daily_used") or 0)
            bonus_credits = int(row.get("bonus_credits") or 0)
            reset_at = row.get("daily_reset_at") or ""

            # Lazy reset: if last reset date < today, reset daily_used to 0
            today = _today_iso()
            if reset_at < today:
                try:
                    supa.table("users").update({
                        "daily_used": 0,
                        "daily_reset_at": today,
                    }).eq("id", user_id).execute()
                    daily_used = 0
                    print(f"[quota] daily reset for user {user_id} (was {row.get('daily_reset_at')}, now {today})")
                except Exception as e:
                    print(f"[quota] daily reset failed for {user_id} (proceeding with old value): {e}")

            daily_remaining = max(0, limits["daily"] - daily_used)
            total_remaining = daily_remaining + bonus_credits
            return {
                "ok": True, "user_id": user_id,
                "tier": "free", "kind": "daily",
                "subscription_status": sub_status,
                "daily_used": daily_used, "daily_limit": limits["daily"],
                "bonus_credits": bonus_credits,
                "daily_remaining": daily_remaining,
                "monthly_used": 0, "monthly_limit": 0, "monthly_remaining": 0,
                "current_period_end": "",
                "total_remaining": total_remaining,
                "allowed": total_remaining > 0,
                "reason": "ok"
            }
        else:
            # PAID TIER PATH — monthly counter only
            monthly_used = int(row.get("monthly_used") or 0)
            monthly_limit = limits["monthly"]
            monthly_remaining = max(0, monthly_limit - monthly_used)
            period_end = row.get("current_period_end") or ""
            return {
                "ok": True, "user_id": user_id,
                "tier": tier, "kind": "monthly",
                "subscription_status": sub_status,
                # Free-tier fields zeroed for paid users
                "daily_used": 0, "daily_limit": 0,
                "bonus_credits": 0, "daily_remaining": 0,
                # Paid-tier fields populated
                "monthly_used": monthly_used,
                "monthly_limit": monthly_limit,
                "monthly_remaining": monthly_remaining,
                "current_period_end": period_end if isinstance(period_end, str) else str(period_end),
                "total_remaining": monthly_remaining,
                "allowed": monthly_remaining > 0,
                "reason": "ok"
            }
    except Exception as e:
        print(f"[quota] _get_user_quota error for {user_id}: {e}")
        return _quota_fallback(user_id, f"db_error: {str(e)[:80]}")


# ============================================================
# LAZY USER CREATION (defense-in-depth for missing webhook rows)
# ------------------------------------------------------------
# When backend receives a JWT for a user not in our DB, fetch their
# info from Clerk's REST API and create the row on-demand. This means
# even if the webhook silently fails (Render asleep, network blip,
# Clerk retry exhausted, etc.), users still get rows on first authed
# API call. Belt-and-suspenders complement to the webhook path.
# ============================================================
def _fetch_clerk_user_basic(user_id):
    """Fetch a Clerk user's basic info (email, first_name, last_name).

    Returns a dict on success: {'email': str, 'first_name': str, 'last_name': str}
    Returns None on any failure. Never raises.

    Used for:
      - lazy_create_user (to populate Supabase row)
      - PayPal subscriber pre-fill (skips manual typing on PayPal checkout)
    """
    if not user_id:
        return None
    secret = (os.getenv("CLERK_SECRET_KEY") or "").strip()
    if not secret:
        return None
    try:
        api_resp = requests.get(
            f"https://api.clerk.com/v1/users/{user_id}",
            headers={"Authorization": f"Bearer {secret}"},
            timeout=8,
        )
        if api_resp.status_code != 200:
            return None
        clerk_data = api_resp.json()
    except Exception:
        return None

    # Extract primary email (same logic as _lazy_create_user)
    email = ""
    try:
        email_list = clerk_data.get("email_addresses", []) or []
        primary_id = clerk_data.get("primary_email_address_id", "")
        for em in email_list:
            if em.get("id") == primary_id:
                email = (em.get("email_address") or "").strip().lower()
                break
        if not email and email_list:
            email = (email_list[0].get("email_address") or "").strip().lower()
    except Exception:
        pass

    first_name = (clerk_data.get("first_name") or "").strip()
    last_name = (clerk_data.get("last_name") or "").strip()
    return {
        "email": email,
        "first_name": first_name,
        "last_name": last_name,
    }


def _lazy_create_user(supa, user_id):
    """Create a Supabase users row by fetching info from Clerk's API.

    Returns True if the row exists in DB after this function (whether
    we created it or it was already there). Returns False on hard failure.

    Idempotent: if row already exists, returns True without changes.
    Runs Layer A (alias dedup) protection same as webhook does.
    """
    if not user_id:
        return False

    # Quick check: maybe row already exists (race with another lazy-create)
    try:
        existing = supa.table("users").select("id").eq("id", user_id).limit(1).execute()
        if existing.data and len(existing.data) > 0:
            return True
    except Exception:
        pass  # fall through to creation

    # Fetch user info from Clerk's REST API
    secret = (os.getenv("CLERK_SECRET_KEY") or "").strip()
    if not secret:
        print(f"[lazy-create] CLERK_SECRET_KEY not set — cannot fetch user {user_id}")
        return False

    try:
        api_resp = requests.get(
            f"https://api.clerk.com/v1/users/{user_id}",
            headers={"Authorization": f"Bearer {secret}"},
            timeout=8,
        )
    except Exception as e:
        print(f"[lazy-create] Clerk API request failed for {user_id}: {e}")
        return False

    if api_resp.status_code != 200:
        print(f"[lazy-create] Clerk API returned {api_resp.status_code} for {user_id}: {api_resp.text[:200]}")
        return False

    try:
        clerk_data = api_resp.json()
    except Exception as e:
        print(f"[lazy-create] Clerk API JSON parse failed for {user_id}: {e}")
        return False

    # Extract email same way webhook does
    email = ""
    try:
        email_list = clerk_data.get("email_addresses", []) or []
        primary_id = clerk_data.get("primary_email_address_id", "")
        for em in email_list:
            if em.get("id") == primary_id:
                email = (em.get("email_address") or "").strip().lower()
                break
        if not email and email_list:
            email = (email_list[0].get("email_address") or "").strip().lower()
    except Exception as e:
        print(f"[lazy-create] email parse error for {user_id}: {e}")

    first_name = (clerk_data.get("first_name") or "").strip()
    last_name = (clerk_data.get("last_name") or "").strip()
    name = (first_name + " " + last_name).strip() or (clerk_data.get("username") or "").strip()

    # Layer A protection: alias dedup
    normalized = _normalize_email(email) if email else ""
    if normalized:
        try:
            dup = supa.table("users").select("id").eq("normalized_email", normalized).limit(1).execute()
            if dup.data and len(dup.data) > 0 and dup.data[0]["id"] != user_id:
                # Different Clerk user already has this normalized email — block.
                # Don't create the row. User effectively gets no_user_row treatment.
                print(f"[lazy-create] [BLOCKED-ALIAS] {user_id} ({email}) "
                      f"normalized to '{normalized}' belongs to {dup.data[0]['id']}")
                return False
        except Exception as dedup_err:
            print(f"[lazy-create] dedup check failed (proceeding): {dedup_err}")

    # Insert the row
    row = {
        "id": user_id,
        "email": email or f"{user_id}@unknown.local",
        "normalized_email": normalized or None,
        "name": name or None,
        "bonus_credits": 2,
        "daily_used": 0,
    }
    try:
        supa.table("users").insert(row).execute()
        print(f"[lazy-create] [OK] created user {user_id} ({email}) norm='{normalized}'")
        return True
    except Exception as ins_err:
        err_str = str(ins_err)
        if "duplicate key" in err_str.lower() or "23505" in err_str:
            # Race condition — another request already inserted it. Treat as success.
            print(f"[lazy-create] {user_id} already exists (race) — OK")
            return True
        print(f"[lazy-create] insert failed for {user_id}: {err_str[:200]}")
        return False



def _consume_user_quota(supa, user_id):
    """Decrement quota for an authenticated user.

    Branches on tier:
      - free: daily-first then bonus (existing behavior, unchanged)
      - paid: increment monthly_used only

    Returns dict:
        {
          "ok": bool,
          "tier": str,
          "consumed_from": "daily" | "bonus" | "monthly" | "none",
          "daily_used": int, "bonus_credits": int, "monthly_used": int,
          "remaining_after": int,
          "reason": str
        }

    Never raises.
    """
    # Get current state (period-end safety net + lazy reset already applied)
    state = _get_user_quota(supa, user_id)
    if not state["ok"]:
        return {
            "ok": False, "tier": state.get("tier", "free"),
            "consumed_from": "none",
            "daily_used": state["daily_used"], "bonus_credits": state["bonus_credits"],
            "monthly_used": state.get("monthly_used", 0),
            "monthly_limit": state.get("monthly_limit", 0),
            "monthly_remaining": state.get("monthly_remaining", 0),
            "remaining_after": state["total_remaining"],
            "reason": state["reason"]
        }

    if state["total_remaining"] <= 0:
        return {
            "ok": False, "tier": state["tier"],
            "consumed_from": "none",
            "daily_used": state["daily_used"], "bonus_credits": state["bonus_credits"],
            "monthly_used": state.get("monthly_used", 0),
            "monthly_limit": state.get("monthly_limit", 0),
            "monthly_remaining": state.get("monthly_remaining", 0),
            "remaining_after": 0, "reason": "exhausted"
        }

    # Branch on tier kind
    if state["kind"] == "daily":
        # ---------- FREE TIER ---------- (preserves existing daily-first-then-bonus)
        new_daily = state["daily_used"]
        new_bonus = state["bonus_credits"]
        consumed_from = ""
        if state["daily_remaining"] > 0:
            new_daily = state["daily_used"] + 1
            consumed_from = "daily"
        elif state["bonus_credits"] > 0:
            new_bonus = state["bonus_credits"] - 1
            consumed_from = "bonus"
        else:
            # Should not reach here (total_remaining > 0 above), but defensive
            return {
                "ok": False, "tier": state["tier"],
                "consumed_from": "none",
                "daily_used": state["daily_used"], "bonus_credits": state["bonus_credits"],
                "monthly_used": 0,
                "remaining_after": 0, "reason": "exhausted_unexpected"
            }
        # Write the new state
        try:
            supa.table("users").update({
                "daily_used": new_daily,
                "bonus_credits": new_bonus,
            }).eq("id", user_id).execute()
        except Exception as e:
            print(f"[quota] _consume_user_quota (free) update failed for {user_id}: {e}")
            return {
                "ok": False, "tier": state["tier"],
                "consumed_from": "none",
                "daily_used": state["daily_used"], "bonus_credits": state["bonus_credits"],
                "monthly_used": 0,
                "monthly_limit": 0,
                "monthly_remaining": 0,
                "remaining_after": state["total_remaining"],
                "reason": f"update_failed: {str(e)[:80]}"
            }

        # Best-effort log to usage_logs (non-blocking — don't fail consumption if log fails)
        try:
            supa.table("usage_logs").insert({
                "user_id": user_id,
                "source": consumed_from,
            }).execute()
        except Exception as e:
            print(f"[quota] usage_log insert failed (non-blocking): {e}")

        new_daily_remaining = max(0, USER_DAILY_LIMIT - new_daily)
        new_total = new_daily_remaining + new_bonus
        return {
            "ok": True, "tier": "free",
            "consumed_from": consumed_from,
            "daily_used": new_daily, "bonus_credits": new_bonus,
            "monthly_used": 0,
            "monthly_limit": 0,
            "monthly_remaining": 0,
            "remaining_after": new_total, "reason": "ok"
        }
    else:
        # ---------- PAID TIER ---------- (creator/pro/agency)
        new_monthly = state["monthly_used"] + 1
        try:
            supa.table("users").update({
                "monthly_used": new_monthly,
            }).eq("id", user_id).execute()
        except Exception as e:
            print(f"[quota] _consume_user_quota (paid) update failed for {user_id}: {e}")
            return {
                "ok": False, "tier": state["tier"],
                "consumed_from": "none",
                "daily_used": 0, "bonus_credits": 0,
                "monthly_used": state["monthly_used"],
                "monthly_limit": state["monthly_limit"],
                "monthly_remaining": state["monthly_remaining"],
                "remaining_after": state["total_remaining"],
                "reason": f"update_failed: {str(e)[:80]}"
            }
        # Best-effort log
        try:
            supa.table("usage_logs").insert({
                "user_id": user_id, "source": "monthly",
            }).execute()
        except Exception as e:
            print(f"[quota] usage_log insert failed (non-blocking): {e}")

        new_monthly_remaining = max(0, state["monthly_limit"] - new_monthly)
        return {
            "ok": True, "tier": state["tier"],
            "consumed_from": "monthly",
            "daily_used": 0, "bonus_credits": 0,
            "monthly_used": new_monthly,
            "monthly_limit": state["monthly_limit"],
            "monthly_remaining": new_monthly_remaining,
            "remaining_after": new_monthly_remaining, "reason": "ok"
        }


# ============================================================
# Rate Limiting (IP-based, in-memory)
# ============================================================
# REGEN_LIMIT regenerations per IP within REGEN_WINDOW_SEC.
# Storage is in-memory: { ip: deque([timestamps...]) }
# Lost on server restart (Render free tier sleeps after ~15min idle).
# That's an acceptable tradeoff for a beta — bypass via VPN/different
# network is also possible, this is best-effort soft enforcement.
# Backend regen limit was REDUNDANT with Apps Script quota system.
# Apps Script enforces 3 generations/day already. The backend limit was hitting
# users who only tried to regenerate once because the in-memory counter
# accumulated across testing sessions. Setting to a high number effectively
# disables this layer; the Apps Script quota system (3/day) is the real gate.
REGEN_LIMIT = 999
REGEN_WINDOW_SEC = 24 * 60 * 60  # 24 hours
_regen_log = {}
_regen_lock = threading.Lock()

def _client_ip():
    """Return the real end-user IP, accounting for Cloudflare proxy."""
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

def check_regen_limit(ip):
    """Returns (allowed: bool, remaining: int, retry_after_sec: int)."""
    now = time.time()
    cutoff = now - REGEN_WINDOW_SEC
    with _regen_lock:
        dq = _regen_log.get(ip)
        if dq is None:
            dq = deque()
            _regen_log[ip] = dq
        # Drop old entries outside the window
        while dq and dq[0] < cutoff:
            dq.popleft()
        used = len(dq)
        if used >= REGEN_LIMIT:
            retry_after = int(dq[0] + REGEN_WINDOW_SEC - now) + 1
            return False, 0, retry_after
        return True, REGEN_LIMIT - used, 0

def record_regen(ip):
    """Record a successful regeneration against this IP's quota."""
    with _regen_lock:
        dq = _regen_log.setdefault(ip, deque())
        dq.append(time.time())

def _human_retry_msg(seconds):
    """Convert seconds → friendly message."""
    if seconds < 60:
        return f"Try again in {seconds} seconds."
    minutes = seconds // 60
    if minutes < 60:
        return f"Try again in {minutes} minute{'s' if minutes != 1 else ''}."
    hours = minutes // 60
    rem_minutes = minutes % 60
    if rem_minutes == 0:
        return f"Try again in {hours} hour{'s' if hours != 1 else ''}."
    return f"Try again in {hours}h {rem_minutes}m."

# ============================================================
# Disposable Email Domain List (cached, refreshed every 24h)
# ============================================================
DISPOSABLE_DOMAINS_CACHE = {"set": None, "loaded_at": 0}
_disposable_lock = threading.Lock()

def load_disposable_domains():
    """Load ~10K disposable domains from public GitHub list. Cached for 24h."""
    now = time.time()
    with _disposable_lock:
        cache = DISPOSABLE_DOMAINS_CACHE
        if cache["set"] is not None and (now - cache["loaded_at"]) < 86400:
            return cache["set"]
        try:
            url = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf"
            r = requests.get(url, timeout=8)
            if r.status_code == 200:
                domains = {line.strip().lower() for line in r.text.splitlines() if line.strip() and not line.startswith("#")}
                cache["set"] = domains
                cache["loaded_at"] = now
                print(f"[check-email] Loaded {len(domains)} disposable domains")
                return domains
        except Exception as e:
            print(f"[check-email] Disposable list load failed: {e}")
        # Fallback minimal set if network fails
        fallback = {
            "10minutemail.com", "tempmail.com", "guerrillamail.com", "mailinator.com",
            "throwawaymail.com", "trashmail.com", "yopmail.com", "tempmail.net",
            "temp-mail.org", "mail.tm", "fakeinbox.com", "sharklasers.com",
            "getnada.com", "maildrop.cc", "mintemail.com", "spamgourmet.com",
            "mytemp.email", "33mail.com", "mohmal.com", "emailondeck.com",
        }
        cache["set"] = fallback
        cache["loaded_at"] = now
        return fallback

# Patterns that strongly suggest disposable even if domain isn't on list
DISPOSABLE_PATTERNS = [
    r"temp.*mail", r"throwaway", r"trash.?mail", r"guerrilla", r"10minute",
    r"disposable", r"mailinator", r"yopmail", r"fakeinbox", r"burner.?mail",
    r"\.ml$", r"\.tk$", r"\.ga$", r"\.cf$",  # free TLDs heavily abused
]

# ============================================================

@app.after_request
def add_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "*"
    return response

@app.route("/")
def home():
    return jsonify({"status": "OnePost backend live"})

# ============================================================
# /verify-signup — verifies reCAPTCHA v3 token before allowing
# the frontend to log a signup. Frontend MUST send token from
# grecaptcha.execute() in the request body.
# ============================================================
@app.route("/verify-signup", methods=["POST", "OPTIONS"])
def verify_signup():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

    secret = os.getenv("RECAPTCHA_SECRET")
    if not secret:
        # If secret not configured, fail OPEN (don't block real users in case of misconfig)
        return jsonify({
            "success": True,
            "allowed": True,
            "score": None,
            "message": "Verification skipped (no key configured)"
        })

    # Parse JSON body
    try:
        payload = request.get_json(force=True, silent=True) or {}
    except Exception:
        payload = {}
    token = payload.get("token", "")
    email = payload.get("email", "")

    if not token:
        # No token from frontend (script blocked, ad-blocker, etc.) — fail OPEN
        # This prevents legitimate users with strict privacy settings from being locked out.
        return jsonify({
            "success": True,
            "allowed": True,
            "score": None,
            "message": "No captcha token (allowed by default)"
        })

    # Verify with Google
    try:
        r = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": secret, "response": token, "remoteip": _client_ip()},
            timeout=8
        )
        if not r.ok:
            return jsonify({"success": True, "allowed": True, "score": None,
                            "message": "Verifier unreachable (allowed)"})
        data = r.json()
        success = bool(data.get("success"))
        score = data.get("score", 0.0)
        action = data.get("action", "")
        # reCAPTCHA v3 returns 0.0 (very likely bot) → 1.0 (very likely human)
        # Threshold 0.5 is Google's default recommendation
        threshold = 0.5
        if not success:
            return jsonify({
                "success": True,
                "allowed": False,
                "score": score,
                "message": "Verification failed. Please refresh and try again."
            })
        if score < threshold:
            return jsonify({
                "success": True,
                "allowed": False,
                "score": score,
                "message": "Suspicious activity detected. Please try again or contact support."
            })
        return jsonify({
            "success": True,
            "allowed": True,
            "score": score,
            "action": action,
            "message": "OK"
        })
    except Exception as e:
        # Network error or Google outage — fail OPEN
        return jsonify({
            "success": True,
            "allowed": True,
            "score": None,
            "message": f"Verifier error: {str(e)[:100]}"
        })


# ============================================================
# /check-email — validates that an email address actually exists
# Layers:
#   1. Format validation (regex)
#   2. Disposable domain blocklist (~10K domains, cached 24h)
#   3. Disposable pattern matching (catches new disposable domains)
#   4. Abstract API SMTP/MX deliverability check (real existence)
# All checks fail OPEN on infrastructure errors — never block real
# users due to OUR problems (API timeout, network failure, etc.)
# ============================================================
@app.route("/check-email", methods=["POST", "OPTIONS"])
def check_email():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

    try:
        data = request.get_json(force=True, silent=True) or {}
        email = (data.get("email") or "").strip().lower()

        # 1. Format check
        if not email or "@" not in email:
            return jsonify({"valid": False, "reason": "Please enter a valid email address."})
        if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
            return jsonify({"valid": False, "reason": "Please enter a valid email address."})

        domain = email.split("@", 1)[1]

        # 2. Disposable domain list check
        disposable = load_disposable_domains()
        if domain in disposable:
            return jsonify({"valid": False, "reason": "Please use a real email — disposable addresses aren't allowed."})

        # 3. Pattern check (catches new disposable domains not yet on the list)
        for pattern in DISPOSABLE_PATTERNS:
            if re.search(pattern, email, re.IGNORECASE):
                return jsonify({"valid": False, "reason": "Please use a real email — disposable addresses aren't allowed."})

        # 4. SMTP / deliverability check via Abstract API
        api_key = (os.getenv("ABSTRACT_API_KEY") or "").strip()
        if not api_key:
            # No API key = skip deep check, but log it
            print("[check-email] No ABSTRACT_API_KEY set — skipping deliverability check")
            return jsonify({"valid": True, "reason": "OK (deliverability check skipped)"})

        try:
            api_url = f"https://emailvalidation.abstractapi.com/v1/?api_key={api_key}&email={email}"
            r = requests.get(api_url, timeout=8)
            if r.status_code != 200:
                # API failure = fail OPEN (don't block real users due to our problem)
                print(f"[check-email] Abstract API returned {r.status_code} — failing open")
                return jsonify({"valid": True, "reason": "OK (verifier unavailable)"})

            result = r.json()
            deliverability = (result.get("deliverability") or "").upper()
            is_smtp_valid = (result.get("is_smtp_valid") or {}).get("value", True)
            is_mx_found = (result.get("is_mx_found") or {}).get("value", True)
            is_disposable = (result.get("is_disposable_email") or {}).get("value", False)

            # Log score for analytics
            print(f"[check-email] {email} → deliverability={deliverability}, smtp={is_smtp_valid}, mx={is_mx_found}, disposable={is_disposable}")

            if is_disposable:
                return jsonify({"valid": False, "reason": "Please use a real email — disposable addresses aren't allowed."})
            if not is_mx_found:
                return jsonify({"valid": False, "reason": "This email domain doesn't accept mail. Please check the spelling."})
            if not is_smtp_valid:
                return jsonify({"valid": False, "reason": "This email address doesn't seem to exist. Please check the spelling."})
            if deliverability == "UNDELIVERABLE":
                return jsonify({"valid": False, "reason": "This email address doesn't seem to exist. Please check the spelling."})

            # DELIVERABLE, RISKY, or UNKNOWN → allow
            return jsonify({"valid": True, "reason": "OK", "deliverability": deliverability})

        except requests.Timeout:
            print(f"[check-email] Abstract API timeout for {email} — failing open")
            return jsonify({"valid": True, "reason": "OK (verifier timeout)"})
        except Exception as api_err:
            print(f"[check-email] Abstract API error: {api_err} — failing open")
            return jsonify({"valid": True, "reason": "OK (verifier error)"})

    except Exception as e:
        print(f"[check-email] Unexpected error: {e}")
        # Fail open on unexpected errors — don't block signups due to our bugs
        return jsonify({"valid": True, "reason": "OK (check error)"})


@app.route("/generate", methods=["POST", "OPTIONS"])
def generate():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

    groq_key = os.getenv("GROQ_API_KEY")
    deepgram_key = os.getenv("DEEPGRAM_KEY")

    content_type_input = request.form.get("content_type", "personal story")
    tone = request.form.get("tone", "casual and fun")
    language = request.form.get("language", "english")
    user_context = request.form.get("user_context", "")
    frames_json = request.form.get("frames_json", "")
    file_type = request.form.get("file_type", "text")

    if language == "hindi":
        lang_instruction = "Generate ALL content in Hindi only (Devanagari script). Use natural, native Hindi expressions — NOT translated English. Include Hindi-friendly hashtags."
    elif language == "spanish":
        lang_instruction = "Generate ALL content in Spanish only. Use natural, native Spanish expressions and idioms. Include Spanish-language hashtags."
    elif language == "french":
        lang_instruction = "Generate ALL content in French only. Use natural, native French expressions. Include French-language hashtags."
    elif language == "portuguese":
        lang_instruction = "Generate ALL content in Portuguese only (Brazilian style). Use natural, native Portuguese expressions. Include Portuguese hashtags."
    elif language == "german":
        lang_instruction = "Generate ALL content in German only. Use natural, native German expressions. Include German-language hashtags."
    elif language == "japanese":
        lang_instruction = "Generate ALL content in Japanese only. Use natural Japanese with appropriate mix of kanji, hiragana, katakana. Include Japanese-friendly hashtags."
    elif language == "arabic":
        lang_instruction = "Generate ALL content in Arabic only (Modern Standard Arabic). Use natural, native Arabic expressions. Include Arabic hashtags."
    elif language == "russian":
        lang_instruction = "Generate ALL content in Russian only (Cyrillic script). Use natural, native Russian expressions. Include Russian-language hashtags."
    elif language == "both":
        # Legacy compatibility — old "both" requests now treated as English
        lang_instruction = "Generate ALL content in English only."
    else:
        lang_instruction = "Generate ALL content in English only."

    visual_description = ""
    transcript = ""
    context = ""

    # CASE 1: Frames sent from browser (video)
    if frames_json:
        try:
            frames = json.loads(frames_json)
            if frames:
                visual_description = analyze_frames_groq(frames, content_type_input, tone, groq_key)
        except Exception as e:
            visual_description = ""

    # CASE 2: Image file sent directly
    elif "file" in request.files:
        f = request.files["file"]
        file_bytes = f.read()
        mime = f.mimetype or "image/jpeg"
        if mime.startswith("image"):
            b64 = base64.b64encode(file_bytes).decode()
            visual_description = analyze_frames_groq([b64], content_type_input, tone, groq_key, mime)
        elif mime.startswith(("video", "audio")):
            # Try Deepgram transcription
            try:
                dg_resp = requests.post(
                    "https://api.deepgram.com/v1/listen",
                    params={"model": "nova-2", "smart_format": "true", "punctuate": "true"},
                    headers={"Authorization": f"Token {deepgram_key}", "Content-Type": mime},
                    data=file_bytes,
                    timeout=60
                )
                if dg_resp.ok:
                    dg_data = dg_resp.json()
                    transcript = dg_data["results"]["channels"][0]["alternatives"][0]["transcript"]
            except Exception:
                transcript = ""

    # CASE 3: Plain text
    elif request.form.get("text"):
        context = request.form.get("text", "")

    # Build final context
    parts = []
    if visual_description:
        parts.append(f"VISUAL: {visual_description}")
    if transcript and len(transcript) > 5:
        parts.append(f"AUDIO TRANSCRIPT: {transcript}")
    if user_context:
        parts.append(f"ADDITIONAL CONTEXT FROM USER: {user_context}")
    if context:
        parts.append(f"TEXT: {context}")
    if not parts:
        parts.append(f"A {content_type_input} content with {tone} tone")

    final_context = "\n".join(parts)

    # Generate content with Groq
    prompt = f"""You are OnePost AI. Generate highly engaging, platform-optimized social media content.

Content Analysis:
{final_context}

Content Type: {content_type_input}
Tone: {tone}
Language: {lang_instruction}

Generate content for each platform. Return ONLY valid JSON with these exact keys:
{{
  "instagram": "engaging caption with emojis and 5-8 relevant hashtags",
  "reels_script": "HOOK: (attention-grabbing opener) MAIN: (3 key points) CTA: (strong call to action)",
  "youtube_video": "Title: (compelling title)\\nDescription: (detailed 150-word description)\\nTags: (10 relevant tags)",
  "youtube_shorts": "HOOK: (first 3 seconds script) MAIN: (key message) CTA: (subscribe/follow)",
  "facebook": "friendly conversational post telling the full story with emojis",
  "snapchat": "fun punchy snap caption under 80 chars with emojis 🔥",
  "tiktok": "punchy TikTok caption under 150 chars with a strong hook in the first 5 words, native creator voice, 4-6 trending hashtags including #fyp #foryou",
  "whatsapp": "engaging WhatsApp status under 150 chars with emojis",
  "linkedin": "professional insightful post with value for network, no hashtag spam",
  "twitter": "compelling Twitter/X thread: 1/ hook 2/ insight 3/ takeaway 4/ CTA",
  "pinterest": "SEO-rich Pinterest pin description with keywords and call to action"
}}"""

    try:
        groq_resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {groq_key}", "Content-Type": "application/json"},
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 2000,
                "temperature": 0.7
            },
            timeout=60
        )
        if not groq_resp.ok:
            return jsonify({"error": "AI generation failed", "details": groq_resp.text}), 502

        content_text = groq_resp.json()["choices"][0]["message"]["content"]
        json_match = re.search(r'\{.*\}', content_text, re.DOTALL)
        if not json_match:
            return jsonify({"error": "Could not parse AI response"}), 500

        result = json.loads(json_match.group())
        return jsonify({
            "success": True,
            "content": result,
            "analysis": visual_description or transcript or context
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# /regen-status — frontend can fetch remaining count anytime
# ============================================================
@app.route("/regen-status", methods=["GET", "OPTIONS"])
def regen_status():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200
    ip = _client_ip()
    allowed, remaining, retry_after = check_regen_limit(ip)
    return jsonify({
        "success": True,
        "allowed": allowed,
        "remaining": remaining,
        "limit": REGEN_LIMIT,
        "window_hours": REGEN_WINDOW_SEC // 3600,
        "retry_after_seconds": retry_after,
        "retry_after_human": _human_retry_msg(retry_after) if retry_after else ""
    })


# ============================================================
# /check-quota and /record-generation — persistent generation
# limits keyed by email + browser fingerprint + IP. Persisted in
# Google Sheets via Apps Script so the limit survives Render
# restarts, browser switches, and incognito.
# Required env var: QUOTA_URL = your Apps Script web app URL
# ============================================================
def _call_quota_script(action, email, fingerprint, ip, timeout=10):
    """Forward a quota action to the Google Apps Script."""
    quota_url = (os.getenv("QUOTA_URL") or "").strip()
    if not quota_url:
        # No quota URL configured — fail open (don't block users on misconfig)
        return {"ok": True, "allowed": True, "used": 0, "remaining": 3,
                "limit": 3, "retry_after_seconds": 0,
                "_note": "QUOTA_URL not configured"}
    try:
        r = requests.post(
            quota_url,
            json={
                "action": action,
                "email": email or "",
                "fingerprint": fingerprint or "",
                "ip": ip or ""
            },
            timeout=timeout,
            allow_redirects=True
        )
        if not r.ok:
            print(f"[quota] Apps Script returned {r.status_code}")
            return {"ok": True, "allowed": True, "_note": f"script_{r.status_code}"}
        try:
            return r.json()
        except Exception:
            # Apps Script sometimes returns HTML on errors
            print(f"[quota] Non-JSON response: {r.text[:200]}")
            return {"ok": True, "allowed": True, "_note": "non_json"}
    except requests.Timeout:
        print(f"[quota] Apps Script timeout for action={action}")
        return {"ok": True, "allowed": True, "_note": "timeout"}
    except Exception as e:
        print(f"[quota] Apps Script error: {e}")
        return {"ok": True, "allowed": True, "_note": "error"}


@app.route("/check-quota", methods=["POST", "OPTIONS"])
def check_quota():
    """Check if user has remaining generations.

    BRANCH:
      - Authenticated (valid Clerk JWT in Authorization header):
          → reads from Supabase (daily_used + bonus_credits)
      - Anonymous (no/invalid JWT):
          → existing flow via Apps Script keyed by email/fingerprint/IP
    """
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200
    try:
        data = request.get_json(force=True, silent=True) or {}
        email = (data.get("email") or "").strip().lower()
        fingerprint = (data.get("fingerprint") or "").strip()
        ip = _client_ip()

        # Branch on auth: try JWT verification (silent on failure → anonymous flow)
        user_id = None
        if _AUTH_DEPS_OK:
            user_id, _jwt_err = _verify_clerk_jwt(request)

        if user_id:
            # AUTHENTICATED PATH — use Supabase
            supa = _get_supabase()
            if supa is None:
                # Supabase down — fall back to anonymous flow rather than block user
                print(f"[check-quota] supabase unavailable for user {user_id} — falling back to anon flow")
            else:
                state = _get_user_quota(supa, user_id)
                return jsonify({
                    "success": True,
                    "auth": "user",   # tells frontend this came from authenticated path
                    "allowed": bool(state["allowed"]),
                    "used": state["daily_used"],
                    "remaining": state["total_remaining"],     # daily + bonus
                    "limit": state["daily_limit"],
                    "daily_used": state["daily_used"],
                    "daily_remaining": state["daily_remaining"],
                    "bonus_credits": state["bonus_credits"],
                    # Paid-tier fields (zero for free users — frontend uses 'kind' to branch)
                    "tier": state["tier"],
                    "kind": state["kind"],
                    "subscription_status": state.get("subscription_status", ""),
                    "monthly_used": state["monthly_used"],
                    "monthly_limit": state["monthly_limit"],
                    "monthly_remaining": state["monthly_remaining"],
                    "current_period_end": state["current_period_end"],
                    "retry_after_seconds": 0,
                    "retry_after_human": "",
                    "note": state["reason"],
                })

        # ANONYMOUS PATH — existing Apps Script flow (UNCHANGED)
        result = _call_quota_script("check_quota", email, fingerprint, ip, timeout=10)
        retry_after = int(result.get("retry_after_seconds") or 0)
        upstream_error = result.get("error", "") if not result.get("ok", True) else ""
        return jsonify({
            "success": True,
            "auth": "anon",
            "allowed": bool(result.get("allowed", True)),
            "used": int(result.get("used", 0)),
            "remaining": int(result.get("remaining", 3)),
            "limit": int(result.get("limit", 3)),
            "retry_after_seconds": retry_after,
            "retry_after_human": _human_retry_msg(retry_after) if retry_after else "",
            "note": result.get("_note", "") or upstream_error
        })
    except Exception as e:
        print(f"[check-quota] Unexpected error: {e}")
        # Fail open on unexpected errors
        return jsonify({"success": True, "auth": "anon", "allowed": True, "used": 0,
                        "remaining": 3, "limit": 3, "retry_after_seconds": 0,
                        "retry_after_human": "", "note": f"backend_error: {str(e)[:80]}"})


@app.route("/record-generation", methods=["POST", "OPTIONS"])
def record_generation():
    """Record a successful generation against this user's quota.
    Called by frontend AFTER /generate succeeds.

    BRANCH:
      - Authenticated: decrement Supabase (daily first, then bonus)
      - Anonymous: existing Apps Script flow
    """
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200
    try:
        data = request.get_json(force=True, silent=True) or {}
        email = (data.get("email") or "").strip().lower()
        fingerprint = (data.get("fingerprint") or "").strip()
        ip = _client_ip()

        # Branch on auth: try JWT first, fall back to anonymous
        user_id = None
        if _AUTH_DEPS_OK:
            user_id, _jwt_err = _verify_clerk_jwt(request)

        if user_id:
            # AUTHENTICATED PATH — consume from Supabase
            supa = _get_supabase()
            if supa is None:
                # Supabase down — fall back to anonymous flow rather than block user
                print(f"[record-generation] supabase unavailable for user {user_id} — falling back to anon flow")
            else:
                result = _consume_user_quota(supa, user_id)
                return jsonify({
                    "success": True,
                    "auth": "user",
                    "recorded": bool(result.get("ok", False)),
                    "consumed_from": result.get("consumed_from", "none"),
                    "daily_used": result.get("daily_used", 0),
                    "bonus_credits": result.get("bonus_credits", 0),
                    "remaining": result.get("remaining_after", 0),
                    # Paid-tier fields (zero for free users — frontend uses 'kind' to branch)
                    "tier": result.get("tier", "free"),
                    "kind": "monthly" if result.get("tier", "free") in ("creator", "pro", "agency") else "daily",
                    "monthly_used": result.get("monthly_used", 0),
                    "monthly_limit": result.get("monthly_limit", 0),
                    "monthly_remaining": result.get("monthly_remaining", 0),
                    "note": result.get("reason", ""),
                })

        # ANONYMOUS PATH — existing Apps Script flow (UNCHANGED)
        result = _call_quota_script("record_generation", email, fingerprint, ip, timeout=10)
        upstream_error = result.get("error", "") if not result.get("ok", True) else ""
        return jsonify({
            "success": True,
            "auth": "anon",
            "recorded": bool(result.get("recorded", False)),
            "row": result.get("row", 0),
            "note": result.get("_note", "") or upstream_error
        })
    except Exception as e:
        print(f"[record-generation] Unexpected error: {e}")
        return jsonify({"success": True, "auth": "anon", "recorded": False,
                        "note": f"backend_error: {str(e)[:80]}"})


# ============================================================
# /regenerate — single platform caption regeneration
# Rate limited: REGEN_LIMIT regenerations per IP per REGEN_WINDOW_SEC
# ============================================================
@app.route("/regenerate", methods=["POST", "OPTIONS"])
def regenerate():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

    # ---- Rate limit check (IP-based, total across all platforms) ----
    ip = _client_ip()
    allowed, remaining, retry_after = check_regen_limit(ip)
    if not allowed:
        return jsonify({
            "success": False,
            "error": "regen_limit_reached",
            "message": f"You've used all {REGEN_LIMIT} regenerations for today. {_human_retry_msg(retry_after)}",
            "limit": REGEN_LIMIT,
            "remaining": 0,
            "retry_after_seconds": retry_after,
            "retry_after_human": _human_retry_msg(retry_after)
        }), 429

    groq_key = os.getenv("GROQ_API_KEY")

    platform = request.form.get("platform", "")
    platform_name = request.form.get("platform_name", platform)
    previous_caption = request.form.get("previous_caption", "")
    attempt = request.form.get("attempt", "1")
    variation_hint = request.form.get("variation_hint", "different angle and hook")
    content_type_input = request.form.get("content_type", "personal story")
    tone = request.form.get("tone", "casual and fun")
    language = request.form.get("language", "english")
    user_context = request.form.get("user_context", "")

    if not platform or not previous_caption:
        return jsonify({"success": False, "error": "Missing platform or previous_caption"}), 400

    if language == "hindi":
        lang_instruction = "Generate the caption in Hindi only (Devanagari script). Use natural, native Hindi expressions — NOT translated English."
    elif language == "spanish":
        lang_instruction = "Generate the caption in Spanish only. Use natural, native Spanish expressions and idioms."
    elif language == "french":
        lang_instruction = "Generate the caption in French only. Use natural, native French expressions."
    elif language == "portuguese":
        lang_instruction = "Generate the caption in Portuguese only (Brazilian style). Use natural, native Portuguese expressions."
    elif language == "german":
        lang_instruction = "Generate the caption in German only. Use natural, native German expressions."
    elif language == "japanese":
        lang_instruction = "Generate the caption in Japanese only. Use natural Japanese with appropriate kanji/hiragana/katakana."
    elif language == "arabic":
        lang_instruction = "Generate the caption in Arabic only (Modern Standard Arabic). Use natural, native Arabic."
    elif language == "russian":
        lang_instruction = "Generate the caption in Russian only (Cyrillic script). Use natural, native Russian expressions."
    elif language == "both":
        lang_instruction = "Generate the caption in English only."
    else:
        lang_instruction = "Generate the caption in English only."

    # Platform-specific format guidelines (matching your /generate endpoint exactly)
    platform_formats = {
        "instagram": "an engaging Instagram caption with emojis and 5-8 relevant hashtags",
        "reels_script": "a Reels script with HOOK: (attention-grabbing opener) MAIN: (3 key points) CTA: (strong call to action)",
        "youtube_video": "YouTube content with Title:, Description: (150 words), and Tags: (10 relevant tags)",
        "youtube_shorts": "a YouTube Shorts script with HOOK: (first 3 seconds) MAIN: (key message) CTA: (subscribe/follow)",
        "facebook": "a friendly conversational Facebook post telling the full story with emojis",
        "snapchat": "a fun punchy Snapchat caption under 80 characters with emojis 🔥",
        "tiktok": "a punchy TikTok caption under 150 characters with a strong hook in the first 5 words, native creator voice, and 4-6 trending hashtags including #fyp and #foryou",
        "whatsapp": "an engaging WhatsApp status under 150 characters with emojis",
        "linkedin": "a professional insightful LinkedIn post with value for the network, no hashtag spam",
        "twitter": "a compelling Twitter/X thread formatted as: 1/ hook 2/ insight 3/ takeaway 4/ CTA",
        "pinterest": "an SEO-rich Pinterest pin description with keywords and call to action"
    }
    format_guideline = platform_formats.get(platform, f"engaging content for {platform_name}")

    ctx_part = f"\nADDITIONAL CONTEXT FROM USER: {user_context}\n" if user_context else ""

    prompt = f"""You are OnePost AI. Generate a FRESH, COMPLETELY NEW caption for {platform_name} ONLY.

The user already saw this caption and wants a noticeably DIFFERENT variation:
---
{previous_caption}
---

CRITICAL RULES:
1. Generate a COMPLETELY NEW caption with a {variation_hint}.
2. Do NOT repeat phrases, hooks, opening lines, or structure from the previous caption.
3. The new caption must feel meaningfully different — different angle, different emotional beat, different word choices.
4. Format: {format_guideline}
5. Content type: {content_type_input}
6. Tone: {tone}
7. Language: {lang_instruction}
8. This is regeneration attempt #{attempt} — the user wants noticeably fresh creative output.{ctx_part}

Return ONLY the new caption text. No JSON, no preamble, no explanation, no quotation marks around the caption."""

    try:
        # Higher temperature for genuine variation; bump per attempt
        temp = min(0.9 + (int(attempt) - 1) * 0.1, 1.2)

        groq_resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {groq_key}", "Content-Type": "application/json"},
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 800,
                "temperature": temp,
                "top_p": 0.95
            },
            timeout=45
        )

        if not groq_resp.ok:
            return jsonify({
                "success": False,
                "error": "AI regeneration failed",
                "details": groq_resp.text
            }), 502

        new_caption = groq_resp.json()["choices"][0]["message"]["content"].strip()

        # Strip accidental wrapping quotes
        if len(new_caption) >= 2:
            if (new_caption.startswith('"') and new_caption.endswith('"')) or \
               (new_caption.startswith("'") and new_caption.endswith("'")):
                new_caption = new_caption[1:-1].strip()

        # Strip any "Caption:" or similar lead-ins the model might add
        new_caption = re.sub(r'^(caption|new caption|here\'?s? (the |a )?(new |fresh )?caption)\s*[:\-]\s*',
                             '', new_caption, flags=re.IGNORECASE).strip()

        if not new_caption or len(new_caption) < 5:
            return jsonify({
                "success": False,
                "error": "Empty regeneration response"
            }), 500

        # ---- Record successful regeneration against the IP's quota ----
        record_regen(ip)
        _, remaining_after, _ = check_regen_limit(ip)

        return jsonify({
            "success": True,
            "caption": new_caption,
            "platform": platform,
            "attempt": int(attempt) if attempt.isdigit() else 1,
            "remaining": remaining_after,
            "limit": REGEN_LIMIT
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Regeneration error: {str(e)}"
        }), 500


def analyze_frames_groq(frames, content_type, tone, groq_key, mime="image/jpeg"):
    """Send frames to Groq vision model for analysis"""
    try:
        messages_content = [{
            "type": "text",
            "text": f"Analyze these images/frames in detail for social media content generation. Content type: '{content_type}', tone: '{tone}'. Describe everything you see: subjects, setting, actions, mood, colors, text visible, products, location, emotions. Be very specific and detailed."
        }]
        for frame_b64 in frames[:4]:  # max 4 frames
            messages_content.append({
                "type": "image_url",
                "image_url": {"url": f"data:{mime};base64,{frame_b64}"}
            })

        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {groq_key}", "Content-Type": "application/json"},
            json={
                "model": "meta-llama/llama-4-scout-17b-16e-instruct",
                "messages": [{"role": "user", "content": messages_content}],
                "max_tokens": 600
            },
            timeout=30
        )
        if resp.ok:
            return resp.json()["choices"][0]["message"]["content"]
        return ""
    except Exception:
        return ""


# ============================================================
# /api/clerk-webhook — receives user lifecycle events from Clerk
# Subscribes to: user.created, user.updated, user.deleted
# On user.created: inserts a row in Supabase users table with bonus_credits=2
# On user.updated: keeps email/name in sync
# On user.deleted: removes the user row (cascades to usage_logs)
#
# SECURITY: Verifies the Svix webhook signature using CLERK_WEBHOOK_SECRET.
# Without verification, anyone could POST fake user_created events to us.
# ============================================================
@app.route("/api/clerk-webhook", methods=["POST", "OPTIONS"])
def clerk_webhook():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

    # Step 1 — fail fast if the optional auth deps didn't import
    if not _AUTH_DEPS_OK:
        print(f"[clerk-webhook] auth deps unavailable: {_AUTH_DEPS_ERR}")
        return jsonify({"ok": False, "error": _AUTH_DEPS_ERR}), 503

    # Step 2 — verify the webhook signature using Svix
    webhook_secret = (os.getenv("CLERK_WEBHOOK_SECRET") or "").strip()
    if not webhook_secret:
        print("[clerk-webhook] CLERK_WEBHOOK_SECRET not configured")
        return jsonify({"ok": False, "error": "webhook_secret_missing"}), 503

    # Svix expects the raw body bytes for signature verification
    raw_body = request.get_data()
    headers = {
        "svix-id": request.headers.get("svix-id", ""),
        "svix-timestamp": request.headers.get("svix-timestamp", ""),
        "svix-signature": request.headers.get("svix-signature", ""),
    }
    if not all(headers.values()):
        print(f"[clerk-webhook] missing svix headers: {headers}")
        return jsonify({"ok": False, "error": "missing_svix_headers"}), 400

    try:
        wh = SvixWebhook(webhook_secret)
        # verify() raises on bad signature; returns the parsed JSON payload on success
        payload = wh.verify(raw_body, headers)
    except Exception as e:
        print(f"[clerk-webhook] signature verification failed: {e}")
        return jsonify({"ok": False, "error": "bad_signature"}), 401

    # Step 3 — extract event type and user data
    event_type = payload.get("type", "")
    data = payload.get("data", {}) or {}
    clerk_user_id = data.get("id", "")

    print(f"[clerk-webhook] received event_type={event_type} user_id={clerk_user_id}")

    if not clerk_user_id:
        return jsonify({"ok": False, "error": "missing_user_id"}), 400

    # Step 4 — get Supabase client
    supa = _get_supabase()
    if supa is None:
        # We accept the webhook (return 200) so Clerk doesn't endlessly retry,
        # but log loud so we know something's wrong.
        print("[clerk-webhook] Supabase unavailable — accepting webhook without writing")
        return jsonify({"ok": True, "warn": "supabase_unavailable"}), 200

    # Step 5 — extract email and name from the payload
    # Clerk payload shape: data.email_addresses is a list of {id, email_address, ...}
    # data.primary_email_address_id points to the primary one
    email = ""
    try:
        email_list = data.get("email_addresses", []) or []
        primary_id = data.get("primary_email_address_id", "")
        for em in email_list:
            if em.get("id") == primary_id:
                email = (em.get("email_address") or "").strip().lower()
                break
        # Fallback — first email if primary not found
        if not email and email_list:
            email = (email_list[0].get("email_address") or "").strip().lower()
    except Exception as e:
        print(f"[clerk-webhook] email parse error: {e}")

    first_name = (data.get("first_name") or "").strip()
    last_name = (data.get("last_name") or "").strip()
    name = (first_name + " " + last_name).strip() or (data.get("username") or "").strip()

    # Step 6 — handle the event (idempotent operations)
    try:
        if event_type == "user.created":
            # ---- ANTI-ABUSE Layer A: Gmail normalization + dedup ----
            # Normalize email to its canonical form (strip Gmail dots/aliases).
            # Then check if any existing user has the same normalized_email.
            # If yes → this is a Tier 2 abuse attempt (alias trick). Block it.
            normalized = _normalize_email(email) if email else ""
            if normalized:
                try:
                    existing = supa.table("users").select("id").eq("normalized_email", normalized).limit(1).execute()
                    if existing.data and len(existing.data) > 0 and existing.data[0]["id"] != clerk_user_id:
                        # Duplicate normalized email belongs to a DIFFERENT Clerk user.
                        # The fresh signup is an abuse attempt. We:
                        #   1. Don't insert a row in our DB
                        #   2. Return 200 so Clerk doesn't retry
                        #   3. Log it loud so we can see it in Render logs
                        # The orphaned Clerk account (without our row) won't get bonus credits
                        # or any quota perks. Future cleanup task: delete it via Clerk API.
                        existing_id = existing.data[0]["id"]
                        print(f"[clerk-webhook] [BLOCKED-ALIAS] new user {clerk_user_id} ({email}) "
                              f"normalized to '{normalized}' which already belongs to {existing_id}")
                        return jsonify({
                            "ok": True,
                            "blocked": True,
                            "reason": "duplicate_normalized_email",
                            "user_id": clerk_user_id
                        }), 200
                except Exception as dedup_err:
                    # Dedup check failed for some non-blocking reason — log but proceed
                    # with insert (fail open: don't block legit users due to DB hiccups).
                    print(f"[clerk-webhook] dedup check failed (proceeding anyway): {dedup_err}")

            # Idempotent insert: if row already exists, this raises a duplicate key error
            # which we catch and treat as success (Clerk sometimes resends events)
            row = {
                "id": clerk_user_id,
                "email": email or f"{clerk_user_id}@unknown.local",  # email is required (UNIQUE NOT NULL)
                "normalized_email": normalized or None,
                "name": name or None,
                "bonus_credits": 2,
                "daily_used": 0,
            }
            try:
                supa.table("users").insert(row).execute()
                print(f"[clerk-webhook] inserted user {clerk_user_id} ({email}) norm='{normalized}'")
            except Exception as ins_err:
                err_str = str(ins_err)
                # Detect duplicate-key (idempotent retry) vs real error
                if "duplicate key" in err_str.lower() or "23505" in err_str:
                    print(f"[clerk-webhook] user {clerk_user_id} already exists — idempotent OK")
                else:
                    raise

        elif event_type == "user.updated":
            # Update email and name only. Don't touch bonus_credits or daily_used.
            update_fields = {}
            if email:
                update_fields["email"] = email
                # Keep normalized_email in sync when email changes
                update_fields["normalized_email"] = _normalize_email(email)
            if name:
                update_fields["name"] = name
            if update_fields:
                supa.table("users").update(update_fields).eq("id", clerk_user_id).execute()
                print(f"[clerk-webhook] updated user {clerk_user_id}")

        elif event_type == "user.deleted":
            # Delete cascades to usage_logs via FK ON DELETE CASCADE
            supa.table("users").delete().eq("id", clerk_user_id).execute()
            print(f"[clerk-webhook] deleted user {clerk_user_id}")

        else:
            # Unknown event type — accept (200) so Clerk doesn't retry, but log
            print(f"[clerk-webhook] ignoring unknown event_type={event_type}")

        return jsonify({"ok": True, "event": event_type, "user_id": clerk_user_id}), 200

    except Exception as e:
        print(f"[clerk-webhook] supabase operation failed: {e}")
        # Return 500 so Clerk retries (transient errors should self-heal)
        return jsonify({"ok": False, "error": f"db_error: {str(e)[:160]}"}), 500


# ============================================================
# /api/signup-metadata — receives browser-side context (fingerprint, IP)
# right after Clerk completes signup. Runs Layers B + C anti-abuse checks
# and stores the metadata on the user's row.
#
# Frontend MUST call this endpoint with:
#   Authorization: Bearer <Clerk session JWT>
#   Body: {"fingerprint": "<browser fingerprint>"}
#
# Returns:
#   200 {"ok": true, "stored": true}  — all good, metadata stored
#   200 {"ok": true, "stored": false, "reason": "..."} — fail-open (logged)
#   403 {"ok": false, "reason": "blocked_fingerprint" | "blocked_ip"} — abuse block
#   401 {"ok": false, "reason": "unauthorized"} — JWT invalid
# ============================================================
@app.route("/api/signup-metadata", methods=["POST", "OPTIONS"])
def signup_metadata():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

    if not _AUTH_DEPS_OK:
        return jsonify({"ok": False, "reason": "auth_deps_unavailable", "detail": _AUTH_DEPS_ERR}), 503

    # 1. Verify the Clerk JWT
    user_id, jwt_err = _verify_clerk_jwt(request)
    if not user_id:
        print(f"[signup-metadata] JWT verification failed: {jwt_err}")
        return jsonify({"ok": False, "reason": "unauthorized", "detail": jwt_err}), 401

    # 2. Parse the request body for fingerprint
    try:
        body = request.get_json(force=True, silent=True) or {}
    except Exception:
        body = {}
    fingerprint = (body.get("fingerprint") or "").strip()[:200]
    ip = _client_ip()

    # 3. Get Supabase
    supa = _get_supabase()
    if supa is None:
        # Without DB, we can't enforce limits — fail open but warn
        print(f"[signup-metadata] Supabase unavailable for user {user_id}")
        return jsonify({"ok": True, "stored": False, "reason": "supabase_unavailable"}), 200

    # 3.5 — IDEMPOTENCY CHECK: if user already has metadata recorded, this is a
    # returning sign-IN, not a fresh sign-UP. Skip abuse checks entirely.
    # This is the bugfix from Day 3 Step 6 — without this, every sign-in by a
    # returning user counts against the IP rate-limit, locking out real users.
    try:
        existing = (supa.table("users")
                    .select("signup_fingerprint, signup_ip, email")
                    .eq("id", user_id)
                    .limit(1)
                    .execute())
        if existing.data and len(existing.data) > 0:
            existing_fp = (existing.data[0].get("signup_fingerprint") or "").strip()
            existing_ip = (existing.data[0].get("signup_ip") or "").strip()
            existing_email = (existing.data[0].get("email") or "").strip()
            if existing_fp or existing_ip:
                # User has been through metadata sync before — they're a returning sign-in.
                # Don't run abuse checks (they'd unfairly block returning users).
                # Don't record to signup_attempts (it's not a signup attempt).
                print(f"[signup-metadata] [RETURNING] user={user_id} email={existing_email} "
                      f"already has metadata, skipping abuse checks")
                return jsonify({
                    "ok": True,
                    "stored": False,  # nothing new written
                    "returning": True,
                    "reason": "already_synced",
                    "user_id": user_id
                }), 200
        else:
            # NO row exists for this Clerk user — orphan from a missed webhook.
            # Don't run Layer C (it would unfairly count this real existing user
            # against the IP rate-limit). Instead: lazy-create their row using
            # Clerk's API, then treat them as a returning user.
            # This handles users who signed up before the webhook was reliable,
            # OR where Clerk's webhook delivery silently failed.
            print(f"[signup-metadata] no row for {user_id} — attempting lazy creation before abuse checks")
            created = _lazy_create_user(supa, user_id)
            if created:
                # Now write the fingerprint+IP we just received. They're effectively a fresh
                # signup metadata sync at this point — but with no abuse-check penalty since
                # we already recovered them as an orphan.
                try:
                    supa.table("users").update({
                        "signup_fingerprint": fingerprint or None,
                        "signup_ip": ip or None,
                    }).eq("id", user_id).execute()
                    print(f"[signup-metadata] [ORPHAN-RECOVERED] {user_id} lazy-created + metadata stored")
                except Exception as upd_err:
                    print(f"[signup-metadata] orphan metadata update failed: {upd_err}")
                return jsonify({
                    "ok": True,
                    "stored": True,
                    "orphan_recovered": True,
                    "reason": "lazy_created",
                    "user_id": user_id
                }), 200
            else:
                # Lazy creation failed (Clerk API down or alias-block).
                # Don't sign them out — fail open and let them continue as anonymous-equivalent.
                # The /check-quota endpoint will also try lazy creation, so they get another chance.
                print(f"[signup-metadata] lazy creation failed for orphan {user_id} — failing open")
                return jsonify({
                    "ok": True,
                    "stored": False,
                    "reason": "lazy_create_failed_failing_open",
                    "user_id": user_id
                }), 200
    except Exception as e:
        # Idempotency check failed — proceed with abuse checks (safe fallback)
        print(f"[signup-metadata] idempotency check failed (proceeding): {e}")

    # 4. Run anti-abuse checks (Layers B + C) — only reached for FRESH signups
    allowed, reason = _check_signup_metadata_limits(supa, ip, fingerprint, user_id)

    # 5. Get the user's email (for logging the attempt)
    user_email = ""
    try:
        ures = supa.table("users").select("email").eq("id", user_id).limit(1).execute()
        if ures.data and len(ures.data) > 0:
            user_email = ures.data[0].get("email", "") or ""
    except Exception:
        pass

    # 6. Log the attempt (only for fresh signups now)
    _record_signup_attempt(supa, ip, fingerprint, user_email, "allowed" if allowed else reason)

    if not allowed:
        # Blocked. The Clerk user exists but we won't write fingerprint/IP to their row.
        # Frontend will receive 403 and sign them out.
        print(f"[signup-metadata] [BLOCKED] user={user_id} email={user_email} "
              f"ip={ip} fp={fingerprint[:20]}... reason={reason}")
        return jsonify({
            "ok": False,
            "reason": reason,
            "user_id": user_id
        }), 403

    # 7. Allowed — update the user row with fingerprint + IP
    try:
        supa.table("users").update({
            "signup_fingerprint": fingerprint or None,
            "signup_ip": ip or None,
        }).eq("id", user_id).execute()
        print(f"[signup-metadata] [OK] user={user_id} email={user_email} "
              f"ip={ip} fp={fingerprint[:20]}...")
        return jsonify({"ok": True, "stored": True, "user_id": user_id}), 200
    except Exception as e:
        # Update failed — don't block the user, but log loud
        print(f"[signup-metadata] update failed for {user_id}: {e}")
        return jsonify({"ok": True, "stored": False, "reason": "update_failed",
                        "detail": str(e)[:120]}), 200


# ============================================================
# /api/checkout/razorpay/create-subscription
# ------------------------------------------------------------
# Creates a Razorpay subscription for an authenticated user.
# Frontend calls this when user clicks a paid-tier CTA. We:
#   1. Verify the Clerk JWT (proves user is signed in)
#   2. Read tier + cycle from the request body
#   3. Look up the matching plan_id from Render env vars
#   4. Call Razorpay's API to create a subscription
#   5. Stash the subscription_id + plan_id on the user's row
#      (status='created' — webhook will flip to 'active' when paid)
#   6. Return Razorpay's hosted checkout URL (short_url)
#
# Frontend then redirects user to short_url. User pays. Razorpay
# webhook (Task 6) tells us "paid", we update tier to active.
#
# Request body:
#   { "tier": "creator"|"pro"|"agency", "cycle": "monthly"|"yearly" }
#
# Response (success):
#   200 { "ok": true, "short_url": "...", "subscription_id": "...",
#         "plan_id": "...", "tier": "...", "cycle": "..." }
#
# Response (error):
#   401 unauthorized                 — no JWT or invalid
#   400 bad_request                  — invalid tier/cycle
#   503 razorpay_unavailable         — SDK not installed or keys missing
#   503 plan_not_configured          — env var for that plan_id missing
#   500 razorpay_api_error           — Razorpay API returned an error
#   500 db_error                     — couldn't store subscription_id on user row
# ============================================================
@app.route("/api/checkout/razorpay/create-subscription", methods=["POST", "OPTIONS"])
def razorpay_create_subscription():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

    # 1. Verify auth (Clerk JWT required — only signed-in users can subscribe)
    if not _AUTH_DEPS_OK:
        return jsonify({"ok": False, "error": "auth_deps_unavailable", "detail": _AUTH_DEPS_ERR}), 503
    user_id, jwt_err = _verify_clerk_jwt(request)
    if not user_id:
        print(f"[rzp-checkout] JWT verification failed: {jwt_err}")
        return jsonify({"ok": False, "error": "unauthorized", "detail": jwt_err}), 401

    # 1b. Rate limit (CME-2): 3 attempts per 5 minutes per user per provider.
    # Protects against abuse of the create-subscription path which hits
    # Razorpay's API, creates a subscription, and writes to our DB on
    # every call. Returns 429 with Retry-After if exceeded.
    allowed, retry_after = _check_checkout_rate_limit(user_id, "razorpay")
    if not allowed:
        print(f"[rzp-checkout] RATE LIMITED user={user_id} "
              f"retry_after={retry_after}s")
        return _rate_limited_response("razorpay", retry_after)

    # 2. Parse request body
    try:
        body = request.get_json(force=True, silent=True) or {}
    except Exception:
        body = {}
    tier = (body.get("tier") or "").strip().lower()
    cycle = (body.get("cycle") or "").strip().lower()
    # force_resubscribe: set by frontend when user explicitly chose to
    # resume/switch from My Account. Bypasses conflict guard and runs a
    # defensive cancel on the prior sub. Default False — random Subscribe
    # clicks from pricing cards never bypass the guard.
    force_resubscribe = bool(body.get("force_resubscribe"))
    if tier not in {"creator", "pro", "agency"}:
        return jsonify({"ok": False, "error": "bad_request",
                        "detail": f"invalid tier: {tier!r}"}), 400
    if cycle not in {"monthly", "yearly"}:
        return jsonify({"ok": False, "error": "bad_request",
                        "detail": f"invalid cycle: {cycle!r}"}), 400

    # 3. Look up plan_id from env
    plan_id = _get_razorpay_plan_id(tier, cycle)
    if not plan_id:
        return jsonify({"ok": False, "error": "plan_not_configured",
                        "detail": f"no env var for tier={tier} cycle={cycle}"}), 503

    # 4. Get Razorpay client
    rzp = _get_razorpay()
    if rzp is None:
        return jsonify({"ok": False, "error": "razorpay_unavailable",
                        "detail": _RAZORPAY_DEPS_ERR or "client_init_failed"}), 503

    # 5. Get Supabase (we need it to record the subscription_id on the user)
    supa = _get_supabase()
    if supa is None:
        return jsonify({"ok": False, "error": "supabase_unavailable"}), 503

    # 5b. Conflict check OR explicit-resubscribe path.
    if force_resubscribe:
        # User explicitly chose to resume/switch from My Account. Trust them:
        # skip the conflict guard, but defensively cancel the OLD provider
        # subscription first to guarantee no stray rebill on the abandoned sub.
        print(f"[rzp-checkout] force_resubscribe=True for user={user_id} — "
              f"running defensive cancel before creating new sub")
        _defensive_cancel_existing(supa, user_id)
    else:
        # Normal path: enforce conflict guard.
        conflict = _check_subscription_conflict(supa, user_id, "razorpay", tier, cycle)
        if conflict:
            print(f"[rzp-checkout] conflict for user={user_id}: {conflict['reason']}")
            return jsonify({
                "ok": False,
                "error": "subscription_conflict",
                "detail": conflict["reason"],
                "existing_provider": conflict["existing_provider"],
                "existing_tier": conflict["existing_tier"],
                "existing_subscription_status": conflict.get("existing_subscription_status", ""),
                "current_period_end": conflict["current_period_end"],
            }), 409  # 409 Conflict — semantically correct status code

    # 6. Create the subscription via Razorpay API
    # total_count = number of billing cycles before Razorpay auto-stops the subscription.
    # We use 120 (10 years) for monthly and 10 (10 years) for yearly — effectively indefinite.
    # User can cancel any time via "My Account" → portal link. Industry-standard SaaS behavior
    # (Spotify, Notion, Figma all use similar long-running subscriptions). Razorpay's hard max
    # is around 240, so this leaves headroom. If we ever need to extend further, we can update
    # active subscriptions via the Razorpay API.
    total_count = 120 if cycle == "monthly" else 10

    # customer_notify=1 → Razorpay sends payment-related emails to user
    # quantity=1 → one unit of the plan (we don't multi-seat)
    # Note: Razorpay's subscription.create() does NOT accept a callback_url.
    # The post-payment redirect is handled on the frontend by appending
    # ?callback_url=... to the short_url before redirecting (see Task 7 frontend).
    try:
        sub = rzp.subscription.create({
            "plan_id": plan_id,
            "total_count": total_count,
            "quantity": 1,
            "customer_notify": 1,
            "notes": {
                "user_id": user_id,
                "tier": tier,
                "cycle": cycle,
            },
        })
    except Exception as e:
        err_str = str(e)[:300]
        print(f"[rzp-checkout] Razorpay API error for user={user_id} tier={tier}: {err_str}")
        return jsonify({"ok": False, "error": "razorpay_api_error",
                        "detail": err_str}), 500

    subscription_id = sub.get("id", "")
    short_url = sub.get("short_url", "")
    if not subscription_id or not short_url:
        print(f"[rzp-checkout] Razorpay returned incomplete response: {sub}")
        return jsonify({"ok": False, "error": "razorpay_bad_response",
                        "detail": "missing id or short_url"}), 500

    # 7. Stash subscription_id + plan_id on the user row.
    # Status is 'created' — the webhook flips this to 'active' when payment succeeds.
    # We DO NOT change tier yet — webhook is the authoritative tier-flip.
    # If user abandons checkout, this row stays with subscription_status='created',
    # which is fine — they're still tier='free' and unaffected.
    try:
        supa.table("users").update({
            "subscription_id": subscription_id,
            "plan_id": plan_id,
            "subscription_status": "created",
            "payment_provider": "razorpay",
        }).eq("id", user_id).execute()
        print(f"[rzp-checkout] [OK] user={user_id} tier={tier} cycle={cycle} "
              f"sub={subscription_id} plan={plan_id}")
    except Exception as e:
        # Razorpay subscription is already created at this point — we shouldn't fail the request
        # because the user can still pay. We log loud and proceed.
        print(f"[rzp-checkout] DB update failed (proceeding anyway): {e}")

    # 8. Return the hosted checkout URL — frontend redirects user there
    return jsonify({
        "ok": True,
        "short_url": short_url,
        "subscription_id": subscription_id,
        "plan_id": plan_id,
        "tier": tier,
        "cycle": cycle,
    }), 200



# ============================================================
# /api/checkout/paypal/create-subscription
# ------------------------------------------------------------
# Creates a PayPal subscription for an authenticated user.
# Frontend calls this when user clicks a paid-tier CTA (USD pricing path).
# Mirrors the Razorpay checkout endpoint, but uses PayPal's API:
#
#   1. Verify the Clerk JWT (proves user is signed in)
#   2. Read tier + cycle from the request body
#   3. Look up the matching plan_id from PayPal env vars
#   4. Get OAuth token from PayPal (cached)
#   5. POST /v1/billing/subscriptions to PayPal API
#   6. Stash subscription_id + plan_id + provider='paypal' on user row
#      (status='created' — webhook will flip to 'active' when paid)
#   7. Return the PayPal approval URL for frontend redirect
#
# Frontend redirects user to the approve link. User pays. PayPal webhook
# (Task 11) tells us "paid", we update tier to active.
#
# Request body:
#   { "tier": "creator"|"pro"|"agency", "cycle": "monthly"|"yearly" }
#
# Response (success):
#   200 { "ok": true, "approve_url": "...", "subscription_id": "...",
#         "plan_id": "...", "tier": "...", "cycle": "..." }
# Response (error):
#   401 unauthorized          — no JWT or invalid
#   400 bad_request           — invalid tier/cycle
#   503 paypal_unavailable    — token fetch failed (creds missing or PayPal down)
#   503 plan_not_configured   — env var for that plan_id missing
#   500 paypal_api_error      — PayPal API returned an error
#   500 db_error              — couldn't store subscription_id on user row
# ============================================================
@app.route("/api/checkout/paypal/create-subscription", methods=["POST", "OPTIONS"])
def paypal_create_subscription():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

    # 1. Verify auth (Clerk JWT required)
    if not _AUTH_DEPS_OK:
        return jsonify({"ok": False, "error": "auth_deps_unavailable", "detail": _AUTH_DEPS_ERR}), 503
    user_id, jwt_err = _verify_clerk_jwt(request)
    if not user_id:
        print(f"[pp-checkout] JWT verification failed: {jwt_err}")
        return jsonify({"ok": False, "error": "unauthorized", "detail": jwt_err}), 401

    # 1b. Rate limit (CME-2): 3 attempts per 5 minutes per user per provider.
    # Independent counter from Razorpay's limit so a user CAN switch
    # providers without hitting a shared cap, but each provider is still
    # protected from spam.
    allowed, retry_after = _check_checkout_rate_limit(user_id, "paypal")
    if not allowed:
        print(f"[pp-checkout] RATE LIMITED user={user_id} "
              f"retry_after={retry_after}s")
        return _rate_limited_response("paypal", retry_after)

    # 2. Parse body
    try:
        body = request.get_json(force=True, silent=True) or {}
    except Exception:
        body = {}
    tier = (body.get("tier") or "").strip().lower()
    cycle = (body.get("cycle") or "").strip().lower()
    # force_resubscribe: set by frontend when user explicitly chose to
    # resume/switch from My Account. Bypasses conflict guard and runs a
    # defensive cancel on the prior sub. See Razorpay endpoint for full notes.
    force_resubscribe = bool(body.get("force_resubscribe"))
    if tier not in {"creator", "pro", "agency"}:
        return jsonify({"ok": False, "error": "bad_request",
                        "detail": f"invalid tier: {tier!r}"}), 400
    if cycle not in {"monthly", "yearly"}:
        return jsonify({"ok": False, "error": "bad_request",
                        "detail": f"invalid cycle: {cycle!r}"}), 400

    # 3. Look up plan_id
    plan_id = _get_paypal_plan_id(tier, cycle)
    if not plan_id:
        return jsonify({"ok": False, "error": "plan_not_configured",
                        "detail": f"no env var for tier={tier} cycle={cycle}"}), 503

    # 4. Get OAuth token
    token = _get_paypal_access_token()
    if not token:
        return jsonify({"ok": False, "error": "paypal_unavailable",
                        "detail": "oauth_token_fetch_failed"}), 503

    # 5. Get Supabase
    supa = _get_supabase()
    if supa is None:
        return jsonify({"ok": False, "error": "supabase_unavailable"}), 503

    # 5b. Conflict check OR explicit-resubscribe path.
    if force_resubscribe:
        print(f"[pp-checkout] force_resubscribe=True for user={user_id} — "
              f"running defensive cancel before creating new sub")
        _defensive_cancel_existing(supa, user_id)
    else:
        conflict = _check_subscription_conflict(supa, user_id, "paypal", tier, cycle)
        if conflict:
            print(f"[pp-checkout] conflict for user={user_id}: {conflict['reason']}")
            return jsonify({
                "ok": False,
                "error": "subscription_conflict",
                "detail": conflict["reason"],
                "existing_provider": conflict["existing_provider"],
                "existing_tier": conflict["existing_tier"],
                "existing_subscription_status": conflict.get("existing_subscription_status", ""),
                "current_period_end": conflict["current_period_end"],
            }), 409  # 409 Conflict — semantically correct status code

    # 6. Build return URLs (where PayPal sends user after approve/cancel)
    # Frontend reads ?subscribed=1&tier=X to show welcome, ?cancelled=1 for cancel page.
    # Origin = onepost.co.in (or wherever frontend is hosted). We accept this from
    # request headers so it works in any environment.
    origin = request.headers.get("Origin", "").strip() or "https://onepost.co.in"
    return_url = f"{origin}/?subscribed=1&tier={tier}&provider=paypal"
    cancel_url = f"{origin}/?cancelled=1"

    # 6b. Pre-fill subscriber info from Clerk (better UX — user doesn't retype email
    # on PayPal's checkout page). Fetched best-effort: if Clerk API call fails, we
    # proceed without subscriber block, PayPal collects info on their page.
    subscriber_block = None
    try:
        user_info = _fetch_clerk_user_basic(user_id)
        if user_info and user_info.get("email"):
            sub_dict = {"email_address": user_info["email"]}
            # PayPal accepts name as {given_name, surname}. Both required if name is present.
            fn = user_info.get("first_name", "")
            ln = user_info.get("last_name", "")
            if fn:
                sub_dict["name"] = {
                    "given_name": fn[:140],   # PayPal field length limit
                    "surname": (ln or "User")[:140],  # PayPal requires surname; use 'User' if empty
                }
            subscriber_block = sub_dict
    except Exception as e:
        # Pre-fill is best-effort; never block checkout on this
        print(f"[pp-checkout] subscriber pre-fill skipped: {e}")

    # 7. Create the subscription via PayPal API
    # PayPal /v1/billing/subscriptions accepts:
    #   plan_id, subscriber, application_context (return/cancel URLs), custom_id
    # custom_id is a free-form string we use to stash user_id so the webhook
    # can correlate the subscription back to our user.
    sub_request_body = {
        "plan_id": plan_id,
        "custom_id": user_id,  # critical: webhook reads this to find user
        "application_context": {
            "brand_name": "OnePost",
            "locale": "en-US",
            "shipping_preference": "NO_SHIPPING",
            "user_action": "SUBSCRIBE_NOW",
            "payment_method": {
                "payer_selected": "PAYPAL",
                "payee_preferred": "IMMEDIATE_PAYMENT_REQUIRED",
            },
            "return_url": return_url,
            "cancel_url": cancel_url,
        },
    }
    if subscriber_block:
        sub_request_body["subscriber"] = subscriber_block

    try:
        import requests as _requests
        import json as _json
        resp = _requests.post(
            f"{_PAYPAL_API_BASE}/v1/billing/subscriptions",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Prefer": "return=representation",
            },
            data=_json.dumps(sub_request_body),
            timeout=30,
        )
    except Exception as e:
        err_str = str(e)[:300]
        print(f"[pp-checkout] PayPal API exception for user={user_id} tier={tier}: {err_str}")
        return jsonify({"ok": False, "error": "paypal_api_error", "detail": err_str}), 500

    if resp.status_code not in (200, 201):
        err_text = resp.text[:300] if resp.text else f"HTTP {resp.status_code}"
        print(f"[pp-checkout] PayPal API error {resp.status_code} for user={user_id}: {err_text}")
        return jsonify({"ok": False, "error": "paypal_api_error",
                        "status": resp.status_code,
                        "detail": err_text}), 500

    try:
        sub = resp.json()
    except Exception as e:
        print(f"[pp-checkout] PayPal response JSON parse failed: {e}")
        return jsonify({"ok": False, "error": "paypal_bad_response",
                        "detail": "json_parse_failed"}), 500

    subscription_id = sub.get("id", "")
    # Find approve link in PayPal's HATEOAS-style links array
    approve_url = ""
    for link in (sub.get("links") or []):
        if (link.get("rel") or "").lower() == "approve":
            approve_url = link.get("href", "")
            break
    if not subscription_id or not approve_url:
        print(f"[pp-checkout] PayPal returned incomplete: id={subscription_id!r} approve={approve_url!r}")
        return jsonify({"ok": False, "error": "paypal_bad_response",
                        "detail": "missing id or approve link"}), 500

    # 8. Stash on user row (mirrors Razorpay behavior).
    # status='created' — webhook flips to 'active' when payment succeeds.
    try:
        supa.table("users").update({
            "subscription_id": subscription_id,
            "plan_id": plan_id,
            "subscription_status": "created",
            "payment_provider": "paypal",
        }).eq("id", user_id).execute()
        print(f"[pp-checkout] [OK] user={user_id} tier={tier} cycle={cycle} "
              f"sub={subscription_id} plan={plan_id}")
    except Exception as e:
        print(f"[pp-checkout] DB update failed (proceeding anyway): {e}")

    # 9. Return the approve URL — frontend redirects user there
    return jsonify({
        "ok": True,
        "approve_url": approve_url,
        "subscription_id": subscription_id,
        "plan_id": plan_id,
        "tier": tier,
        "cycle": cycle,
    }), 200


# ============================================================
# /api/me/subscription  (GET)  — My Account: read subscription state
# ------------------------------------------------------------
# Returns a complete picture of the user's subscription for the
# "My Account" modal. Authenticated only.
#
# Free users get a clean { tier: "free", subscription_status: null, ... }
# response (200, not 404) — frontend renders "You're on the Free plan".
#
# For paid users, returns provider/id/plan/period info plus a derived
# `cycle` (monthly|yearly) reverse-looked-up from plan_id, and a
# `is_period_active` boolean computed via _is_period_active() so the
# frontend can render "Active until ..." vs "Expired" without re-parsing
# timestamps in JS.
# ============================================================
@app.route("/api/me/subscription", methods=["GET", "OPTIONS"])
def me_subscription():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

    # 1. Auth (Clerk JWT required)
    if not _AUTH_DEPS_OK:
        return jsonify({"ok": False, "error": "auth_deps_unavailable",
                        "detail": _AUTH_DEPS_ERR}), 503
    user_id, jwt_err = _verify_clerk_jwt(request)
    if not user_id:
        return jsonify({"ok": False, "error": "unauthorized",
                        "detail": jwt_err}), 401

    # 2. Read user row
    supa = _get_supabase()
    if supa is None:
        return jsonify({"ok": False, "error": "supabase_unavailable"}), 503

    try:
        res = (supa.table("users")
               .select("email, tier, subscription_status, subscription_id, "
                       "plan_id, payment_provider, current_period_start, "
                       "current_period_end, monthly_used")
               .eq("id", user_id)
               .limit(1)
               .execute())
        if not res.data or len(res.data) == 0:
            # No row yet — treat as free user (lazy-create happens on quota fetch).
            return jsonify({
                "ok": True,
                "tier": "free",
                "subscription_status": None,
                "subscription_id": None,
                "plan_id": None,
                "payment_provider": None,
                "cycle": None,
                "current_period_start": None,
                "current_period_end": None,
                "is_period_active": False,
                "monthly_used": 0,
                "monthly_limit": 0,
                "email": None,
            }), 200
        row = res.data[0]
    except Exception as e:
        print(f"[me-sub] DB read failed for user={user_id}: {e}")
        return jsonify({"ok": False, "error": "db_read_failed",
                        "detail": str(e)[:120]}), 503

    tier = (row.get("tier") or "free").strip().lower()
    provider = (row.get("payment_provider") or "").strip().lower() or None
    plan_id = (row.get("plan_id") or "").strip() or None
    status = (row.get("subscription_status") or "").strip().lower() or None
    period_end = row.get("current_period_end") or None

    # Derive cycle from plan_id (reverse-lookup against env vars)
    cycle = None
    if plan_id and provider == "razorpay":
        _t, _c = _tier_from_plan_id(plan_id)
        cycle = _c or None
    elif plan_id and provider == "paypal":
        _t, _c = _paypal_tier_from_plan_id(plan_id)
        cycle = _c or None

    # Derive monthly_limit from tier (same source of truth as quota path)
    tier_limits = _get_tier_limits(tier)
    monthly_limit = int(tier_limits.get("monthly") or 0)

    return jsonify({
        "ok": True,
        "tier": tier,
        "subscription_status": status,
        "subscription_id": (row.get("subscription_id") or "").strip() or None,
        "plan_id": plan_id,
        "payment_provider": provider,
        "cycle": cycle,
        "current_period_start": row.get("current_period_start") or None,
        "current_period_end": period_end,
        "is_period_active": _is_period_active(period_end),
        "monthly_used": int(row.get("monthly_used") or 0),
        "monthly_limit": monthly_limit,
        "email": (row.get("email") or "").strip() or None,
    }), 200


# ============================================================
# /api/me/cancel-subscription  (POST)  — My Account: self-service cancel
# ------------------------------------------------------------
# This is the fix for Bug 1 (UPI Autopay cancellation doesn't propagate).
# Calls the payment provider's cancel API directly, which triggers their
# webhook to fire to us, which updates our DB via the existing handlers.
#
# BEHAVIOR (B-simple cancel-at-period-end):
#   - Razorpay: rzp.subscription.cancel(sub_id, {cancel_at_cycle_end: 0})
#     → cancels immediately at Razorpay → subscription.cancelled webhook
#     → DB row gets status='cancelled', tier preserved until period_end
#   - PayPal: POST /v1/billing/subscriptions/{id}/cancel
#     → cancels at PayPal → BILLING.SUBSCRIPTION.CANCELLED webhook
#     → DB row gets status='cancelled', tier preserved until period_end
#
# Defense-in-depth: we also write status='cancelled' to the DB right
# after a successful provider-side cancel, so the user sees instant UI
# feedback even before the webhook arrives. The webhook is idempotent
# (uses event_id PRIMARY KEY in webhook_events table), so this double-
# write is safe — when the webhook fires it'll either find the row
# already correct (no-op effectively) or correct any drift.
#
# IDEMPOTENCY:
#   - If user is already 'cancelled' / 'halted' / 'expired': return 200
#     with a friendly message rather than calling the provider again
#     (calling cancel on an already-cancelled sub at Razorpay returns
#     error; PayPal returns 422). Frontend can just refresh.
#   - If user is 'free' with no subscription_id: return 404.
#
# AUTH: Clerk JWT required (user can only cancel their own sub).
# ============================================================
@app.route("/api/me/cancel-subscription", methods=["POST", "OPTIONS"])
def me_cancel_subscription():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

    # 1. Auth
    if not _AUTH_DEPS_OK:
        return jsonify({"ok": False, "error": "auth_deps_unavailable",
                        "detail": _AUTH_DEPS_ERR}), 503
    user_id, jwt_err = _verify_clerk_jwt(request)
    if not user_id:
        return jsonify({"ok": False, "error": "unauthorized",
                        "detail": jwt_err}), 401

    # 2. Read user's subscription state
    supa = _get_supabase()
    if supa is None:
        return jsonify({"ok": False, "error": "supabase_unavailable"}), 503

    try:
        res = (supa.table("users")
               .select("tier, subscription_status, subscription_id, "
                       "payment_provider, current_period_end")
               .eq("id", user_id)
               .limit(1)
               .execute())
        row = res.data[0] if res.data and len(res.data) > 0 else None
    except Exception as e:
        print(f"[me-cancel] DB read failed for user={user_id}: {e}")
        return jsonify({"ok": False, "error": "db_read_failed",
                        "detail": str(e)[:120]}), 503

    if not row:
        return jsonify({"ok": False, "error": "no_subscription",
                        "detail": "No active subscription found."}), 404

    status = (row.get("subscription_status") or "").strip().lower()
    provider = (row.get("payment_provider") or "").strip().lower()
    sub_id = (row.get("subscription_id") or "").strip()
    period_end = row.get("current_period_end") or None

    # 3. Idempotency: nothing to cancel
    if not sub_id or not provider:
        return jsonify({"ok": False, "error": "no_subscription",
                        "detail": "No active subscription found."}), 404

    # Already cancelled/halted/expired — friendly no-op.
    # We treat these as "already done" to keep retries safe.
    if status in {"cancelled", "halted", "expired"}:
        print(f"[me-cancel] user={user_id} sub={sub_id} already in terminal "
              f"status={status} — no-op")
        return jsonify({
            "ok": True,
            "already_cancelled": True,
            "provider": provider,
            "subscription_id": sub_id,
            "current_period_end": period_end,
            "subscription_status": status,
            "message": "Your subscription is already cancelled.",
        }), 200

    # 4. Call the provider's cancel API
    if provider == "razorpay":
        rzp = _get_razorpay()
        if rzp is None:
            return jsonify({"ok": False, "error": "razorpay_unavailable",
                            "detail": _RAZORPAY_DEPS_ERR or "client_init_failed"}), 503
        try:
            # cancel_at_cycle_end=0 means "cancel now at Razorpay side"
            # (no more renewal attempts). User's tier is preserved on OUR side
            # via _is_period_active() safety net until current_period_end.
            rzp.subscription.cancel(sub_id, {"cancel_at_cycle_end": 0})
            print(f"[me-cancel] razorpay cancel OK: user={user_id} sub={sub_id}")
        except Exception as e:
            err_str = str(e)[:200]
            print(f"[me-cancel] razorpay cancel FAILED: user={user_id} "
                  f"sub={sub_id} err={err_str}")
            # If Razorpay says the subscription is already in a terminal state
            # (cancelled/completed/halted), accept that — our DB is just out of
            # date. The webhook should arrive shortly to sync us.
            err_lower = err_str.lower()
            if ("already" in err_lower) or ("status" in err_lower and
                                            ("cancelled" in err_lower or
                                             "completed" in err_lower or
                                             "halted" in err_lower)):
                print(f"[me-cancel] razorpay reports already-terminal — "
                      f"proceeding with DB defense-in-depth update")
                # Fall through to DB update below
            else:
                return jsonify({"ok": False, "error": "razorpay_cancel_failed",
                                "detail": err_str}), 502

    elif provider == "paypal":
        access_token = _get_paypal_access_token()
        if not access_token:
            return jsonify({"ok": False, "error": "paypal_unavailable",
                            "detail": "could not obtain OAuth token"}), 503
        try:
            import requests as _requests
            resp = _requests.post(
                f"{_PAYPAL_API_BASE}/v1/billing/subscriptions/{sub_id}/cancel",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json={"reason": "User requested cancellation via OnePost "
                                "account page"},
                timeout=20,
            )
            # PayPal returns 204 No Content on success.
            if resp.status_code == 204:
                print(f"[me-cancel] paypal cancel OK: user={user_id} "
                      f"sub={sub_id}")
            elif resp.status_code == 422:
                # 422 Unprocessable Entity — sub is already in a terminal
                # state (cancelled / expired). Accept it.
                print(f"[me-cancel] paypal sub already terminal "
                      f"(HTTP 422): user={user_id} sub={sub_id}")
                # Fall through to DB update
            else:
                err_body = resp.text[:300] if resp.text else ""
                print(f"[me-cancel] paypal cancel FAILED: user={user_id} "
                      f"sub={sub_id} HTTP={resp.status_code} body={err_body}")
                return jsonify({"ok": False, "error": "paypal_cancel_failed",
                                "detail": f"HTTP {resp.status_code}: "
                                          f"{err_body[:120]}"}), 502
        except Exception as e:
            print(f"[me-cancel] paypal cancel exception: user={user_id} "
                  f"sub={sub_id} err={e}")
            return jsonify({"ok": False, "error": "paypal_cancel_failed",
                            "detail": str(e)[:120]}), 502

    else:
        return jsonify({"ok": False, "error": "unknown_provider",
                        "detail": f"unsupported payment_provider: "
                                  f"{provider!r}"}), 400

    # 5. Defense-in-depth: write status='cancelled' to DB immediately.
    # The webhook will (idempotently) write the same value when it arrives.
    # Tier is preserved per B-simple pattern — _is_period_active() handles
    # the eventual downgrade when period_end passes.
    try:
        supa.table("users").update({
            "subscription_status": "cancelled",
        }).eq("id", user_id).execute()
        print(f"[me-cancel] DB defense-in-depth update applied: user={user_id}")
    except Exception as e:
        # Provider-side cancel already succeeded — webhook will sync DB.
        # Log and proceed; don't fail the request.
        print(f"[me-cancel] DB defense-in-depth update failed (webhook will "
              f"sync): user={user_id} err={e}")

    return jsonify({
        "ok": True,
        "provider": provider,
        "subscription_id": sub_id,
        "current_period_end": period_end,
        "subscription_status": "cancelled",
        "message": ("Subscription cancelled. You'll keep access until "
                    "the end of your current billing period."),
    }), 200


# ============================================================
# /api/webhooks/razorpay — receives subscription lifecycle events
# ------------------------------------------------------------
# Razorpay POSTs here on every subscription event. This is what
# actually moves users between tiers. Without this, payments
# don't translate to tier upgrades.
#
# SECURITY: Verifies the X-Razorpay-Signature header using
# RAZORPAY_WEBHOOK_SECRET. Without verification, anyone could
# POST fake "user paid" events to upgrade themselves.
#
# IDEMPOTENCY: Razorpay retries failed webhooks. We use the
# webhook_events table (PRIMARY KEY on event_id) to detect
# duplicate deliveries and no-op on retries.
#
# EVENT HANDLING:
#   subscription.activated → flip to paid tier, set period dates, monthly_used=0
#   subscription.charged   → renewal: roll period dates, reset monthly_used=0
#   subscription.cancelled → mark status='cancelled', tier preserved (B-simple
#                            cancel-at-period-end via _is_period_active safety net)
#   subscription.halted    → payment failures stopped retrying, downgrade to free
#   subscription.completed → total_count reached (10 years), downgrade to free
#   subscription.paused    → status='paused', tier preserved (treat like cancelled)
#
# Always returns 200 so Razorpay doesn't retry. Errors are logged loud.
# ============================================================
import hmac as _hmac
import hashlib as _hashlib

def _verify_razorpay_signature(raw_body, signature_header, secret):
    """Verify Razorpay webhook signature.
    Razorpay signs webhooks with HMAC-SHA256(secret, raw_body).
    Returns True if signature is valid, False otherwise. Never raises."""
    if not signature_header or not secret:
        return False
    try:
        expected = _hmac.new(
            secret.encode("utf-8"),
            raw_body,
            _hashlib.sha256,
        ).hexdigest()
        # Use compare_digest to prevent timing attacks
        return _hmac.compare_digest(expected, signature_header)
    except Exception as e:
        print(f"[rzp-webhook] signature verify error: {e}")
        return False


def _ts_to_iso(ts):
    """Convert Razorpay's epoch timestamp (seconds, int) to ISO 8601 UTC string.
    Returns empty string if ts is None/invalid. Never raises."""
    if ts is None:
        return ""
    try:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()
    except Exception:
        return ""


def _tier_from_plan_id(plan_id):
    """Reverse-lookup: given a Razorpay plan_id, return the tier name.
    Reads env vars to figure out which plan_id corresponds to which tier+cycle.
    Returns ('creator'|'pro'|'agency'|'', 'monthly'|'yearly'|''). Never raises.

    Used when subscription.activated fires — we need to know which tier the
    user just bought. We could read it from notes.tier, but reverse-lookup
    via plan_id is more authoritative (notes can be tampered, plan_id can't).
    """
    if not plan_id:
        return "", ""
    plan_id = plan_id.strip()
    for tier in ("creator", "pro", "agency"):
        for cycle in ("monthly", "yearly"):
            env_var = f"RAZORPAY_PLAN_{tier.upper()}_{cycle.upper()}"
            if (os.getenv(env_var) or "").strip() == plan_id:
                return tier, cycle
    return "", ""


@app.route("/api/webhooks/razorpay", methods=["POST", "OPTIONS"])
def razorpay_webhook():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

    # 1. Get the webhook secret
    secret = (os.getenv("RAZORPAY_WEBHOOK_SECRET") or "").strip()
    if not secret:
        # No secret configured — accept (200) so Razorpay doesn't retry forever,
        # but log loud. This means we can't verify any webhook until secret is set.
        print("[rzp-webhook] RAZORPAY_WEBHOOK_SECRET not configured — refusing")
        return jsonify({"ok": False, "error": "webhook_secret_missing"}), 503

    # 2. Get raw body + signature header
    raw_body = request.get_data()
    signature = request.headers.get("X-Razorpay-Signature", "")

    # 3. Verify signature
    if not _verify_razorpay_signature(raw_body, signature, secret):
        print(f"[rzp-webhook] signature verification failed (sig={signature[:20]}...)")
        return jsonify({"ok": False, "error": "bad_signature"}), 401

    # 4. Parse JSON payload
    try:
        payload = request.get_json(force=True, silent=True) or {}
    except Exception as e:
        print(f"[rzp-webhook] JSON parse error: {e}")
        return jsonify({"ok": False, "error": "bad_json"}), 400

    event_type = payload.get("event", "")
    event_id = ""
    # Razorpay's event_id is at payload.id OR payload.payload.subscription.entity.id
    # Best practice: use payload.id (the event-level id, unique per webhook delivery)
    event_id = payload.get("id", "") or payload.get("event_id", "")

    if not event_id:
        # Fallback: synthesize an id from event type + entity id + timestamp
        # This is defensive — every Razorpay payload SHOULD have id, but...
        sub_obj = (payload.get("payload", {}) or {}).get("subscription", {}) or {}
        sub_entity = sub_obj.get("entity", {}) or {}
        sub_id = sub_entity.get("id", "")
        ts = payload.get("created_at", "")
        event_id = f"synth_{event_type}_{sub_id}_{ts}"
        print(f"[rzp-webhook] WARN: payload missing id field, using synth: {event_id}")

    print(f"[rzp-webhook] received event={event_type} id={event_id}")

    # 5. Get Supabase
    supa = _get_supabase()
    if supa is None:
        # Without Supabase, we can't process. Return 500 so Razorpay retries
        # later when (hopefully) Supabase is back up.
        print("[rzp-webhook] Supabase unavailable — returning 500 for retry")
        return jsonify({"ok": False, "error": "supabase_unavailable"}), 500

    # 6. Idempotency check via webhook_events table
    # Insert with PRIMARY KEY on event_id — duplicate delivery throws, we handle gracefully.
    try:
        supa.table("webhook_events").insert({
            "event_id": event_id,
            "provider": "razorpay",
            "event_type": event_type,
            "payload": payload,
            "status": "received",
        }).execute()
    except Exception as ins_err:
        err_str = str(ins_err)
        if "duplicate key" in err_str.lower() or "23505" in err_str:
            # Already processed — return 200, no-op
            print(f"[rzp-webhook] duplicate event {event_id} — already processed, skipping")
            return jsonify({"ok": True, "duplicate": True, "event_id": event_id}), 200
        # Other DB error — log and retry-by-returning-500
        print(f"[rzp-webhook] webhook_events insert failed: {err_str[:200]}")
        return jsonify({"ok": False, "error": "db_insert_failed"}), 500

    # 7. Extract subscription details from payload
    # Razorpay payload structure: payload.payload.subscription.entity = {id, plan_id, status, current_start, current_end, notes, ...}
    sub_obj = (payload.get("payload", {}) or {}).get("subscription", {}) or {}
    sub_entity = sub_obj.get("entity", {}) or {}
    subscription_id = sub_entity.get("id", "")
    plan_id = sub_entity.get("plan_id", "")
    notes = sub_entity.get("notes", {}) or {}
    user_id = notes.get("user_id", "")
    current_start = sub_entity.get("current_start")  # epoch seconds
    current_end = sub_entity.get("current_end")      # epoch seconds

    if not user_id:
        # No user_id in notes — can't proceed. This shouldn't happen if checkout
        # flow worked correctly (we set notes.user_id there).
        print(f"[rzp-webhook] WARN: no user_id in notes for sub={subscription_id}")
        # Mark webhook event as failed but return 200 (don't retry — won't help)
        try:
            supa.table("webhook_events").update({
                "status": "failed",
                "processed_at": _now_utc().isoformat(),
            }).eq("event_id", event_id).execute()
        except Exception:
            pass
        return jsonify({"ok": True, "skipped": True, "reason": "no_user_id_in_notes"}), 200

    # 8. Branch on event type and update user row accordingly
    update_fields = None  # dict of fields to update on users row, or None to skip
    extra_log = ""

    if event_type == "subscription.activated":
        # First-time activation: flip to paid tier, set period dates, reset counters.
        tier, cycle = _tier_from_plan_id(plan_id)
        if not tier:
            print(f"[rzp-webhook] WARN: unknown plan_id {plan_id} on activation — skipping tier flip")
            # Still update status so webhook isn't lost
            update_fields = {
                "subscription_status": "active",
                "subscription_id": subscription_id,
                "plan_id": plan_id,
            }
        else:
            update_fields = {
                "tier": tier,
                "subscription_status": "active",
                "subscription_id": subscription_id,
                "plan_id": plan_id,
                "payment_provider": "razorpay",
                "current_period_start": _ts_to_iso(current_start),
                "current_period_end": _ts_to_iso(current_end),
                "monthly_used": 0,
            }
            extra_log = f"tier={tier} cycle={cycle}"

    elif event_type == "subscription.charged":
        # Renewal payment succeeded — roll period dates, reset monthly_used.
        # Note: also fires on first payment after activation. That's fine — we'd just
        # re-set monthly_used=0 (already 0 from activation), no harm done.
        update_fields = {
            "subscription_status": "active",
            "current_period_start": _ts_to_iso(current_start),
            "current_period_end": _ts_to_iso(current_end),
            "monthly_used": 0,
        }
        extra_log = "renewal"

    elif event_type == "subscription.cancelled":
        # User cancelled. B-simple flavor: set status='cancelled', tier preserved.
        # _is_period_active() safety net auto-treats them as free after period_end.
        update_fields = {
            "subscription_status": "cancelled",
        }
        extra_log = f"cancelled, tier preserved until period_end"

    elif event_type == "subscription.halted":
        # Card declined repeatedly, Razorpay gave up. Immediate downgrade to free.
        update_fields = {
            "tier": "free",
            "subscription_status": "halted",
            "current_period_end": None,
        }
        extra_log = "halted, downgraded to free"

    elif event_type == "subscription.completed":
        # total_count reached (10 years with our settings, so this is rare).
        # Downgrade to free.
        update_fields = {
            "tier": "free",
            "subscription_status": "expired",
            "current_period_end": None,
        }
        extra_log = "completed (total_count reached), downgraded to free"

    elif event_type == "subscription.paused":
        # User paused the sub. Treat like cancelled — preserve tier until period end.
        update_fields = {
            "subscription_status": "paused",
        }
        extra_log = "paused, tier preserved until period_end"

    elif event_type == "subscription.resumed":
        # User unpaused. Flip status back to active, period dates already valid.
        update_fields = {
            "subscription_status": "active",
        }
        extra_log = "resumed"

    else:
        # Unknown event type — log and accept. Don't error (Razorpay would retry).
        print(f"[rzp-webhook] ignoring unknown event_type={event_type}")
        try:
            supa.table("webhook_events").update({
                "status": "skipped",
                "processed_at": _now_utc().isoformat(),
            }).eq("event_id", event_id).execute()
        except Exception:
            pass
        return jsonify({"ok": True, "ignored": True, "event_type": event_type}), 200

    # 9. Apply the update (if any)
    if update_fields is not None:
        # CME-1 fix: check whether this webhook is for the user's CURRENT
        # subscription before clobbering their row. Stale webhooks for old
        # subs (e.g. delayed cancel for sub_OLD after user moved to sub_NEW)
        # would otherwise overwrite the new sub's metadata.
        is_activation = (event_type == "subscription.activated")
        should_apply, stale_reason = _should_apply_webhook(
            supa, user_id, subscription_id, is_activation
        )
        if not should_apply:
            # Webhook is stale — record audit trail and accept (200) so
            # Razorpay doesn't retry. The actual user state is unchanged.
            try:
                supa.table("webhook_events").update({
                    "status": stale_reason,
                    "user_id": user_id,
                    "processed_at": _now_utc().isoformat(),
                }).eq("event_id", event_id).execute()
            except Exception as e:
                print(f"[rzp-webhook] webhook_events stale-status update "
                      f"failed (non-blocking): {e}")
            return jsonify({"ok": True, "skipped_stale": True,
                            "reason": stale_reason,
                            "event_type": event_type}), 200

        try:
            supa.table("users").update(update_fields).eq("id", user_id).execute()
            print(f"[rzp-webhook] [OK] event={event_type} user={user_id} sub={subscription_id} {extra_log} (stale-check={stale_reason})")
        except Exception as e:
            err_str = str(e)[:200]
            print(f"[rzp-webhook] DB update failed for user={user_id}: {err_str}")
            # Mark webhook as failed but return 500 so Razorpay retries
            try:
                supa.table("webhook_events").update({
                    "status": "failed",
                    "processed_at": _now_utc().isoformat(),
                }).eq("event_id", event_id).execute()
            except Exception:
                pass
            return jsonify({"ok": False, "error": "db_update_failed", "detail": err_str}), 500

    # 10. Mark webhook event as processed
    try:
        supa.table("webhook_events").update({
            "status": "processed",
            "user_id": user_id,
            "processed_at": _now_utc().isoformat(),
        }).eq("event_id", event_id).execute()
    except Exception as e:
        # Already applied user update — don't fail the webhook. Just log.
        print(f"[rzp-webhook] webhook_events status update failed (non-blocking): {e}")

    return jsonify({"ok": True, "event_type": event_type, "user_id": user_id}), 200



# ============================================================
# /api/webhooks/paypal — receives subscription lifecycle events from PayPal
# ------------------------------------------------------------
# PayPal POSTs here on every subscription event. Mirrors Razorpay's webhook
# in structure, but uses PayPal-specific:
#   - Signature verification: API call to /v1/notifications/verify-webhook-signature
#     (NOT HMAC like Razorpay — PayPal designed it this way; we have no choice).
#   - Event field paths: event.resource.id (subscription_id), event.resource.custom_id
#     (the user_id we stashed in Task 10), event.resource.plan_id.
#   - Event names: BILLING.SUBSCRIPTION.ACTIVATED, PAYMENT.SALE.COMPLETED, etc.
#
# Same B-simple cancel-at-period-end pattern as Razorpay: cancel webhook just
# sets subscription_status='cancelled' but leaves tier intact. Period-end
# safety net (_is_period_active) auto-treats user as free after period_end.
#
# IDEMPOTENCY: Uses webhook_events table (PRIMARY KEY on event_id) — same
# table as Razorpay, just with provider='paypal' to distinguish.
#
# EVENT HANDLING:
#   BILLING.SUBSCRIPTION.ACTIVATED      → flip to paid tier, set period dates, monthly_used=0
#   PAYMENT.SALE.COMPLETED              → renewal: roll period dates, reset monthly_used=0
#   BILLING.SUBSCRIPTION.CANCELLED      → mark status='cancelled', tier preserved
#   BILLING.SUBSCRIPTION.SUSPENDED      → status='paused', tier preserved (treat like cancel)
#   BILLING.SUBSCRIPTION.EXPIRED        → downgrade to free
#   BILLING.SUBSCRIPTION.PAYMENT.FAILED → log, no tier change (auto-downgrade only on SUSPENDED/EXPIRED)
#
# Always returns 200 so PayPal doesn't retry. Errors logged loud.
# ============================================================

def _verify_paypal_webhook(headers, body_str, webhook_id, access_token):
    """Verify PayPal webhook signature via PayPal's API.
    PayPal doesn't use HMAC — instead we POST the headers + body to their
    /v1/notifications/verify-webhook-signature endpoint and they return
    {verification_status: 'SUCCESS' | 'FAILURE'}.

    Args:
        headers: dict-like (request.headers) — PayPal sends auth_algo, transmission_id,
                 transmission_time, transmission_sig, cert_url
        body_str: raw request body as a string (must match exactly what PayPal sent)
        webhook_id: from PAYPAL_WEBHOOK_ID env var (created in PayPal dashboard)
        access_token: from _get_paypal_access_token()

    Returns True on verified, False on failure or any error. Never raises.
    """
    if not webhook_id or not access_token:
        return False
    try:
        import requests as _requests
        import json as _json
        # Required headers from PayPal — case-insensitive lookup
        def _h(name):
            return headers.get(name) or headers.get(name.lower()) or headers.get(name.title()) or ""
        verify_payload = {
            "auth_algo": _h("PAYPAL-AUTH-ALGO"),
            "cert_url": _h("PAYPAL-CERT-URL"),
            "transmission_id": _h("PAYPAL-TRANSMISSION-ID"),
            "transmission_sig": _h("PAYPAL-TRANSMISSION-SIG"),
            "transmission_time": _h("PAYPAL-TRANSMISSION-TIME"),
            "webhook_id": webhook_id,
            # webhook_event must be the parsed JSON object, not the raw string
            "webhook_event": _json.loads(body_str) if body_str else {},
        }
        # If any required header is missing, fail closed
        for k in ("auth_algo", "cert_url", "transmission_id", "transmission_sig", "transmission_time"):
            if not verify_payload[k]:
                print(f"[pp-webhook] verify: missing required header {k}")
                return False

        resp = _requests.post(
            f"{_PAYPAL_API_BASE}/v1/notifications/verify-webhook-signature",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            data=_json.dumps(verify_payload),
            timeout=15,
        )
        if resp.status_code != 200:
            print(f"[pp-webhook] verify API returned {resp.status_code}: {resp.text[:200]}")
            return False
        result = resp.json()
        status = (result.get("verification_status") or "").strip().upper()
        if status != "SUCCESS":
            print(f"[pp-webhook] verification_status={status}")
            return False
        return True
    except Exception as e:
        print(f"[pp-webhook] verify exception: {e}")
        return False


def _paypal_iso_now():
    """ISO timestamp for the current UTC moment."""
    return _now_utc().isoformat()


@app.route("/api/webhooks/paypal", methods=["POST", "OPTIONS"])
def paypal_webhook():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

    # 1. Get config — webhook_id needed for verification
    webhook_id = (os.getenv("PAYPAL_WEBHOOK_ID") or "").strip()
    if not webhook_id:
        print("[pp-webhook] PAYPAL_WEBHOOK_ID not configured")
        return jsonify({"ok": False, "error": "webhook_not_configured"}), 503

    # 2. Get raw body (string for signature verification, must be byte-for-byte
    # what PayPal sent. We read once and reuse.)
    raw_body = request.get_data(as_text=True)

    # 3. Get OAuth access token (needed for signature verification API call)
    access_token = _get_paypal_access_token()
    if not access_token:
        print("[pp-webhook] could not get PayPal access token for verification")
        # Return 500 so PayPal retries — token issue may be transient
        return jsonify({"ok": False, "error": "paypal_token_unavailable"}), 500

    # 4. Verify signature via PayPal API
    if not _verify_paypal_webhook(request.headers, raw_body, webhook_id, access_token):
        print(f"[pp-webhook] signature verification FAILED")
        return jsonify({"ok": False, "error": "bad_signature"}), 401

    # 5. Parse JSON payload (safe — already verified)
    try:
        payload = request.get_json(force=True, silent=True) or {}
    except Exception as e:
        print(f"[pp-webhook] JSON parse error: {e}")
        return jsonify({"ok": False, "error": "bad_json"}), 400

    event_type = payload.get("event_type", "")
    event_id = payload.get("id", "")  # PayPal puts event id at top level

    if not event_id:
        # Fallback: synthesize an id from event_type + create_time
        ct = payload.get("create_time", "")
        event_id = f"synth_{event_type}_{ct}"
        print(f"[pp-webhook] WARN: payload missing id, using synth: {event_id}")

    print(f"[pp-webhook] received event={event_type} id={event_id}")

    # 6. Get Supabase
    supa = _get_supabase()
    if supa is None:
        print("[pp-webhook] Supabase unavailable — returning 500 for retry")
        return jsonify({"ok": False, "error": "supabase_unavailable"}), 500

    # 7. Idempotency: insert into webhook_events. Duplicate delivery throws.
    try:
        supa.table("webhook_events").insert({
            "event_id": event_id,
            "provider": "paypal",
            "event_type": event_type,
            "payload": payload,
            "status": "received",
        }).execute()
    except Exception as ins_err:
        err_str = str(ins_err)
        if "duplicate key" in err_str.lower() or "23505" in err_str:
            print(f"[pp-webhook] duplicate event {event_id} — already processed")
            return jsonify({"ok": True, "duplicate": True, "event_id": event_id}), 200
        print(f"[pp-webhook] webhook_events insert failed: {err_str[:200]}")
        return jsonify({"ok": False, "error": "db_insert_failed"}), 500

    # 8. Extract subscription details from PayPal's payload structure.
    # PayPal puts the subscription object at payload.resource.
    # Key fields:
    #   resource.id            → PayPal subscription_id (e.g. I-XXXX or BILL-XXXX)
    #   resource.plan_id       → PayPal plan_id
    #   resource.custom_id     → user_id we stashed in Task 10
    #   resource.status        → ACTIVE | CANCELLED | SUSPENDED | EXPIRED
    #   resource.billing_info.next_billing_time → ISO datetime, our period_end
    #   resource.billing_info.last_payment.time → ISO datetime, our period_start
    #   resource.start_time    → original subscription start (used as period_start fallback)
    #
    # For PAYMENT.SALE.COMPLETED, the resource is a Payment object instead:
    #   resource.billing_agreement_id → the subscription_id this payment is for
    #   resource.create_time          → payment timestamp
    resource = payload.get("resource", {}) or {}

    # Identify the subscription_id and find the user
    # For BILLING.SUBSCRIPTION.* events: subscription_id = resource.id
    # For PAYMENT.SALE.COMPLETED: subscription_id = resource.billing_agreement_id
    if event_type.startswith("BILLING.SUBSCRIPTION"):
        subscription_id = resource.get("id", "")
        plan_id = resource.get("plan_id", "")
        user_id = resource.get("custom_id", "")
    elif event_type == "PAYMENT.SALE.COMPLETED":
        subscription_id = resource.get("billing_agreement_id", "")
        plan_id = ""  # not directly available — we'll look up via DB
        user_id = ""  # not in payment payload — we'll look up via DB
    else:
        subscription_id = resource.get("id", "")
        plan_id = resource.get("plan_id", "")
        user_id = resource.get("custom_id", "")

    # If user_id wasn't in payload, look it up via subscription_id in our DB
    if not user_id and subscription_id:
        try:
            res = (supa.table("users")
                   .select("id")
                   .eq("subscription_id", subscription_id)
                   .limit(1)
                   .execute())
            if res.data and len(res.data) > 0:
                user_id = res.data[0]["id"]
        except Exception as e:
            print(f"[pp-webhook] user_id lookup by sub_id failed: {e}")

    if not user_id:
        # Can't proceed — log and accept (PayPal won't retry on 200)
        print(f"[pp-webhook] WARN: no user_id resolvable for event={event_type} sub={subscription_id}")
        try:
            supa.table("webhook_events").update({
                "status": "failed",
                "processed_at": _paypal_iso_now(),
            }).eq("event_id", event_id).execute()
        except Exception:
            pass
        return jsonify({"ok": True, "skipped": True, "reason": "no_user_id_resolvable"}), 200

    # Extract period dates if available (BILLING.SUBSCRIPTION events have these)
    billing_info = resource.get("billing_info", {}) or {}
    last_payment = billing_info.get("last_payment", {}) or {}
    period_start = last_payment.get("time", "") or resource.get("start_time", "")
    period_end = billing_info.get("next_billing_time", "")

    # 9. Branch on event type
    update_fields = None
    extra_log = ""

    if event_type == "BILLING.SUBSCRIPTION.ACTIVATED":
        # First-time activation: flip to paid tier, set period dates, reset counters
        tier, cycle = _paypal_tier_from_plan_id(plan_id)
        if not tier:
            print(f"[pp-webhook] WARN: unknown plan_id {plan_id} on activation")
            update_fields = {
                "subscription_status": "active",
                "subscription_id": subscription_id,
                "plan_id": plan_id,
                "payment_provider": "paypal",
            }
        else:
            update_fields = {
                "tier": tier,
                "subscription_status": "active",
                "subscription_id": subscription_id,
                "plan_id": plan_id,
                "payment_provider": "paypal",
                "current_period_start": period_start or _paypal_iso_now(),
                "current_period_end": period_end or "",
                "monthly_used": 0,
            }
            extra_log = f"tier={tier} cycle={cycle}"

    elif event_type == "PAYMENT.SALE.COMPLETED":
        # Renewal payment succeeded — roll period dates, reset monthly_used.
        # PayPal's PAYMENT.SALE.COMPLETED resource doesn't include period_end.
        # We calculate it ourselves: period_end = period_start + 1 month / 1 year
        # (depending on cycle, which we infer from the user's plan_id in DB).
        # This matches Stripe/Razorpay/standard SaaS behavior — no extra API hop needed.
        update_fields = {
            "subscription_status": "active",
            "monthly_used": 0,
        }
        # period_start = the payment time (when this billing cycle began)
        payment_time = resource.get("create_time", "")
        if payment_time:
            update_fields["current_period_start"] = payment_time

        # Fetch the user's plan_id from DB so we can determine cycle (monthly/yearly)
        # and compute the new period_end. If lookup fails, leave period_end as-is —
        # the period-end safety net might prematurely expire them, but better that
        # than a stale "infinite" period.
        try:
            from datetime import datetime, timezone, timedelta
            # Re-fetch user's plan_id (the one we set when subscription was created)
            user_row = (supa.table("users")
                        .select("plan_id")
                        .eq("id", user_id)
                        .limit(1)
                        .execute())
            if user_row.data and len(user_row.data) > 0:
                stored_plan_id = (user_row.data[0].get("plan_id") or "").strip()
                _tier, cycle = _paypal_tier_from_plan_id(stored_plan_id)
                if cycle and payment_time:
                    # Parse payment_time (PayPal sends ISO 8601 with Z suffix)
                    pt_str = payment_time.replace("Z", "+00:00")
                    pt_dt = datetime.fromisoformat(pt_str)
                    # Calculate period_end = period_start + cycle duration.
                    # 30 days for monthly (close enough for SaaS — exact PayPal handling
                    # uses calendar months, but date math is unambiguous & safe).
                    if cycle == "monthly":
                        new_period_end = pt_dt + timedelta(days=30)
                    else:  # yearly
                        new_period_end = pt_dt + timedelta(days=365)
                    update_fields["current_period_end"] = new_period_end.isoformat()
        except Exception as e:
            print(f"[pp-webhook] period_end calculation skipped: {e}")
        extra_log = "renewal payment"

    elif event_type == "BILLING.SUBSCRIPTION.CANCELLED":
        # User cancelled. B-simple flavor: status='cancelled', tier preserved.
        # _is_period_active() safety net auto-treats them as free after period_end.
        update_fields = {
            "subscription_status": "cancelled",
        }
        extra_log = "cancelled, tier preserved until period_end"

    elif event_type == "BILLING.SUBSCRIPTION.SUSPENDED":
        # PayPal "suspended" = paused. Treat like cancel (preserve tier until period_end).
        update_fields = {
            "subscription_status": "paused",
        }
        extra_log = "suspended, tier preserved until period_end"

    elif event_type == "BILLING.SUBSCRIPTION.EXPIRED":
        # Subscription naturally ended (PayPal-side). Downgrade to free.
        update_fields = {
            "tier": "free",
            "subscription_status": "expired",
            "current_period_end": None,
        }
        extra_log = "expired, downgraded to free"

    elif event_type == "BILLING.SUBSCRIPTION.PAYMENT.FAILED":
        # Payment failed but subscription not yet suspended. Log only — don't
        # downgrade yet. PayPal will retry; if all retries fail, SUSPENDED fires
        # which we handle separately. For now, just record the failure.
        update_fields = None
        extra_log = "payment_failed (no tier change yet)"
        print(f"[pp-webhook] payment_failed user={user_id} sub={subscription_id} (not downgrading — will await SUSPENDED if persistent)")

    else:
        # Unknown event — accept but no-op
        print(f"[pp-webhook] ignoring unknown event_type={event_type}")
        try:
            supa.table("webhook_events").update({
                "status": "skipped",
                "processed_at": _paypal_iso_now(),
            }).eq("event_id", event_id).execute()
        except Exception:
            pass
        return jsonify({"ok": True, "ignored": True, "event_type": event_type}), 200

    # 10. Apply DB update if any
    if update_fields is not None:
        # CME-1 fix: same staleness gate as Razorpay. PayPal's activation
        # event is BILLING.SUBSCRIPTION.ACTIVATED. PAYMENT.SALE.COMPLETED
        # (renewal) is NOT activation — those need sub_id match.
        is_activation = (event_type == "BILLING.SUBSCRIPTION.ACTIVATED")
        should_apply, stale_reason = _should_apply_webhook(
            supa, user_id, subscription_id, is_activation
        )
        if not should_apply:
            # Webhook is stale — record audit trail and accept (200) so
            # PayPal doesn't retry. The actual user state is unchanged.
            try:
                supa.table("webhook_events").update({
                    "status": stale_reason,
                    "user_id": user_id,
                    "processed_at": _paypal_iso_now(),
                }).eq("event_id", event_id).execute()
            except Exception as e:
                print(f"[pp-webhook] webhook_events stale-status update "
                      f"failed (non-blocking): {e}")
            return jsonify({"ok": True, "skipped_stale": True,
                            "reason": stale_reason,
                            "event_type": event_type}), 200

        try:
            supa.table("users").update(update_fields).eq("id", user_id).execute()
            print(f"[pp-webhook] [OK] event={event_type} user={user_id} sub={subscription_id} {extra_log} (stale-check={stale_reason})")
        except Exception as e:
            err_str = str(e)[:200]
            print(f"[pp-webhook] DB update failed for user={user_id}: {err_str}")
            try:
                supa.table("webhook_events").update({
                    "status": "failed",
                    "processed_at": _paypal_iso_now(),
                }).eq("event_id", event_id).execute()
            except Exception:
                pass
            return jsonify({"ok": False, "error": "db_update_failed", "detail": err_str}), 500

    # 11. Mark webhook_events row as processed
    try:
        supa.table("webhook_events").update({
            "status": "processed",
            "user_id": user_id,
            "processed_at": _paypal_iso_now(),
        }).eq("event_id", event_id).execute()
    except Exception as e:
        print(f"[pp-webhook] webhook_events status update failed (non-blocking): {e}")

    return jsonify({"ok": True, "event_type": event_type, "user_id": user_id}), 200



# ============================================================
# /api/auth-debug — diagnostic endpoint, safe to call anytime.
# Reports whether auth deps + Razorpay are configured correctly.
# Does NOT expose any secrets — only their PRESENCE/ABSENCE.
# ============================================================
@app.route("/api/auth-debug", methods=["GET", "OPTIONS"])
def auth_debug():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200
    supa = _get_supabase()
    jwks = _get_jwks_client()
    rzp = _get_razorpay()
    return jsonify({
        "auth_deps_imported": _AUTH_DEPS_OK,
        "auth_deps_error": _AUTH_DEPS_ERR if not _AUTH_DEPS_OK else "",
        "supabase_url_set": bool((os.getenv("SUPABASE_URL") or "").strip()),
        "supabase_key_set": bool((os.getenv("SUPABASE_SERVICE_KEY") or "").strip()),
        "clerk_webhook_secret_set": bool((os.getenv("CLERK_WEBHOOK_SECRET") or "").strip()),
        "clerk_secret_key_set": bool((os.getenv("CLERK_SECRET_KEY") or "").strip()),
        "supabase_client_ready": supa is not None,
        "jwks_client_ready": jwks is not None,
        "jwks_init_error": _jwks_init_err if jwks is None else "",
        "signup_fp_limit": int((os.getenv("SIGNUP_FP_LIMIT") or "2").strip()),
        "signup_ip_limit_24h": int((os.getenv("SIGNUP_IP_LIMIT_24H") or "5").strip()),
        # ---- Razorpay diagnostics (Task 5) ----
        "razorpay_deps_imported": _RAZORPAY_DEPS_OK,
        "razorpay_deps_error": _RAZORPAY_DEPS_ERR if not _RAZORPAY_DEPS_OK else "",
        "razorpay_key_id_set": bool((os.getenv("RAZORPAY_KEY_ID") or "").strip()),
        "razorpay_key_secret_set": bool((os.getenv("RAZORPAY_KEY_SECRET") or "").strip()),
        "razorpay_webhook_secret_set": bool((os.getenv("RAZORPAY_WEBHOOK_SECRET") or "").strip()),
        "razorpay_client_ready": rzp is not None,
        "razorpay_plans_configured": {
            "creator_monthly": bool((os.getenv("RAZORPAY_PLAN_CREATOR_MONTHLY") or "").strip()),
            "creator_yearly":  bool((os.getenv("RAZORPAY_PLAN_CREATOR_YEARLY") or "").strip()),
            "pro_monthly":     bool((os.getenv("RAZORPAY_PLAN_PRO_MONTHLY") or "").strip()),
            "pro_yearly":      bool((os.getenv("RAZORPAY_PLAN_PRO_YEARLY") or "").strip()),
            "agency_monthly":  bool((os.getenv("RAZORPAY_PLAN_AGENCY_MONTHLY") or "").strip()),
            "agency_yearly":   bool((os.getenv("RAZORPAY_PLAN_AGENCY_YEARLY") or "").strip()),
        },
        # ---- PayPal diagnostics (Task 10) ----
        # Token reachable means OAuth call succeeded — i.e. CLIENT_ID + SECRET valid
        # AND PayPal API reachable. We DO NOT call this on every auth-debug request
        # (would burn rate limits) — instead we check cache state.
        "paypal_client_id_set": bool((os.getenv("PAYPAL_CLIENT_ID") or "").strip()),
        "paypal_client_secret_set": bool((os.getenv("PAYPAL_CLIENT_SECRET") or "").strip()),
        "paypal_webhook_id_set": bool((os.getenv("PAYPAL_WEBHOOK_ID") or "").strip()),
        "paypal_product_id_set": bool((os.getenv("PAYPAL_PRODUCT_ID") or "").strip()),
        "paypal_plans_configured": {
            "creator_monthly": bool((os.getenv("PAYPAL_PLAN_CREATOR_MONTHLY") or "").strip()),
            "creator_yearly":  bool((os.getenv("PAYPAL_PLAN_CREATOR_YEARLY") or "").strip()),
            "pro_monthly":     bool((os.getenv("PAYPAL_PLAN_PRO_MONTHLY") or "").strip()),
            "pro_yearly":      bool((os.getenv("PAYPAL_PLAN_PRO_YEARLY") or "").strip()),
            "agency_monthly":  bool((os.getenv("PAYPAL_PLAN_AGENCY_MONTHLY") or "").strip()),
            "agency_yearly":   bool((os.getenv("PAYPAL_PLAN_AGENCY_YEARLY") or "").strip()),
        },
        # ---- Task 14: My Account self-service cancel ----
        # Presence of these flags simply confirms the new code is deployed.
        "task_14_endpoints_deployed": {
            "me_subscription_get":     True,
            "me_cancel_subscription":  True,
        },
        # ---- CME-1 webhook race-condition fix ----
        # When True, both Razorpay & PayPal webhook handlers gate UPDATE
        # writes on subscription_id match (with activation override).
        "cme1_webhook_staleness_check": True,
        # ---- CME-2 checkout rate limit ----
        # When True, both checkout endpoints rate-limit per user per
        # provider (3 attempts per 5 minutes, in-memory sliding window).
        "cme2_checkout_rate_limit": True,
        # ---- /api/webhook-health auth secret ----
        # Required to be set before configuring the external cron job.
        "webhook_health_key_set": bool((os.getenv("WEBHOOK_HEALTH_KEY") or "").strip()),
        # ---- Sentry error monitoring ----
        # Two booleans here so we can distinguish "DSN not configured"
        # from "DSN configured but init failed at import time".
        "sentry_dsn_set":  bool((os.getenv("SENTRY_DSN") or "").strip()),
        "sentry_active":   _SENTRY_OK,
    })


# ============================================================
# /api/sentry-test — Sentry verification endpoint
# ------------------------------------------------------------
# Triggers a controlled error so we can confirm Sentry is wired
# correctly end-to-end. Used once during initial setup; safe to
# leave in place (auth-gated so randos can't spam our error quota).
#
# Auth: requires X-Sentry-Test-Key header matching SENTRY_TEST_KEY
# env var. If SENTRY_TEST_KEY is not set, endpoint returns 503 so
# it can't be abused before the operator opts in.
#
# Two trigger modes via ?mode= query param:
#   message  — captures a Sentry message (info-level, no stack trace)
#   error    — raises ZeroDivisionError, captured as a real exception
#              (default; this is what you want for the smoke test)
#
# Returns 200 with the Sentry event ID on success (so you can search
# for it in the dashboard). Returns 503 if Sentry isn't initialized.
# ============================================================
@app.route("/api/sentry-test", methods=["GET", "OPTIONS"])
def sentry_test_endpoint():
    if request.method == "OPTIONS":
        return ("", 204)
    expected_key = (os.getenv("SENTRY_TEST_KEY") or "").strip()
    if not expected_key:
        return jsonify({
            "error": "SENTRY_TEST_KEY env var not set on server",
            "hint":  "Set it on Render, then retry with the same value as X-Sentry-Test-Key header",
        }), 503
    provided_key = (request.headers.get("X-Sentry-Test-Key") or "").strip()
    if provided_key != expected_key:
        return jsonify({"error": "invalid X-Sentry-Test-Key"}), 401
    if not _SENTRY_OK:
        return jsonify({
            "error": "Sentry not initialized",
            "reason": _SENTRY_ERR or "unknown",
        }), 503
    mode = (request.args.get("mode") or "error").strip().lower()
    try:
        import sentry_sdk as _s
    except Exception as e:
        return jsonify({"error": f"sentry_sdk import failed at runtime: {e}"}), 503
    if mode == "message":
        event_id = _s.capture_message("OnePost Sentry smoke test (message)", level="info")
        return jsonify({
            "ok": True,
            "mode": "message",
            "event_id": event_id,
            "note": "Search this event_id in Sentry dashboard to confirm delivery.",
        })
    # mode == "error" (default): raise inside the request handler so
    # FlaskIntegration captures it automatically with full request context.
    # We return 500 (Flask's default) — Sentry will tag this as a real
    # unhandled exception, exactly like a production bug would look.
    raise ZeroDivisionError("OnePost Sentry smoke test — this is an intentional error, safe to ignore in Sentry")


# ============================================================
# /api/webhook-health — operational audit endpoint
# ------------------------------------------------------------
# Periodic health check for webhook processing. Designed to be pinged
# every 48h by an external cron service (cron-job.org) which will email
# the owner if the response contains "alert":true.
#
# Auth: requires X-Health-Key header matching WEBHOOK_HEALTH_KEY env var.
# Set this env var on Render BEFORE configuring the cron job.
#
# Content negotiation:
#   - Accept: text/html  → returns HTML dashboard (browser-friendly)
#   - Anything else      → returns JSON (cron + curl friendly)
#
# Alert conditions (ANY triggers alert=true and HTTP 503):
#   1. ANY 'failed' webhook events in last 7 days
#   2. ANY 'applied_no_match_warned' events in last 7 days (orphan rows)
#   3. >5 'ignored_stale_*' events in last 24h (race firing too often)
#
# HTTP status semantics:
#   200 — alert=false (healthy). cron-job.org logs as success.
#   503 — alert=true (something needs attention). cron-job.org fires the
#         failure-notification email. On recovery (next 200), it fires
#         a "recovered" email so you know it's resolved.
#   403 — auth header missing/wrong. NOT an alert state, just a bad
#         request. Won't trigger cron-job.org's persistent-failure flow.
# ============================================================
@app.route("/api/webhook-health", methods=["GET", "OPTIONS"])
def webhook_health():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

    # Auth: shared secret header. Don't accept query-string version —
    # that would leak the key into Render request logs.
    expected_key = (os.getenv("WEBHOOK_HEALTH_KEY") or "").strip()
    if not expected_key:
        # Env var not configured. Refuse politely instead of returning data.
        return jsonify({
            "ok": False,
            "error": "WEBHOOK_HEALTH_KEY env var not set on backend"
        }), 503
    provided_key = (request.headers.get("X-Health-Key") or "").strip()
    if provided_key != expected_key:
        # Don't 401 — that triggers cron retry logic. Just refuse with 403.
        return jsonify({"ok": False, "error": "forbidden"}), 403

    supa = _get_supabase()
    if supa is None:
        # Supabase missing — we can't audit. Return 503 so cron-job.org's
        # failure-notification fires and emails the owner. The alert
        # signal is also in the body for human inspection.
        return jsonify({
            "ok": True,
            "alert": True,
            "alert_reasons": ["supabase_client_unavailable"],
            "checked_at": _now_utc().isoformat(),
        }), 503

    # Collect counts. Three windows:
    #   24h — for the spike threshold
    #   7d  — for the broad health view
    #   total — sanity check the table has data at all
    from datetime import timedelta
    now = _now_utc()
    iso_24h = (now - timedelta(hours=24)).isoformat()
    iso_7d  = (now - timedelta(days=7)).isoformat()

    # Try a robust fetch. If anything fails, set alert=true with the reason
    # rather than crashing.
    counts_7d = {}
    counts_24h = {}
    total_ever = 0
    audit_error = ""
    try:
        # Pull all rows from last 7 days, group in Python (small data, OK).
        # Supabase Python client doesn't support GROUP BY directly — we'd
        # need an RPC for that. Fetching raw rows is fine at this scale.
        res_7d = (supa.table("webhook_events")
                  .select("status, received_at")
                  .gte("received_at", iso_7d)
                  .execute())
        rows = res_7d.data or []
        for r in rows:
            s = (r.get("status") or "unknown")
            counts_7d[s] = counts_7d.get(s, 0) + 1
            ra = r.get("received_at") or ""
            if ra >= iso_24h:
                counts_24h[s] = counts_24h.get(s, 0) + 1

        # Total count of webhook_events ever (sanity check, small table)
        # We use a HEAD-style count if Supabase client supports it. Falling
        # back to a simple list query bounded by limit=1 if not, for which
        # we won't get the total. Safer to omit on failure.
        try:
            res_total = (supa.table("webhook_events")
                         .select("event_id", count="exact")
                         .limit(1)
                         .execute())
            total_ever = int(getattr(res_total, "count", 0) or 0)
        except Exception:
            total_ever = -1  # signal "unknown" without crashing
    except Exception as e:
        audit_error = str(e)[:200]
        print(f"[webhook-health] audit query failed: {audit_error}")

    # Decide alert state
    alert = False
    alert_reasons = []

    if audit_error:
        alert = True
        alert_reasons.append(f"audit_query_failed: {audit_error}")

    failed_7d = counts_7d.get("failed", 0)
    if failed_7d > 0:
        alert = True
        alert_reasons.append(f"failed_events_7d={failed_7d}")

    orphan_7d = counts_7d.get("applied_no_match_warned", 0)
    if orphan_7d > 0:
        alert = True
        alert_reasons.append(f"orphan_rows_7d={orphan_7d}")

    stale_24h = (counts_24h.get("ignored_stale_sub", 0)
                 + counts_24h.get("ignored_stale_active", 0))
    if stale_24h > 5:
        alert = True
        alert_reasons.append(f"stale_race_24h={stale_24h}_exceeds_threshold_5")

    # Build the response payload
    payload = {
        "ok": True,
        "alert": alert,
        "alert_reasons": alert_reasons,
        "checked_at": now.isoformat(),
        "window_24h": counts_24h,
        "window_7d": counts_7d,
        "total_ever": total_ever,
        "thresholds": {
            "stale_24h_max": 5,
            "failed_7d_max": 0,
            "orphan_7d_max": 0,
        },
    }

    # Content negotiation. Browser → HTML dashboard. Everything else → JSON.
    accept = (request.headers.get("Accept") or "").lower()
    wants_html = "text/html" in accept

    # HTTP status: alert → 503 so cron-job.org's failure-notification
    # fires and emails the owner. Clean state → 200. The endpoint still
    # responds successfully in both cases — the status code is purely
    # a signaling mechanism for external monitoring.
    status_code = 503 if alert else 200

    if not wants_html:
        return jsonify(payload), status_code

    # ---- HTML rendering ----
    # Minimal, no-CSS-framework dashboard. Two tables, status banner at top.
    # All untrusted content is integer counts, so HTML escaping isn't
    # strictly required, but we _str() everything anyway for safety.
    def _row(status_name, count_7d, count_24h):
        return (f"<tr><td>{_html_escape(status_name)}</td>"
                f"<td style='text-align:right'>{int(count_24h)}</td>"
                f"<td style='text-align:right'>{int(count_7d)}</td></tr>")

    # Union of statuses seen in either window, sorted by 7d count desc.
    all_statuses = set(counts_7d.keys()) | set(counts_24h.keys())
    sorted_statuses = sorted(all_statuses,
                             key=lambda s: counts_7d.get(s, 0),
                             reverse=True)
    rows_html = "".join(
        _row(s, counts_7d.get(s, 0), counts_24h.get(s, 0))
        for s in sorted_statuses
    ) or "<tr><td colspan='3' style='text-align:center;color:#888'>No webhook events in this window.</td></tr>"

    banner_bg = "#d73a49" if alert else "#28a745"
    banner_text = ("⚠ ALERT — " + "; ".join(alert_reasons)) if alert else "✓ All clear"
    reasons_html = ("<ul>" + "".join(f"<li>{_html_escape(r)}</li>" for r in alert_reasons) + "</ul>") if alert_reasons else ""

    html = f"""<!doctype html>
<html><head>
<meta charset="utf-8">
<title>OnePost — Webhook Health</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;color:#24292e}}
  h1{{font-size:1.5rem;margin-bottom:0.25rem}}
  .meta{{color:#586069;font-size:0.85rem;margin-bottom:1rem}}
  .banner{{background:{banner_bg};color:#fff;padding:0.75rem 1rem;border-radius:6px;font-weight:600;margin:1rem 0}}
  table{{width:100%;border-collapse:collapse;margin:1rem 0}}
  th,td{{padding:0.5rem 0.75rem;border-bottom:1px solid #e1e4e8;font-size:0.95rem}}
  th{{background:#f6f8fa;text-align:left;font-weight:600}}
  th:nth-child(2),th:nth-child(3){{text-align:right}}
  .footer{{color:#586069;font-size:0.8rem;margin-top:2rem;border-top:1px solid #e1e4e8;padding-top:0.75rem}}
  code{{background:#f6f8fa;padding:0.1rem 0.3rem;border-radius:3px;font-size:0.85rem}}
</style>
</head><body>
<h1>OnePost — Webhook Health</h1>
<div class="meta">Checked at {_html_escape(now.isoformat())} · Total events ever: {int(total_ever) if total_ever >= 0 else "unknown"}</div>
<div class="banner">{_html_escape(banner_text)}</div>
{reasons_html}
<table>
<thead><tr><th>Status</th><th>Last 24h</th><th>Last 7 days</th></tr></thead>
<tbody>{rows_html}</tbody>
</table>
<div class="footer">
Thresholds: alert if <code>failed</code> &gt; 0 in 7d, OR <code>applied_no_match_warned</code> &gt; 0 in 7d, OR <code>ignored_stale_*</code> &gt; 5 in 24h.<br>
Healthy distribution: most events as <code>processed</code> or <code>applied</code>; a few <code>ignored_stale_sub</code> is fine (CME-1 fix working); zero <code>failed</code>.
</div>
</body></html>"""
    return Response(html, mimetype="text/html"), status_code


def _html_escape(s):
    """Minimal HTML-escape for safety in the dashboard. Standard library
    `html.escape` would work, but we keep it inline so this endpoint has
    no extra imports at module top."""
    if s is None:
        return ""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
