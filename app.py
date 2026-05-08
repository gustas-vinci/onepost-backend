import os
import json
import base64
import re
import time
import threading
import requests
from collections import deque
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS

load_dotenv()
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
USER_DAILY_LIMIT = 3  # mirror of frontend DAILY_CAP

def _today_iso():
    """Today's date in YYYY-MM-DD format (UTC). Used for daily_reset_at comparisons."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).date().isoformat()


def _get_user_quota(supa, user_id):
    """Read current quota state for an authenticated user. Lazy-resets daily counter
    if it's a new day since last reset.

    Returns dict:
        {
          "ok": bool,
          "user_id": str,
          "daily_used": int,
          "daily_limit": int,
          "bonus_credits": int,
          "daily_remaining": int,    # max(0, daily_limit - daily_used)
          "total_remaining": int,    # daily_remaining + bonus_credits
          "allowed": bool,           # total_remaining > 0
          "reason": str              # 'ok' | 'no_user' | 'db_error'
        }

    Never raises. On DB error, returns ok=False with reason set.
    """
    try:
        res = (supa.table("users")
               .select("id, daily_used, bonus_credits, daily_reset_at")
               .eq("id", user_id)
               .limit(1)
               .execute())
        if not res.data or len(res.data) == 0:
            # User authenticated via JWT but no Supabase row — webhook may not have
            # synced yet. Treat as anonymous-quota-equivalent (allow but warn).
            return {
                "ok": False, "user_id": user_id,
                "daily_used": 0, "daily_limit": USER_DAILY_LIMIT,
                "bonus_credits": 0, "daily_remaining": USER_DAILY_LIMIT,
                "total_remaining": USER_DAILY_LIMIT, "allowed": True,
                "reason": "no_user_row"
            }
        row = res.data[0]
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

        daily_remaining = max(0, USER_DAILY_LIMIT - daily_used)
        total_remaining = daily_remaining + bonus_credits
        return {
            "ok": True, "user_id": user_id,
            "daily_used": daily_used, "daily_limit": USER_DAILY_LIMIT,
            "bonus_credits": bonus_credits,
            "daily_remaining": daily_remaining,
            "total_remaining": total_remaining,
            "allowed": total_remaining > 0,
            "reason": "ok"
        }
    except Exception as e:
        print(f"[quota] _get_user_quota error for {user_id}: {e}")
        return {
            "ok": False, "user_id": user_id,
            "daily_used": 0, "daily_limit": USER_DAILY_LIMIT,
            "bonus_credits": 0, "daily_remaining": USER_DAILY_LIMIT,
            "total_remaining": USER_DAILY_LIMIT, "allowed": True,
            "reason": f"db_error: {str(e)[:80]}"
        }


def _consume_user_quota(supa, user_id):
    """Decrement quota for an authenticated user.
    Daily is consumed first; once exhausted, bonus credits are consumed.

    Returns dict:
        {
          "ok": bool,
          "consumed_from": "daily" | "bonus" | "none",
          "daily_used": int,
          "bonus_credits": int,
          "remaining_after": int,
          "reason": str
        }

    Never raises.
    """
    # First, get current state (with lazy reset applied)
    state = _get_user_quota(supa, user_id)
    if not state["ok"]:
        return {
            "ok": False, "consumed_from": "none",
            "daily_used": state["daily_used"], "bonus_credits": state["bonus_credits"],
            "remaining_after": state["total_remaining"],
            "reason": state["reason"]
        }

    if state["total_remaining"] <= 0:
        return {
            "ok": False, "consumed_from": "none",
            "daily_used": state["daily_used"], "bonus_credits": state["bonus_credits"],
            "remaining_after": 0, "reason": "exhausted"
        }

    # Consume from daily first if available
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
            "ok": False, "consumed_from": "none",
            "daily_used": state["daily_used"], "bonus_credits": state["bonus_credits"],
            "remaining_after": 0, "reason": "exhausted_unexpected"
        }

    # Write the new state
    try:
        supa.table("users").update({
            "daily_used": new_daily,
            "bonus_credits": new_bonus,
        }).eq("id", user_id).execute()
    except Exception as e:
        print(f"[quota] _consume_user_quota update failed for {user_id}: {e}")
        return {
            "ok": False, "consumed_from": "none",
            "daily_used": state["daily_used"], "bonus_credits": state["bonus_credits"],
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
        "ok": True, "consumed_from": consumed_from,
        "daily_used": new_daily, "bonus_credits": new_bonus,
        "remaining_after": new_total, "reason": "ok"
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

    # 4. Run anti-abuse checks (Layers B + C)
    allowed, reason = _check_signup_metadata_limits(supa, ip, fingerprint, user_id)

    # 5. Get the user's email (for logging the attempt)
    user_email = ""
    try:
        ures = supa.table("users").select("email").eq("id", user_id).limit(1).execute()
        if ures.data and len(ures.data) > 0:
            user_email = ures.data[0].get("email", "") or ""
    except Exception:
        pass

    # 6. Always log the attempt (whether allowed or blocked)
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
# /api/auth-debug — diagnostic endpoint, safe to call anytime.
# Reports whether auth deps are configured correctly. Does NOT
# expose any secrets — only their PRESENCE/ABSENCE and lengths.
# ============================================================
@app.route("/api/auth-debug", methods=["GET", "OPTIONS"])
def auth_debug():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200
    supa = _get_supabase()
    jwks = _get_jwks_client()
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
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
