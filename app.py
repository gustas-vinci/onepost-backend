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
# Rate Limiting (IP-based, in-memory)
# ============================================================
# REGEN_LIMIT regenerations per IP within REGEN_WINDOW_SEC.
# Storage is in-memory: { ip: deque([timestamps...]) }
# Lost on server restart (Render free tier sleeps after ~15min idle).
# That's an acceptable tradeoff for a beta — bypass via VPN/different
# network is also possible, this is best-effort soft enforcement.
REGEN_LIMIT = 5
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
    """Check if user has remaining generations for the day.
    Identifies user by email AND fingerprint AND IP — match on ANY = quota counts."""
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200
    try:
        data = request.get_json(force=True, silent=True) or {}
        email = (data.get("email") or "").strip().lower()
        fingerprint = (data.get("fingerprint") or "").strip()
        ip = _client_ip()

        result = _call_quota_script("check_quota", email, fingerprint, ip, timeout=10)
        # Surface the result to frontend
        retry_after = int(result.get("retry_after_seconds") or 0)
        # Surface Apps Script error if present (for debugging visibility)
        upstream_error = result.get("error", "") if not result.get("ok", True) else ""
        return jsonify({
            "success": True,
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
        return jsonify({"success": True, "allowed": True, "used": 0,
                        "remaining": 3, "limit": 3, "retry_after_seconds": 0,
                        "retry_after_human": "", "note": f"backend_error: {str(e)[:80]}"})


@app.route("/record-generation", methods=["POST", "OPTIONS"])
def record_generation():
    """Record a successful generation against this user's quota.
    Called by frontend AFTER /generate succeeds."""
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200
    try:
        data = request.get_json(force=True, silent=True) or {}
        email = (data.get("email") or "").strip().lower()
        fingerprint = (data.get("fingerprint") or "").strip()
        ip = _client_ip()

        result = _call_quota_script("record_generation", email, fingerprint, ip, timeout=10)
        # Surface Apps Script error if present (so frontend debug overlay shows it)
        upstream_error = result.get("error", "") if not result.get("ok", True) else ""
        return jsonify({
            "success": True,
            "recorded": bool(result.get("recorded", False)),
            "row": result.get("row", 0),
            "note": result.get("_note", "") or upstream_error
        })
    except Exception as e:
        print(f"[record-generation] Unexpected error: {e}")
        return jsonify({"success": True, "recorded": False, "note": f"backend_error: {str(e)[:80]}"})


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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
