import os
import json
import base64
import re
import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS

load_dotenv()
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

@app.after_request
def add_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "*"
    return response

@app.route("/")
def home():
    return jsonify({"status": "OnePost backend live"})

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
# /regenerate — single platform caption regeneration
# ============================================================
@app.route("/regenerate", methods=["POST", "OPTIONS"])
def regenerate():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

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

        return jsonify({
            "success": True,
            "caption": new_caption,
            "platform": platform,
            "attempt": int(attempt) if attempt.isdigit() else 1
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
