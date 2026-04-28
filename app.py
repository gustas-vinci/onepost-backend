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
        lang_instruction = "Generate ALL content in Hindi only (Devanagari script)."
    elif language == "both":
        lang_instruction = "Generate in BOTH English and Hindi. English first, then Hindi below, separated by ---"
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

