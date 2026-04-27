import os
import base64
import requests
import tempfile
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
        return jsonify({"status": "ok"}), 200

    groq_key = os.getenv("GROQ_API_KEY")
    deepgram_key = os.getenv("DEEPGRAM_KEY")

    content_type_input = request.form.get("content_type", "personal story")
    tone = request.form.get("tone", "casual and fun")
    language = request.form.get("language", "english")

    if language == "hindi":
        lang_instruction = "Generate ALL content in Hindi only (Devanagari script)."
    elif language == "both":
        lang_instruction = "Generate in BOTH English and Hindi. English first, then Hindi below separated by ---"
    else:
        lang_instruction = "Generate ALL content in English only."

    context = ""
    file_analysis = ""

    if "file" in request.files:
        f = request.files["file"]
        file_bytes = f.read()
        mime = f.mimetype or ""

        if mime.startswith("image"):
            b64 = base64.b64encode(file_bytes).decode()
            vision_resp = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {groq_key}", "Content-Type": "application/json"},
                json={
                    "model": "meta-llama/llama-4-scout-17b-16e-instruct",
                    "messages": [{"role": "user", "content": [
                        {"type": "text", "text": f"Analyze this image in detail for social media content generation. Content type: {content_type_input}, tone: {tone}. Describe everything you see: subjects, setting, mood, colors, text, products, emotions."},
                        {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{b64}"}}
                    ]}],
                    "max_tokens": 500
                },
                timeout=30
            )
            if vision_resp.ok:
                file_analysis = vision_resp.json()["choices"][0]["message"]["content"]
            context = file_analysis or f"An image for {content_type_input} content"

        elif mime.startswith("video") or mime.startswith("audio"):
            try:
                dg_resp = requests.post(
                    "https://api.deepgram.com/v1/listen",
                    params={"model": "nova-2", "smart_format": "true", "punctuate": "true"},
                    headers={"Authorization": f"Token {deepgram_key}", "Content-Type": mime},
                    data=file_bytes,
                    timeout=180
                )
                if dg_resp.ok:
                    dg_data = dg_resp.json()
                    transcript = dg_data["results"]["channels"][0]["alternatives"][0]["transcript"]
                    if transcript:
                        context = f"Video transcript: {transcript}"
            except Exception:
                pass

            # Extract first frame from video for visual analysis
            try:
                import cv2
                import numpy as np
                with tempfile.NamedTemporaryFile(suffix='.mp4', delete=False) as tmp:
                    tmp.write(file_bytes)
                    tmp_path = tmp.name
                cap = cv2.VideoCapture(tmp_path)
                frames_b64 = []
                total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
                for pos in [total//4, total//2, (3*total)//4]:
                    cap.set(cv2.CAP_PROP_POS_FRAMES, pos)
                    ret, frame = cap.read()
                    if ret:
                        _, buf = cv2.imencode('.jpg', frame)
                        frames_b64.append(base64.b64encode(buf).decode())
                cap.release()
                os.unlink(tmp_path)
                if frames_b64:
                    msgs = [{"type": "text", "text": f"Analyze these video frames in detail. Content type: {content_type_input}, tone: {tone}. Describe everything: subjects, setting, actions, mood, colors, text visible, products, emotions."}]
                    for fb in frames_b64:
                        msgs.append({"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{fb}"}})
                    vis_resp = requests.post(
                        "https://api.groq.com/openai/v1/chat/completions",
                        headers={"Authorization": f"Bearer {groq_key}", "Content-Type": "application/json"},
                        json={"model": "meta-llama/llama-4-scout-17b-16e-instruct", "messages": [{"role": "user", "content": msgs}], "max_tokens": 600},
                        timeout=30
                    )
                    if vis_resp.ok:
                        visual_desc = vis_resp.json()["choices"][0]["message"]["content"]
                        if context and len(context) > 20:
                            context = f"VIDEO TRANSCRIPT: {context}\nVISUAL DESCRIPTION: {visual_desc}"
                        else:
                            context = f"VISUAL DESCRIPTION: {visual_desc}"
                        file_analysis = visual_desc
            except Exception as ve:
                pass

            if not context:
                context = f"A {content_type_input} video with {tone} tone"
    else:
        context = request.form.get("text", "Create engaging social media content")

    prompt = f"""You are OnePost AI. Generate optimized social media content.

Content: "{context}"
Type: {content_type_input}
Tone: {tone}
Language: {lang_instruction}

Return ONLY valid JSON with no extra text:
{{
  "instagram": "caption with emojis and 5-8 hashtags",
  "facebook": "friendly conversational post",
  "youtube_shorts": "HOOK: ... MAIN: ... CTA: ...",
  "reels_script": "hook + 3 key points + strong CTA",
  "linkedin": "professional post with insight",
  "twitter": "thread with 1/ 2/ 3/ 4/ tweets",
  "whatsapp": "punchy status under 150 chars",
  "pinterest": "SEO-rich pin description"
}}"""

    groq_resp = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {groq_key}", "Content-Type": "application/json"},
        json={
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1500,
            "temperature": 0.7
        },
        timeout=60
    )

    if not groq_resp.ok:
        return jsonify({"error": "Groq API error", "details": groq_resp.text}), 502

    content_text = groq_resp.json()["choices"][0]["message"]["content"]

    import json
    import re
    json_match = re.search(r'\{.*\}', content_text, re.DOTALL)
    if json_match:
        try:
            result = json.loads(json_match.group())
            return jsonify({"success": True, "content": result, "analysis": file_analysis})
        except Exception:
            pass

    return jsonify({"error": "Could not parse response", "raw": content_text}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

