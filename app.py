import os
import base64
import json
import mimetypes
import tempfile
from typing import Any

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS

load_dotenv()
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=False)

@app.after_request
def add_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Max-Age"] = "86400"
    return response

@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "OnePost backend is live"})

def _guess_mime(file_storage) -> str:
    mime = (getattr(file_storage, "mimetype", None) or "").strip()
    if mime:
        return mime
    guessed, _ = mimetypes.guess_type(getattr(file_storage, "filename", "") or "")
    return guessed or "application/octet-stream"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def _deepgram_transcribe(file_storage) -> str:
    deepgram_key = os.getenv("DEEPGRAM_KEY")
    if not deepgram_key:
        raise RuntimeError("Missing DEEPGRAM_KEY")

    content_type = _guess_mime(file_storage)

    resp = requests.post(
        "https://api.deepgram.com/v1/listen",
        params={"model": "nova-2", "smart_format": "true", "punctuate": "true"},
        headers={"Authorization": f"Token {deepgram_key}", "Content-Type": content_type},
        data=file_storage.stream,
        timeout=180,
    )
    if not resp.ok:
        raise RuntimeError(f"Deepgram error: {resp.status_code}")

    try:
        data = resp.json()
        return data["results"]["channels"][0]["alternatives"][0]["transcript"] or ""
    except Exception:
        return ""


def _extract_video_frames_base64(video_bytes: bytes, max_frames: int = 6) -> list[dict[str, str]]:
    try:
        import cv2  # type: ignore
    except Exception as e:
        raise RuntimeError("Missing opencv-python dependency for video frame extraction") from e

    images: list[dict[str, str]] = []

    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=True) as tmp:
        tmp.write(video_bytes)
        tmp.flush()

        cap = cv2.VideoCapture(tmp.name)
        if not cap.isOpened():
            return images

        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        if frame_count <= 0:
            frame_count = max_frames

        step = max(frame_count // max_frames, 1)
        idx = 0
        grabbed = 0

        while grabbed < max_frames:
            cap.set(cv2.CAP_PROP_POS_FRAMES, idx)
            ok, frame = cap.read()
            if not ok or frame is None:
                break

            ok2, buf = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 85])
            if not ok2:
                break

            images.append({"media_type": "image/jpeg", "data": _b64(buf.tobytes())})
            grabbed += 1
            idx += step

        cap.release()

    return images


def _anthropic_generate_posts(*, prompt_text: str, images: list[dict[str, str]] | None = None) -> dict[str, Any]:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("Missing ANTHROPIC_API_KEY")

    content: list[dict[str, Any]] = [{"type": "text", "text": prompt_text}]
    for img in images or []:
        content.append(
            {
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": img["media_type"],
                    "data": img["data"],
                },
            }
        )

    payload = {
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 1800,
        "temperature": 0.7,
        "messages": [{"role": "user", "content": content}],
    }

    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        data=json.dumps(payload),
        timeout=180,
    )

    if not resp.ok:
        raise RuntimeError(f"Anthropic error: {resp.status_code} {resp.text[:500]}")

    data = resp.json()
    text_parts = []
    for item in data.get("content", []) or []:
        if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
            text_parts.append(item["text"])
    raw_text = "\n".join(text_parts).strip()

    # Expect strict JSON from the model; attempt to parse. If the model wraps JSON in text, extract the first JSON object.
    try:
        return json.loads(raw_text)
    except Exception:
        start = raw_text.find("{")
        end = raw_text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(raw_text[start : end + 1])
        raise


def _generation_prompt(*, asset_type: str, transcript: str | None = None) -> str:
    return f"""
You are OnePost. Generate platform-specific social media posts for 8 platforms.
Asset type: {asset_type}
Transcript (if present): {transcript or ""}

Return STRICT JSON ONLY with this exact shape (no markdown, no extra keys):
{{
  "platform_posts": {{
    "instagram": {{"caption": "...", "hashtags": ["..."], "cta": "..."}}, 
    "tiktok": {{"caption": "...", "hashtags": ["..."], "cta": "..."}}, 
    "youtube_shorts": {{"title": "...", "description": "...", "hashtags": ["..."], "cta": "..."}}, 
    "x": {{"post": "...", "hashtags": ["..."], "cta": "..."}}, 
    "threads": {{"post": "...", "hashtags": ["..."], "cta": "..."}}, 
    "linkedin": {{"post": "...", "hashtags": ["..."], "cta": "..."}}, 
    "facebook": {{"post": "...", "hashtags": ["..."], "cta": "..."}}, 
    "pinterest": {{"title": "...", "description": "...", "hashtags": ["..."], "cta": "..."}}
  }}
}}

Constraints:
- Keep tone consistent and tailored per platform.
- Use the visual content + transcript (if provided) to be accurate.
- Avoid hallucinating specifics not in the media; be generic when uncertain.
""".strip()


@app.route("/generate", methods=["POST", "OPTIONS"])
def generate():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded. Use multipart form field 'file'."}), 400

    f = request.files["file"]
    if not f or not getattr(f, "filename", ""):
        return jsonify({"error": "Empty upload."}), 400

    mime = _guess_mime(f)

    try:
        if mime.startswith("image/"):
            img_bytes = f.read()
            images = [{"media_type": mime, "data": _b64(img_bytes)}]
            prompt = _generation_prompt(asset_type="image")
            result = _anthropic_generate_posts(prompt_text=prompt, images=images)
            return jsonify(result)

        if mime.startswith("video/"):
            # Deepgram consumes the stream; also capture bytes for frame extraction.
            video_bytes = f.read()

            with tempfile.NamedTemporaryFile(suffix=".mp4", delete=True) as tmp:
                tmp.write(video_bytes)
                tmp.flush()
                tmp.seek(0)

                class _TmpLike:
                    stream = tmp
                    filename = getattr(f, "filename", "video.mp4")
                    mimetype = mime

                transcript = _deepgram_transcribe(_TmpLike())

            frames = _extract_video_frames_base64(video_bytes, max_frames=6)
            prompt = _generation_prompt(asset_type="video", transcript=transcript)
            result = _anthropic_generate_posts(prompt_text=prompt, images=frames)
            result.setdefault("transcript", transcript)
            result.setdefault("frames_sent", len(frames))
            return jsonify(result)

        return jsonify({"error": f"Unsupported file type: {mime}"}), 415

    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    except requests.RequestException as e:
        return jsonify({"error": "Network error", "details": str(e)}), 502
    except Exception as e:
        return jsonify({"error": "Unexpected error", "details": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

