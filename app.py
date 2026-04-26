import os

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS

load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})


def _extract_transcript(deepgram_json: dict) -> str | None:
    # Deepgram v1 listen response shape: results.channels[0].alternatives[0].transcript
    try:
        return (
            deepgram_json["results"]["channels"][0]["alternatives"][0]["transcript"]
            or None
        )
    except Exception:
        return None


@app.post("/transcribe")
def transcribe():
    deepgram_key = os.getenv("DEEPGRAM_KEY")
    if not deepgram_key:
        return (
            jsonify(
                {
                    "error": "Missing DEEPGRAM_KEY environment variable.",
                    "hint": "Set DEEPGRAM_KEY in your environment (or Render env vars).",
                }
            ),
            500,
        )

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded. Use multipart form field 'file'."}), 400

    f = request.files["file"]
    if not f or not f.filename:
        return jsonify({"error": "Empty upload."}), 400

    content_type = f.mimetype or "application/octet-stream"

    deepgram_url = "https://api.deepgram.com/v1/listen"
    params = {
        "model": "nova-2",
        "smart_format": "true",
        "punctuate": "true",
        "diarize": "false",
    }

    try:
        resp = requests.post(
            deepgram_url,
            params=params,
            headers={
                "Authorization": f"Token {deepgram_key}",
                "Content-Type": content_type,
            },
            data=f.stream,
            timeout=180,
        )
    except requests.RequestException as e:
        return jsonify({"error": "Deepgram request failed.", "details": str(e)}), 502

    if not resp.ok:
        return (
            jsonify(
                {
                    "error": "Deepgram returned an error.",
                    "status_code": resp.status_code,
                    "response": _safe_json(resp),
                }
            ),
            502,
        )

    deepgram_json = _safe_json(resp)
    transcript = _extract_transcript(deepgram_json) if isinstance(deepgram_json, dict) else None

    return jsonify({"transcript": transcript})


def _safe_json(resp: requests.Response):
    try:
        return resp.json()
    except Exception:
        return {"raw": resp.text}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

