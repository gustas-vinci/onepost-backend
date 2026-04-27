import os
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

@app.route("/transcribe", methods=["GET", "POST", "OPTIONS"])
def transcribe():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    if request.method == "GET":
        return jsonify({"status": "transcribe endpoint ready"})
    
    deepgram_key = os.getenv("DEEPGRAM_KEY")
    if not deepgram_key:
        return jsonify({"error": "Missing DEEPGRAM_KEY"}), 500
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    f = request.files["file"]
    content_type = f.mimetype or "application/octet-stream"
    
    try:
        resp = requests.post(
            "https://api.deepgram.com/v1/listen",
            params={"model": "nova-2", "smart_format": "true", "punctuate": "true"},
            headers={"Authorization": f"Token {deepgram_key}", "Content-Type": content_type},
            data=f.stream,
            timeout=180,
        )
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 502
    
    if not resp.ok:
        return jsonify({"error": "Deepgram error", "status": resp.status_code}), 502
    
    try:
        data = resp.json()
        transcript = data["results"]["channels"][0]["alternatives"][0]["transcript"]
    except Exception:
        transcript = ""
    
    return jsonify({"transcript": transcript})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

