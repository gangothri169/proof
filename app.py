"""
app.py - VeriProof-AI: Digital Evidence Authenticity Verification System

A Flask web application that uses multiple techniques to detect tampered or
forged digital evidence (images, PDFs, videos).
"""

import os
import json
import uuid
from flask import Flask, render_template, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

from utils.hash_utils import get_file_info
from utils.metadata_utils import extract_metadata
from utils.ela_utils import full_ela_analysis

# ──────────────────────────── App Configuration ─────────────────────────────

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "veriproof-secret-key-2024")
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB max upload

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "bmp", "tiff", "webp", "pdf"}

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# ──────────────────────────── Helper Functions ───────────────────────────────

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def compute_verdict(analysis: dict) -> dict:
    """
    Compute an overall authenticity verdict from all analysis results.
    
    Returns:
        Dict with verdict, confidence, and risk_level
    """
    risk_score = 0
    risk_factors = []

    # Metadata anomalies
    meta_anomalies = analysis.get("metadata", {}).get("content", {}).get("anomalies", [])
    risk_score += len(meta_anomalies) * 20
    risk_factors.extend(meta_anomalies)

    # ELA analysis (images only)
    ela = analysis.get("ela", {}).get("ela", {})
    if ela.get("ela_performed"):
        tamper_prob = ela.get("tamper_probability", 0)
        risk_score += tamper_prob * 0.5
        if ela.get("suspicious_regions"):
            risk_factors.append(f"ELA detected tampering (probability: {tamper_prob}%)")

    ela_anomalies = analysis.get("ela", {}).get("all_anomalies", [])
    risk_factors.extend([a for a in ela_anomalies if a not in risk_factors])

    # Determine verdict
    risk_score = min(100, risk_score)

    if risk_score < 20:
        verdict = "LIKELY AUTHENTIC"
        risk_level = "LOW"
        color = "green"
    elif risk_score < 50:
        verdict = "SUSPICIOUS"
        risk_level = "MEDIUM"
        color = "orange"
    else:
        verdict = "LIKELY TAMPERED"
        risk_level = "HIGH"
        color = "red"

    return {
        "verdict": verdict,
        "risk_level": risk_level,
        "risk_score": round(risk_score, 1),
        "color": color,
        "risk_factors": risk_factors,
        "confidence": f"{100 - risk_score:.0f}% authentic confidence",
    }


# ──────────────────────────── Routes ─────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main UI page."""
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Main analysis endpoint.
    
    Accepts a file upload, runs all verification checks, and returns a JSON report.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    if not allowed_file(file.filename):
        return jsonify({
            "error": f"File type not supported. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        }), 400

    # Save file securely
    filename = secure_filename(file.filename)
    unique_name = f"{uuid.uuid4().hex}_{filename}"
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
    file.save(file_path)

    try:
        analysis = {}
        ext = filename.rsplit(".", 1)[1].lower()

        # 1. Hash & file info
        analysis["file_info"] = get_file_info(file_path)
        analysis["file_info"]["original_filename"] = filename

        # 2. Metadata extraction
        analysis["metadata"] = extract_metadata(file_path)

        # 3. ELA (images only)
        if ext in {"jpg", "jpeg", "png", "bmp", "tiff", "webp", "gif"}:
            analysis["ela"] = full_ela_analysis(file_path)
        else:
            analysis["ela"] = {
                "message": "ELA not applicable for this file type",
                "all_anomalies": [],
                "overall_suspicious": False,
            }

        # 4. Compute final verdict
        analysis["verdict"] = compute_verdict(analysis)

        return jsonify({
            "status": "success",
            "analysis": analysis,
        })

    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500

    finally:
        # Clean up uploaded file after analysis (optional — remove if you want to keep files)
        pass


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    """Serve files from uploads folder (e.g., ELA images)."""
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/health")
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok", "service": "VeriProof-AI"})


# ──────────────────────────── Main ───────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print("  VeriProof-AI — Digital Evidence Verifier")
    print("  Running at http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, host="0.0.0.0", port=5000)
