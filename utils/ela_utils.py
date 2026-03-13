"""
ela_utils.py - Error Level Analysis (ELA) for detecting image tampering.

ELA works by re-saving a JPEG image at a known quality and comparing it to 
the original. Tampered regions show different error levels than untampered areas.
"""

import os
import tempfile
import numpy as np
from PIL import Image


def perform_ela(file_path: str, quality: int = 90, scale: int = 10) -> dict:
    """
    Perform Error Level Analysis on an image.
    
    Args:
        file_path: Path to the image file
        quality: JPEG recompression quality (default 90)
        scale: Amplification scale for visualization (default 10)
    
    Returns:
        Dict with ELA results, statistics, and tamper probability
    """
    result = {
        "ela_performed": False,
        "tamper_probability": 0.0,
        "mean_error": 0.0,
        "max_error": 0.0,
        "std_error": 0.0,
        "suspicious_regions": False,
        "ela_image_path": None,
        "error": None,
    }

    try:
        original = Image.open(file_path).convert("RGB")
        
        # Re-save at known quality
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
            tmp_path = tmp.name
        
        original.save(tmp_path, "JPEG", quality=quality)
        recompressed = Image.open(tmp_path).convert("RGB")

        # Compute pixel-level difference
        orig_array = np.array(original, dtype=np.float32)
        recomp_array = np.array(recompressed, dtype=np.float32)
        ela_array = np.abs(orig_array - recomp_array)

        # Scale for visualization
        ela_scaled = np.clip(ela_array * scale, 0, 255).astype(np.uint8)
        ela_image = Image.fromarray(ela_scaled)

        # Save ELA result image
        ela_output_path = file_path.replace("uploads", "uploads/ela_") 
        ela_output_path = os.path.join(
            os.path.dirname(file_path),
            "ela_" + os.path.basename(file_path).replace(".png", ".jpg").replace(".jpeg", ".jpg")
        )
        ela_image.save(ela_output_path, "JPEG")

        # Compute statistics
        mean_err = float(np.mean(ela_array))
        max_err = float(np.max(ela_array))
        std_err = float(np.std(ela_array))

        # Heuristic tamper probability
        # High mean error or std suggests inconsistent compression = tampering
        tamper_prob = min(100.0, (mean_err * 2.5) + (std_err * 1.5))
        suspicious = tamper_prob > 25.0 or std_err > 15.0

        # Cleanup temp file
        os.remove(tmp_path)

        result.update({
            "ela_performed": True,
            "tamper_probability": round(tamper_prob, 2),
            "mean_error": round(mean_err, 4),
            "max_error": round(max_err, 4),
            "std_error": round(std_err, 4),
            "suspicious_regions": suspicious,
            "ela_image_path": ela_output_path,
        })

    except Exception as e:
        result["error"] = str(e)

    return result


def analyze_color_distribution(file_path: str) -> dict:
    """
    Analyze color channel statistics to detect cloning or splicing artifacts.
    
    Returns:
        Dict with per-channel stats and anomaly flags
    """
    result = {"channels": {}, "anomalies": []}
    
    try:
        img = Image.open(file_path).convert("RGB")
        arr = np.array(img, dtype=np.float32)

        channel_names = ["red", "green", "blue"]
        stats = {}

        for i, name in enumerate(channel_names):
            ch = arr[:, :, i]
            stats[name] = {
                "mean": round(float(np.mean(ch)), 3),
                "std": round(float(np.std(ch)), 3),
                "min": int(np.min(ch)),
                "max": int(np.max(ch)),
            }

        result["channels"] = stats

        # Flag extreme uniformity (possible cloning)
        for name, s in stats.items():
            if s["std"] < 5.0:
                result["anomalies"].append(
                    f"{name.capitalize()} channel unusually uniform (std={s['std']}) — possible cloning."
                )

    except Exception as e:
        result["error"] = str(e)

    return result


def full_ela_analysis(file_path: str) -> dict:
    """
    Run complete ELA + color distribution analysis.
    
    Returns:
        Combined analysis dict
    """
    ela = perform_ela(file_path)
    color = analyze_color_distribution(file_path)

    all_anomalies = list(color.get("anomalies", []))
    if ela.get("suspicious_regions"):
        all_anomalies.append(
            f"ELA detected suspicious regions (tamper probability: {ela['tamper_probability']}%)"
        )

    return {
        "ela": ela,
        "color_analysis": color,
        "all_anomalies": all_anomalies,
        "overall_suspicious": len(all_anomalies) > 0,
    }
