"""
metadata_utils.py - Extract and analyze metadata from images, PDFs, and other files.
"""

import os
import json
from datetime import datetime


def extract_image_metadata(file_path: str) -> dict:
    """
    Extract EXIF and other metadata from image files.
    
    Returns:
        Dict containing metadata fields and anomaly flags
    """
    metadata = {}
    anomalies = []

    try:
        import exifread
        with open(file_path, "rb") as f:
            tags = exifread.process_file(f, details=True)
        
        for tag, value in tags.items():
            metadata[tag] = str(value)

        # Check for common tampering indicators in EXIF
        software_tag = tags.get("Image Software", None)
        if software_tag:
            software = str(software_tag).lower()
            editing_tools = ["photoshop", "gimp", "lightroom", "affinity", "canva", "paint.net"]
            for tool in editing_tools:
                if tool in software:
                    anomalies.append(f"Image edited with: {str(software_tag)}")
                    break

        # Date inconsistency check
        date_original = tags.get("EXIF DateTimeOriginal")
        date_modified = tags.get("Image DateTime")
        if date_original and date_modified:
            if str(date_original) != str(date_modified):
                anomalies.append(
                    f"Date mismatch: Original={date_original}, Modified={date_modified}"
                )

    except Exception as e:
        metadata["error"] = str(e)

    return {
        "raw_metadata": metadata,
        "anomalies": anomalies,
        "metadata_count": len(metadata),
    }


def extract_pdf_metadata(file_path: str) -> dict:
    """
    Extract metadata from PDF files.
    
    Returns:
        Dict with PDF info and anomaly flags
    """
    metadata = {}
    anomalies = []

    try:
        import PyPDF2
        with open(file_path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            info = reader.metadata

        if info:
            for key, val in info.items():
                metadata[str(key)] = str(val)

        # Check for editing software
        producer = metadata.get("/Producer", "").lower()
        creator = metadata.get("/Creator", "").lower()
        editing_indicators = ["modified", "edited", "acrobat", "nitro", "foxit"]
        for indicator in editing_indicators:
            if indicator in producer or indicator in creator:
                anomalies.append(f"PDF may have been edited. Producer: {metadata.get('/Producer', 'N/A')}")
                break

        # Check creation vs modification date
        creation = metadata.get("/CreationDate", "")
        modification = metadata.get("/ModDate", "")
        if creation and modification and creation != modification:
            anomalies.append(f"PDF modification date differs from creation date.")

        metadata["page_count"] = len(reader.pages)

    except Exception as e:
        metadata["error"] = str(e)

    return {
        "raw_metadata": metadata,
        "anomalies": anomalies,
        "metadata_count": len(metadata),
    }


def get_file_system_metadata(file_path: str) -> dict:
    """
    Get OS-level file metadata (timestamps, permissions).
    """
    stat = os.stat(file_path)
    return {
        "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
        "size_bytes": stat.st_size,
        "permissions": oct(stat.st_mode),
    }


def extract_metadata(file_path: str) -> dict:
    """
    Universal metadata extractor — routes to image or PDF extractor based on extension.
    
    Returns:
        Combined metadata dict
    """
    ext = os.path.splitext(file_path)[1].lower()
    fs_meta = get_file_system_metadata(file_path)

    if ext in [".jpg", ".jpeg", ".png", ".tiff", ".bmp", ".webp"]:
        content_meta = extract_image_metadata(file_path)
    elif ext == ".pdf":
        content_meta = extract_pdf_metadata(file_path)
    else:
        content_meta = {"raw_metadata": {}, "anomalies": [], "metadata_count": 0}

    return {
        "file_system": fs_meta,
        "content": content_meta,
    }
