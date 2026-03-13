"""
hash_utils.py - File hashing and integrity verification utilities
"""

import hashlib
import os


def compute_hash(file_path: str, algorithm: str = "sha256") -> str:
    """
    Compute cryptographic hash of a file.
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm ('md5', 'sha1', 'sha256', 'sha512')
    
    Returns:
        Hex digest string
    """
    hash_func = hashlib.new(algorithm)
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()


def compute_multiple_hashes(file_path: str) -> dict:
    """
    Compute multiple hashes for a file at once.
    
    Returns:
        Dict with md5, sha1, sha256, sha512 hashes
    """
    hashes = {alg: hashlib.new(alg) for alg in ["md5", "sha1", "sha256", "sha512"]}
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            for h in hashes.values():
                h.update(chunk)
    
    return {alg: h.hexdigest() for alg, h in hashes.items()}


def verify_hash(file_path: str, expected_hash: str, algorithm: str = "sha256") -> bool:
    """
    Verify a file's hash matches an expected value.
    
    Returns:
        True if hash matches, False otherwise
    """
    actual_hash = compute_hash(file_path, algorithm)
    return actual_hash.lower() == expected_hash.lower()


def get_file_size(file_path: str) -> int:
    """Return file size in bytes."""
    return os.path.getsize(file_path)


def get_file_info(file_path: str) -> dict:
    """
    Get complete file info including size and all hashes.
    
    Returns:
        Dict with filename, size, and hash values
    """
    stat = os.stat(file_path)
    hashes = compute_multiple_hashes(file_path)
    
    return {
        "filename": os.path.basename(file_path),
        "size_bytes": stat.st_size,
        "size_kb": round(stat.st_size / 1024, 2),
        "hashes": hashes,
    }
