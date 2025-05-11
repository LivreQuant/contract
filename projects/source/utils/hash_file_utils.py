# utils/hash_utils.py
import hashlib
import logging
from pathlib import Path
from typing import Union

logger = logging.getLogger(__name__)


def calculate_file_hash(file_path: Union[str, Path], algorithm: str = "sha256") -> str:
    """
    Calculate cryptographic hash of a file.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use ('sha256', 'sha512', etc.)

    Returns:
        Hex digest of the hash
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if not file_path.is_file():
        raise ValueError(f"Not a file: {file_path}")

    try:
        hash_func = getattr(hashlib, algorithm)()
    except AttributeError:
        logger.error(f"Unsupported hash algorithm: {algorithm}")
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    try:
        with open(file_path, "rb") as f:
            # Read and update hash in chunks for larger files
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)

        return hash_func.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hash for {file_path}: {e}")
        raise
