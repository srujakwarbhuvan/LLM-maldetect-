"""File utility functions."""

import hashlib
import xxhash
from pathlib import Path
from typing import Optional
from loguru import logger


def compute_file_hash(
    file_path: Path,
    algorithm: str = "sha256",
    chunk_size: int = 8192
) -> str:
    """
    Compute hash of a file.
    
    Args:
        file_path: Path to file
        algorithm: Hash algorithm (sha256, md5, xxh64)
        chunk_size: Chunk size for reading file
    
    Returns:
        Hexadecimal hash string
    """
    if algorithm == "xxh64":
        hasher = xxhash.xxh64()
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest()
    else:
        hasher = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest()


def validate_apk_file(file_path: Path) -> bool:
    """
    Validate that a file is a valid APK.
    
    Args:
        file_path: Path to APK file
    
    Returns:
        True if valid APK, False otherwise
    """
    if not file_path.exists():
        logger.error(f"File does not exist: {file_path}")
        return False
    
    if not file_path.is_file():
        logger.error(f"Path is not a file: {file_path}")
        return False
    
    # Check file extension
    if file_path.suffix.lower() != ".apk":
        logger.warning(f"File does not have .apk extension: {file_path}")
        # Don't return False, as some APKs may have different extensions
    
    # Check file size (APKs should be at least a few KB)
    if file_path.stat().st_size < 1024:
        logger.error(f"File too small to be a valid APK: {file_path}")
        return False
    
    # Check magic bytes (ZIP header: PK\x03\x04)
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
            if magic[:2] != b'PK':
                logger.error(f"Invalid APK magic bytes: {file_path}")
                return False
    except Exception as e:
        logger.error(f"Error reading file: {file_path}, {e}")
        return False
    
    return True


def ensure_directory(directory: Path) -> None:
    """
    Ensure a directory exists, creating it if necessary.
    
    Args:
        directory: Path to directory
    """
    directory.mkdir(parents=True, exist_ok=True)


def get_file_size(file_path: Path) -> int:
    """
    Get file size in bytes.
    
    Args:
        file_path: Path to file
    
    Returns:
        File size in bytes
    """
    return file_path.stat().st_size


def safe_filename(filename: str, max_length: int = 255) -> str:
    """
    Create a safe filename by removing invalid characters.
    
    Args:
        filename: Original filename
        max_length: Maximum filename length
    
    Returns:
        Safe filename
    """
    # Remove invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Truncate if too long
    if len(filename) > max_length:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        max_name_len = max_length - len(ext) - 1
        filename = f"{name[:max_name_len]}.{ext}" if ext else name[:max_length]
    
    return filename
