"""Hash utility functions for deterministic feature extraction."""

import hashlib
from typing import Any, List, Dict


def deterministic_string_hash(text: str, algorithm: str = "md5") -> str:
    """
    Generate deterministic hash of a string.
    
    Args:
        text: Input text
        algorithm: Hash algorithm (md5, sha1, sha256)
    
    Returns:
        Hexadecimal hash string
    """
    hasher = hashlib.new(algorithm)
    hasher.update(text.encode('utf-8'))
    return hasher.hexdigest()


def deterministic_list_hash(items: List[Any], algorithm: str = "md5") -> str:
    """
    Generate deterministic hash of a list by sorting and hashing.
    
    Args:
        items: List of items (must be sortable)
        algorithm: Hash algorithm
    
    Returns:
        Hexadecimal hash string
    """
    # Sort items to ensure determinism
    sorted_items = sorted(str(item) for item in items)
    combined = "|".join(sorted_items)
    return deterministic_string_hash(combined, algorithm)


def deterministic_dict_hash(data: Dict[str, Any], algorithm: str = "md5") -> str:
    """
    Generate deterministic hash of a dictionary by sorting keys.
    
    Args:
        data: Dictionary to hash
        algorithm: Hash algorithm
    
    Returns:
        Hexadecimal hash string
    """
    # Sort keys to ensure determinism
    sorted_items = sorted((str(k), str(v)) for k, v in data.items())
    combined = "|".join(f"{k}:{v}" for k, v in sorted_items)
    return deterministic_string_hash(combined, algorithm)


def truncate_hash(hash_str: str, length: int = 8) -> str:
    """
    Truncate hash to specified length.
    
    Args:
        hash_str: Full hash string
        length: Desired length
    
    Returns:
        Truncated hash
    """
    return hash_str[:length]
