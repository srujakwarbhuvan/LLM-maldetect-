"""APK validator - validates APK files before extraction."""

from pathlib import Path
from typing import Tuple
from loguru import logger
from apk_extractor.utils.file_utils import validate_apk_file


class APKValidator:
    """Validates APK files before feature extraction."""
    
    def __init__(self):
        """Initialize validator."""
        self.logger = logger.bind(component="APKValidator")
    
    def validate(self, apk_path: Path) -> Tuple[bool, str]:
        """
        Validate an APK file.
        
        Args:
            apk_path: Path to APK file
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        self.logger.debug(f"Validating {apk_path}")
        
        # Check if file exists
        if not apk_path.exists():
            return False, f"File does not exist: {apk_path}"
        
        # Check if it's a file
        if not apk_path.is_file():
            return False, f"Path is not a file: {apk_path}"
        
        # Check file size (minimum 1KB)
        size = apk_path.stat().st_size
        if size < 1024:
            return False, f"File too small ({size} bytes): {apk_path}"
        
        # Check if file is too large (>500MB warning)
        if size > 500 * 1024 * 1024:
            self.logger.warning(f"Large APK file ({size / 1024 / 1024:.1f} MB): {apk_path}")
        
        # Check magic bytes (ZIP signature)
        try:
            with open(apk_path, "rb") as f:
                magic = f.read(4)
                if magic[:2] != b'PK':
                    return False, f"Invalid APK magic bytes: {apk_path}"
        except Exception as e:
            return False, f"Error reading file: {e}"
        
        # Try to load with androguard
        try:
            from androguard.core.apk import APK
            apk = APK(str(apk_path))
            
# Try to get package name (validates manifest)
            package = apk.get_package()
            if not package:
                return False, "APK has no package name"
        
        except Exception as e:
            return False, f"Invalid APK structure: {e}"
        
        self.logger.debug(f"Validation successful: {apk_path}")
        return True, ""
