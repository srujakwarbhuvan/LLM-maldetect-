"""Base extractor interface."""

from abc import ABC, abstractmethod
from typing import Any, Dict
from pathlib import Path
from loguru import logger


class BaseExtractor(ABC):
    """
    Abstract base class for all feature extractors.
    
    All extractors must implement the extract() method to extract
    features from an APK object provided by androguard.
    """
    
    def __init__(self, name: str):
        """
        Initialize the extractor.
        
        Args:
            name: Name of the extractor
        """
        self.name = name
        self.logger = logger.bind(extractor=name)
    
    @abstractmethod
    def extract(self, apk_obj: Any, apk_path: Path) -> Dict[str, Any]:
        """
        Extract features from an APK.
        
        Args:
            apk_obj: Androguard APK object
            apk_path: Path to the APK file
        
        Returns:
            Dictionary of extracted features
        
        Raises:
            Exception: If extraction fails
        """
        pass
    
    def safe_extract(self, apk_obj: Any, apk_path: Path) -> Dict[str, Any]:
        """
        Safely extract features with error handling.
        
        Args:
            apk_obj: Androguard APK object
            apk_path: Path to the APK file
        
        Returns:
            Dictionary of extracted features (may be partial if errors occur)
        """
        try:
            self.logger.debug(f"Starting extraction for {apk_path.name}")
            features = self.extract(apk_obj, apk_path)
            self.logger.debug(f"Extraction successful for {apk_path.name}")
            return features
        except Exception as e:
            self.logger.error(f"Extraction failed for {apk_path.name}: {e}")
            return self._get_default_features()
    
    def _get_default_features(self) -> Dict[str, Any]:
        """
        Get default/empty features when extraction fails.
        
        Returns:
            Dictionary with default values
        """
        return {}
    
    def __repr__(self) -> str:
        """String representation."""
        return f"{self.__class__.__name__}(name='{self.name}')"
