"""Main APK feature extraction pipeline."""

from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime
import pandas as pd
from loguru import logger
from tqdm import tqdm

from androguard.core.apk import APK

from apk_extractor.extractors import (
    ManifestExtractor,
    PermissionExtractor,
    APIExtractor,
    StructuralExtractor,
)
from apk_extractor.models.features import APKFeatures
from apk_extractor.pipeline.validator import APKValidator
from apk_extractor.utils.file_utils import compute_file_hash
from apk_extractor.utils.logging_config import setup_logging


class APKFeatureExtractor:
   
    
    def __init__(
        self,
        log_level: str = "INFO",
        log_file: Optional[Path] = None,
    ):
        """
        Initialize the feature extractor.
        
        Args:
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
            log_file: Optional path to log file
        """
        # Setup logging
        setup_logging(log_level=log_level, log_file=log_file)
        self.logger = logger.bind(component="APKFeatureExtractor")
        
        # Initialize validator
        self.validator = APKValidator()
        
        # Initialize extractors
        self.extractors = {
            'manifest': ManifestExtractor(),
            'permission': PermissionExtractor(),
            'api': APIExtractor(),
            'structural': StructuralExtractor(),
        }
        
        self.logger.info("APK Feature Extractor initialized")
    
    def extract(self, apk_path: Path) -> Optional[APKFeatures]:
        """
        Extract features from a single APK file.
        
        Args:
            apk_path: Path to APK file
        
        Returns:
            APKFeatures object or None if extraction failed
        """
        self.logger.info(f"Starting extraction for {apk_path.name}")
        
        # Convert to Path object
        apk_path = Path(apk_path)
        
        # Validate APK
        is_valid, error_msg = self.validator.validate(apk_path)
        if not is_valid:
            self.logger.error(f"Validation failed: {error_msg}")
            return None
        
        # Compute APK hash
        apk_hash = compute_file_hash(apk_path, algorithm="sha256")
        
        # Load APK with androguard
        try:
            apk_obj = APK(str(apk_path))
        except Exception as e:
            self.logger.error(f"Failed to load APK with androguard: {e}")
            return None
        
        # Track errors and warnings
        errors = []
        warnings = []
        
        # Extract manifest features
        try:
            manifest_features = self.extractors['manifest'].extract(apk_obj, apk_path)
        except Exception as e:
            self.logger.error(f"Manifest extraction failed: {e}")
            errors.append(f"Manifest extraction failed: {e}")
            return None
        
        # Extract permission features
        try:
            permission_features = self.extractors['permission'].extract(apk_obj, apk_path)
        except Exception as e:
            self.logger.error(f"Permission extraction failed: {e}")
            errors.append(f"Permission extraction failed: {e}")
            # Continue with empty permissions
            from apk_extractor.models.features import PermissionFeatures
            permission_features = PermissionFeatures()
        
        # Extract API features
        try:
            api_features = self.extractors['api'].extract(apk_obj, apk_path)
        except Exception as e:
            self.logger.warning(f"API extraction failed: {e}")
            warnings.append(f"API extraction failed: {e}")
            from apk_extractor.models.features import APICallFeatures
            api_features = APICallFeatures()
        
        # Extract structural features
        try:
            structural_dict = self.extractors['structural'].extract(apk_obj, apk_path)
            structural_features = structural_dict['structural']
            code_features = structural_dict['code_structure']
            resource_features = structural_dict['resources']
            cert_features = structural_dict['certificate']
        except Exception as e:
            self.logger.error(f"Structural extraction failed: {e}")
            errors.append(f"Structural extraction failed: {e}")
            # Use defaults
            from apk_extractor.models.features import (
                StructuralFeatures, CodeStructureFeatures,
                ResourceFeatures, CertificateFeatures
            )
            structural_features = StructuralFeatures(
                apk_size_bytes=apk_path.stat().st_size,
                apk_size_mb=apk_path.stat().st_size / (1024 * 1024)
            )
            code_features = CodeStructureFeatures()
            resource_features = ResourceFeatures()
            cert_features = CertificateFeatures()
        
        # Assemble complete feature set
        apk_features = APKFeatures(
            apk_hash=apk_hash,
            apk_filename=apk_path.name,
            extraction_timestamp=datetime.utcnow(),
            manifest=manifest_features,
            permissions=permission_features,
            api_calls=api_features,
            code_structure=code_features,
            resources=resource_features,
            certificate=cert_features,
            structural=structural_features,
            extraction_success=len(errors) == 0,
            extraction_errors=errors,
            extraction_warnings=warnings,
        )
        
        self.logger.info(f"Extraction completed for {apk_path.name}")
        return apk_features
    
    def batch_extract(
        self,
        apk_dir: Path,
        output_file: Optional[Path] = None,
        output_format: str = "csv",
        workers: int = 1,
    ) -> List[APKFeatures]:
        """
        Extract features from multiple APK files.
        
        Args:
            apk_dir: Directory containing APK files
            output_file: Optional output file path
            output_format: Output format (csv, json, parquet)
            workers: Number of parallel workers (currently unused, future enhancement)
        
        Returns:
            List of APKFeatures objects
        """
        self.logger.info(f"Starting batch extraction from {apk_dir}")
        
        apk_dir = Path(apk_dir)
        
        # Find all APK files
        apk_files = list(apk_dir.glob("*.apk"))
        self.logger.info(f"Found {len(apk_files)} APK files")
        
        if not apk_files:
            self.logger.warning("No APK files found")
            return []
        
        # Extract features from each APK
        results = []
        failed_count = 0
        
        for apk_path in tqdm(apk_files, desc="Extracting features"):
            try:
                features = self.extract(apk_path)
                if features:
                    results.append(features)
                else:
                    failed_count += 1
            except Exception as e:
                self.logger.error(f"Unexpected error processing {apk_path.name}: {e}")
                failed_count += 1
        
        self.logger.info(
            f"Batch extraction completed: {len(results)} successful, {failed_count} failed"
        )
        
        # Save results if output file specified
        if output_file and results:
            self.save_results(results, output_file, output_format)
        
        return results
    
    def save_results(
        self,
        results: List[APKFeatures],
        output_file: Path,
        output_format: str = "csv",
    ) -> None:
        """
        Save extraction results to file.
        
        Args:
            results: List of APKFeatures objects
            output_file: Output file path
            output_format: Output format (csv, json, parquet)
        """
        self.logger.info(f"Saving {len(results)} results to {output_file}")
        
        output_file = Path(output_file)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        if output_format == "csv":
            self._save_csv(results, output_file)
        elif output_format == "json":
            self._save_json(results, output_file)
        elif output_format == "parquet":
            self._save_parquet(results, output_file)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
        
        self.logger.info(f"Results saved to {output_file}")
    
    def _save_csv(self, results: List[APKFeatures], output_file: Path) -> None:
        """Save results as CSV."""
        # Convert to flat dictionaries
        data = [r.to_flat_dict() for r in results]
        
        # Create DataFrame
        df = pd.DataFrame(data)
        
        # Save to CSV
        df.to_csv(output_file, index=False)
    
    def _save_json(self, results: List[APKFeatures], output_file: Path) -> None:
        """Save results as JSON."""
        import json
        
        # Convert to dictionaries
        data = [r.model_dump() for r in results]
        
        # Save to JSON
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    def _save_parquet(self, results: List[APKFeatures], output_file: Path) -> None:
        """Save results as Parquet."""
        # Convert to flat dictionaries
        data = [r.to_flat_dict() for r in results]
        
        # Create DataFrame
        df = pd.DataFrame(data)
        
        # Save to Parquet
        df.to_parquet(output_file, index=False, engine='pyarrow')
