"""Structural feature extractor."""

from typing import Any, Dict
from pathlib import Path
from apk_extractor.extractors.base import BaseExtractor
from apk_extractor.models.features import StructuralFeatures, CodeStructureFeatures, ResourceFeatures, CertificateFeatures
import zipfile
import math


class StructuralExtractor(BaseExtractor):
    """Extract structural and size-based features from APK."""
    
    def __init__(self):
        """Initialize structural extractor."""
        super().__init__(name="StructuralExtractor")
    
    def extract(self, apk_obj: Any, apk_path: Path) -> Dict[str, Any]:
        """
        Extract structural features from APK.
        
        Args:
            apk_obj: Androguard APK object
            apk_path: Path to APK file
        
        Returns:
            Dictionary containing structural, code, resource, and certificate features
        """
        self.logger.info(f"Extracting structural features from {apk_path.name}")
        
        # Extract all feature categories
        structural = self._extract_structural(apk_obj, apk_path)
        code_structure = self._extract_code_structure(apk_obj)
        resources = self._extract_resources(apk_obj)
        certificate = self._extract_certificate(apk_obj)
        
        return {
            'structural': structural,
            'code_structure': code_structure,
            'resources': resources,
            'certificate': certificate,
        }
    
    def _extract_structural(self, apk_obj: Any, apk_path: Path) -> StructuralFeatures:
        """Extract size and compression features."""
        # APK file size
        apk_size_bytes = apk_path.stat().st_size
        apk_size_mb = apk_size_bytes / (1024 * 1024)
        
        # Get sizes of internal components
        dex_size = 0
        resources_size = 0
        assets_size = 0
        lib_size = 0
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for info in zf.filelist:
                    if info.filename.endswith('.dex'):
                        dex_size += info.file_size
                    elif info.filename.startswith('res/'):
                        resources_size += info.file_size
                    elif info.filename.startswith('assets/'):
                        assets_size += info.file_size
                    elif info.filename.startswith('lib/'):
                        lib_size += info.file_size
                
                # Calculate compression ratio
                total_uncompressed = sum(info.file_size for info in zf.filelist)
                compression_ratio = apk_size_bytes / total_uncompressed if total_uncompressed > 0 else 0
        except Exception as e:
            self.logger.warning(f"Error analyzing ZIP structure: {e}")
            compression_ratio = 0
        
        # Calculate ratios
        dex_to_apk_ratio = dex_size / apk_size_bytes if apk_size_bytes > 0 else 0
        resources_to_apk_ratio = resources_size / apk_size_bytes if apk_size_bytes > 0 else 0
        
        return StructuralFeatures(
            apk_size_bytes=apk_size_bytes,
            apk_size_mb=round(apk_size_mb, 2),
            dex_size_bytes=dex_size,
            resources_size_bytes=resources_size,
            assets_size_bytes=assets_size,
            lib_size_bytes=lib_size,
            compression_ratio=round(compression_ratio, 4),
            dex_to_apk_ratio=round(dex_to_apk_ratio, 4),
            resources_to_apk_ratio=round(resources_to_apk_ratio, 4),
        )
    
    def _extract_code_structure(self, apk_obj: Any) -> CodeStructureFeatures:
        """Extract code structure metrics."""
        num_classes = 0
        num_methods = 0
        num_strings = 0
        num_dex_files = 0
        
        class_names = []
        method_names = []
        
        try:
            # Try to import DEX parser (handles both legacy and new androguard)
            try:
                from androguard.core.bytecodes.dvm import DalvikVMFormat
            except ImportError:
                from androguard.core.dex import DEX as DalvikVMFormat
            
            # Method 1: Using get_all_dex() (returns bytes)
            dex_contents = []
            try:
                for dex in apk_obj.get_all_dex():
                    dex_contents.append(dex)
            except Exception as e:
                self.logger.debug(f"get_all_dex() failed: {e}")
            
            # Method 2: If Method 1 failed, try get_dex()
            if not dex_contents:
                try:
                    dex = apk_obj.get_dex()
                    if dex:
                        dex_contents.append(dex)
                except Exception as e:
                    self.logger.debug(f"get_dex() failed: {e}")
            
            # Method 3: Fallback - manual file iteration
            if not dex_contents:
                try:
                    for filename in apk_obj.get_files():
                        if filename.endswith('.dex'):
                            dex_contents.append(apk_obj.get_file(filename))
                except Exception as e:
                    self.logger.debug(f"Manual file iteration failed: {e}")
            
            num_dex_files = len(dex_contents)
            
            if dex_contents:
                for i, dex_bytes in enumerate(dex_contents):
                    try:
                        if not dex_bytes:
                            continue
                            
                        d = DalvikVMFormat(dex_bytes)
                        
                        # Count classes
                        classes = d.get_classes()
                        num_classes += len(classes)
                        
                        # Collect class names for entropy calculation
                        class_names.extend([c.get_name() for c in classes])
                        
                        # Count methods and strings
                        for cls in classes:
                            methods = cls.get_methods()
                            num_methods += len(methods)
                            method_names.extend([m.get_name() for m in methods])
                        
                        # Count strings
                        strings = d.get_strings()
                        num_strings += len(strings)
                        
                    except Exception as e:
                        self.logger.warning(f"Error analyzing DEX file #{i}: {e}")
                        continue
        
        except Exception as e:
            self.logger.warning(f"Error analyzing code structure: {e}")
        
        # Calculate obfuscation indicators
        avg_class_name_length = (
            sum(len(name) for name in class_names) / len(class_names)
            if class_names else 0
        )
        
        avg_method_name_length = (
            sum(len(name) for name in method_names) / len(method_names)
            if method_names else 0
        )
        
        class_name_entropy = self._calculate_entropy(class_names)
        method_name_entropy = self._calculate_entropy(method_names)
        
        # Check for reflection usage (simplified)
        uses_reflection = any('reflect' in name.lower() for name in method_names[:1000]) if method_names else False
        reflection_count = sum(1 for name in method_names if 'reflect' in name.lower()) if method_names else 0
        
        return CodeStructureFeatures(
            num_classes=num_classes,
            num_methods=num_methods,
            num_strings=num_strings,
            num_dex_files=num_dex_files,
            avg_class_name_length=round(avg_class_name_length, 2),
            avg_method_name_length=round(avg_method_name_length, 2),
            class_name_entropy=round(class_name_entropy, 4),
            method_name_entropy=round(method_name_entropy, 4),
            uses_reflection=uses_reflection,
            reflection_count=reflection_count,
        )
    
    def _extract_resources(self, apk_obj: Any) -> ResourceFeatures:
        """Extract resource features."""
        files = apk_obj.get_files()
        
        num_assets = sum(1 for f in files if f.startswith('assets/'))
        num_raw_resources = sum(1 for f in files if f.startswith('res/raw/'))
        num_drawable_resources = sum(1 for f in files if f.startswith('res/drawable'))
        num_layout_resources = sum(1 for f in files if f.startswith('res/layout/'))
        num_xml_resources = sum(1 for f in files if f.endswith('.xml'))
        
        # Native libraries
        lib_files = [f for f in files if f.startswith('lib/')]
        num_native_libs = len([f for f in lib_files if f.endswith('.so')])
        
        has_arm_libs = any('armeabi' in f for f in lib_files)
        has_x86_libs = any('x86/' in f and 'x86_64' not in f for f in lib_files)
        has_arm64_libs = any('arm64' in f for f in lib_files)
        has_x86_64_libs = any('x86_64' in f for f in lib_files)
        
        return ResourceFeatures(
            num_assets=num_assets,
            num_raw_resources=num_raw_resources,
            num_drawable_resources=num_drawable_resources,
            num_layout_resources=num_layout_resources,
            num_xml_resources=num_xml_resources,
            num_native_libs=num_native_libs,
            has_arm_libs=has_arm_libs,
            has_x86_libs=has_x86_libs,
            has_arm64_libs=has_arm64_libs,
            has_x86_64_libs=has_x86_64_libs,
            total_files=len(files),
        )
    
    def _extract_certificate(self, apk_obj: Any) -> CertificateFeatures:
        """Extract certificate features."""
        try:
            # Get certificate
            certs = apk_obj.get_certificates()
            
            if not certs:
                return CertificateFeatures(is_signed=False)
            
            # Use first certificate
            cert = certs[0]
            
            # Check if self-signed
            is_self_signed = cert.issuer == cert.subject
            
            # Get signature algorithm
            signature_algorithm = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else None
            
            # Calculate validity
            validity_days = (cert.not_valid_after - cert.not_valid_before).days
            
            # Check if expired
            from datetime import datetime, timezone
            is_expired = cert.not_valid_after < datetime.now(timezone.utc)
            
            # Hash issuer and subject for privacy
            from apk_extractor.utils.hash_utils import deterministic_string_hash
            issuer_hash = deterministic_string_hash(str(cert.issuer))[:16]
            subject_hash = deterministic_string_hash(str(cert.subject))[:16]
            
            # Get key size
            key_size = cert.public_key().key_size if hasattr(cert.public_key(), 'key_size') else None
            
            return CertificateFeatures(
                is_signed=True,
                is_self_signed=is_self_signed,
                signature_algorithm=signature_algorithm,
                validity_days=validity_days,
                is_expired=is_expired,
                issuer_hash=issuer_hash,
                subject_hash=subject_hash,
                key_size=key_size,
            )
        
        except Exception as e:
            self.logger.warning(f"Error extracting certificate features: {e}")
            return CertificateFeatures(is_signed=False)
    
    def _calculate_entropy(self, strings: list) -> float:
        """Calculate Shannon entropy of strings."""
        if not strings:
            return 0.0
        
        # Combine all strings
        combined = ''.join(strings)
        
        if not combined:
            return 0.0
        
        # Calculate character frequency
        freq = {}
        for char in combined:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(combined)
        
        for count in freq.values():
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)
        
        return entropy
