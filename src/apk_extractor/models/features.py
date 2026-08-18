"""Pydantic models for feature data structures."""

from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_validator
from datetime import datetime


class ManifestFeatures(BaseModel):
    """Features extracted from AndroidManifest.xml."""
    
    package_name: str
    version_code: int
    version_name: str
    min_sdk_version: int
    target_sdk_version: int
    max_sdk_version: Optional[int] = None
    
    # Component counts
    num_activities: int = 0
    num_services: int = 0
    num_receivers: int = 0
    num_providers: int = 0
    
    # Exported components
    num_exported_activities: int = 0
    num_exported_services: int = 0
    num_exported_receivers: int = 0
    num_exported_providers: int = 0
    
    # Permissions
    num_permissions: int = 0
    num_dangerous_permissions: int = 0
    num_normal_permissions: int = 0
    num_custom_permissions: int = 0
    
    # Features
    num_features: int = 0
    num_required_features: int = 0
    
    # Intent filters
    num_intent_filters: int = 0
    
    # Flags
    has_main_activity: bool = False
    uses_native_code: bool = False
    debuggable: bool = False
    allow_backup: bool = True
    test_only: bool = False


class PermissionFeatures(BaseModel):
    """Binary feature vector for Android permissions."""
    
    # This will be populated dynamically with permission flags
    # Format: perm_<PERMISSION_NAME> = 1 or 0
    permissions: Dict[str, int] = Field(default_factory=dict)
    
    # Aggregated counts
    total_permissions: int = 0
    dangerous_count: int = 0
    normal_count: int = 0
    signature_count: int = 0
    custom_count: int = 0


class APICallFeatures(BaseModel):
    """Features for sensitive API calls."""
    
    # This will be populated dynamically with API flags
    # Format: api_<API_NAME> = 1 or 0
    api_calls: Dict[str, int] = Field(default_factory=dict)
    
    # Aggregated counts
    total_sensitive_api_calls: int = 0
    sms_api_count: int = 0
    location_api_count: int = 0
    camera_api_count: int = 0
    network_api_count: int = 0
    crypto_api_count: int = 0
    reflection_api_count: int = 0
    dynamic_loading_api_count: int = 0


class CodeStructureFeatures(BaseModel):
    """Features related to code structure."""
    
    num_classes: int = 0
    num_methods: int = 0
    num_strings: int = 0
    num_dex_files: int = 0
    
    # Obfuscation indicators
    avg_class_name_length: float = 0.0
    avg_method_name_length: float = 0.0
    class_name_entropy: float = 0.0
    method_name_entropy: float = 0.0
    
    # Reflection usage
    uses_reflection: bool = False
    reflection_count: int = 0


class ResourceFeatures(BaseModel):
    """Features related to APK resources."""
    
    num_assets: int = 0
    num_raw_resources: int = 0
    num_drawable_resources: int = 0
    num_layout_resources: int = 0
    num_xml_resources: int = 0
    
    # Native libraries
    num_native_libs: int = 0
    has_arm_libs: bool = False
    has_x86_libs: bool = False
    has_arm64_libs: bool = False
    has_x86_64_libs: bool = False
    
    # File counts
    total_files: int = 0


class CertificateFeatures(BaseModel):
    """Features from APK signing certificate."""
    
    is_signed: bool = False
    is_self_signed: bool = False
    
    # Algorithm
    signature_algorithm: Optional[str] = None
    
    # Validity
    validity_days: Optional[int] = None
    is_expired: bool = False
    
    # Issuer/Subject
    issuer_hash: Optional[str] = None
    subject_hash: Optional[str] = None
    
    # Key info
    key_size: Optional[int] = None


class StructuralFeatures(BaseModel):
    """Structural and size-based features."""
    
    apk_size_bytes: int
    apk_size_mb: float
    
    dex_size_bytes: int = 0
    resources_size_bytes: int = 0
    assets_size_bytes: int = 0
    lib_size_bytes: int = 0
    
    compression_ratio: float = 0.0
    
    # Ratios
    dex_to_apk_ratio: float = 0.0
    resources_to_apk_ratio: float = 0.0


class APKFeatures(BaseModel):
    """Complete feature set for an APK."""
    
    # Metadata
    apk_hash: str
    apk_filename: str
    extraction_timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Feature categories
    manifest: ManifestFeatures
    permissions: PermissionFeatures
    api_calls: APICallFeatures
    code_structure: CodeStructureFeatures
    resources: ResourceFeatures
    certificate: CertificateFeatures
    structural: StructuralFeatures
    
    # Extraction metadata
    extraction_success: bool = True
    extraction_errors: List[str] = Field(default_factory=list)
    extraction_warnings: List[str] = Field(default_factory=list)
    
    def to_flat_dict(self) -> Dict[str, Any]:
        """
        Convert nested features to flat dictionary for CSV/DataFrame.
        
        Returns:
            Flattened feature dictionary
        """
        flat = {
            "apk_hash": self.apk_hash,
            "apk_filename": self.apk_filename,
            "extraction_timestamp": self.extraction_timestamp.isoformat(),
        }
        
        # Flatten manifest features
        for key, value in self.manifest.model_dump().items():
            flat[f"manifest_{key}"] = value
        
        # Flatten permission features
        flat.update(self.permissions.permissions)
        flat["total_permissions"] = self.permissions.total_permissions
        flat["dangerous_count"] = self.permissions.dangerous_count
        
        # Flatten API call features
        flat.update(self.api_calls.api_calls)
        flat["total_sensitive_api_calls"] = self.api_calls.total_sensitive_api_calls
        
        # Flatten code structure features
        for key, value in self.code_structure.model_dump().items():
            flat[f"code_{key}"] = value
        
        # Flatten resource features
        for key, value in self.resources.model_dump().items():
            flat[f"resource_{key}"] = value
        
        # Flatten certificate features
        for key, value in self.certificate.model_dump().items():
            flat[f"cert_{key}"] = value
        
        # Flatten structural features
        for key, value in self.structural.model_dump().items():
            flat[f"struct_{key}"] = value
        
        # Metadata
        flat["extraction_success"] = self.extraction_success
        flat["num_errors"] = len(self.extraction_errors)
        flat["num_warnings"] = len(self.extraction_warnings)
        
        return flat
    
    class Config:
        """Pydantic configuration."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
