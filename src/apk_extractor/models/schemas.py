"""Schema definitions for feature catalog."""

from typing import List, Optional, Literal
from pydantic import BaseModel, Field
from enum import Enum


class FeatureType(str, Enum):
    """Feature data types."""
    BINARY = "binary"           # 0 or 1
    INTEGER = "integer"         # Whole numbers
    FLOAT = "float"             # Decimal numbers
    STRING = "string"           # Text
    BOOLEAN = "boolean"         # True/False
    CATEGORICAL = "categorical" # Fixed set of values


class FeatureCategory(str, Enum):
    """Feature category groupings."""
    MANIFEST = "manifest"
    PERMISSION = "permission"
    API_CALL = "api_call"
    CODE_STRUCTURE = "code_structure"
    RESOURCE = "resource"
    CERTIFICATE = "certificate"
    STRUCTURAL = "structural"
    METADATA = "metadata"


class FeatureDefinition(BaseModel):
    """Definition of a single feature."""
    
    name: str = Field(..., description="Feature name (column name in output)")
    category: FeatureCategory
    feature_type: FeatureType
    description: str
    
    # Optional constraints
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    possible_values: Optional[List[str]] = None
    
    # Missing value handling
    missing_value_strategy: Literal["zero", "negative_one", "mean", "null"] = "zero"
    
    # Importance
    importance: Literal["critical", "high", "medium", "low"] = "medium"
    
    # Examples
    example_value: Optional[str] = None


class FeatureCatalog(BaseModel):
    """Complete catalog of features."""
    
    version: str = "1.0.0"
    total_features: int
    features: List[FeatureDefinition]
    
    def get_by_category(self, category: FeatureCategory) -> List[FeatureDefinition]:
        """Get all features in a category."""
        return [f for f in self.features if f.category == category]
    
    def get_by_type(self, feature_type: FeatureType) -> List[FeatureDefinition]:
        """Get all features of a specific type."""
        return [f for f in self.features if f.feature_type == feature_type]
    
    def get_feature_names(self) -> List[str]:
        """Get list of all feature names."""
        return [f.name for f in self.features]
