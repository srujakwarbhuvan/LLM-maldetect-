"""Example script: Extract features from a single APK."""

from pathlib import Path
from apk_extractor import APKFeatureExtractor

def main():
    # Initialize extractor
    extractor = APKFeatureExtractor(log_level="INFO")
    
    # Path to APK file
    apk_path = Path("data/input/sample.apk")
    
    if not apk_path.exists():
        print(f"Error: APK file not found at {apk_path}")
        print("Please place an APK file at data/input/sample.apk")
        return
    
    # Extract features
    print(f"Extracting features from {apk_path.name}...")
    features = extractor.extract(apk_path)
    
    if features:
        print("\n✓ Extraction successful!")
        print(f"\nPackage: {features.manifest.package_name}")
        print(f"Version: {features.manifest.version_name}")
        print(f"Permissions: {features.permissions.total_permissions}")
        print(f"API Calls: {features.api_calls.total_sensitive_api_calls}")
        print(f"Classes: {features.code_structure.num_classes}")
        print(f"Methods: {features.code_structure.num_methods}")
        print(f"Size: {features.structural.apk_size_mb} MB")
        
        # Save to JSON
        output_path = Path("data/output/sample_features.json")
        extractor.save_results([features], output_path, "json")
        print(f"\n✓ Features saved to {output_path}")
    else:
        print("\n✗ Extraction failed!")

if __name__ == "__main__":
    main()
