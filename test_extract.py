from pathlib import Path
from apk_extractor import APKFeatureExtractor
import sys

# Get any APK file from the input directory
apk_dir = Path("data/input")
apk_files = list(apk_dir.glob("*.apk"))

if not apk_files:
    print(f"No APK files found in {apk_dir}!")
    sys.exit(1)

target_apk = apk_files[0]
print(f"Extracting features from: {target_apk.name}...")

# Initialize
extractor = APKFeatureExtractor(log_level="INFO")

# Extract
features = extractor.extract(target_apk)

# Print results
if features:
    print(f"\n--- Extraction Successful ---")
    print(f"Package: {features.manifest.package_name}")
    print(f"Permissions: {features.permissions.total_permissions}")
    print(f"API Calls: {features.api_calls.total_sensitive_api_calls}")
    print(f"Size: {features.structural.apk_size_mb} MB")
else:
    print("Extraction failed.")