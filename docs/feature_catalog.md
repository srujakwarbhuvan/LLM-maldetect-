# APK Feature Catalog

## Overview

This document describes all features extracted by the APK Feature Extraction System.

**Total Features**: ~435 static features

## Feature Categories

### 1. Manifest Features (~30 features)

Features extracted from AndroidManifest.xml:

- **package_name**: Application package identifier
- **version_code**: Numeric version code
- **version_name**: Human-readable version string
- **min_sdk_version**: Minimum Android SDK version
- **target_sdk_version**: Target Android SDK version
- **max_sdk_version**: Maximum SDK version (optional)
- **num_activities**: Number of declared activities
- **num_services**: Number of declared services
- **num_receivers**: Number of broadcast receivers
- **num_providers**: Number of content providers
- **num_exported_activities**: Number of exported activities
- **num_exported_services**: Number of exported services
- **num_exported_receivers**: Number of exported receivers
- **num_exported_providers**: Number of exported providers
- **num_permissions**: Total requested permissions
- **num_dangerous_permissions**: Count of dangerous permissions
- **num_normal_permissions**: Count of normal permissions
- **num_custom_permissions**: Count of custom permissions
- **has_main_activity**: Boolean flag for launcher activity
- **uses_native_code**: Boolean flag for native libraries
- **debuggable**: Application is debuggable
- **allow_backup**: Application allows backup
- **test_only**: Application is marked as test-only

### 2. Permission Features (~70+ binary features)

Binary flags for each Android permission (1 = present, 0 = absent):

- **perm_INTERNET**: Internet access
- **perm_READ_SMS**: Read SMS messages
- **perm_SEND_SMS**: Send SMS messages
- **perm_ACCESS_FINE_LOCATION**: Fine location access
- **perm_CAMERA**: Camera access
- **...**: (70+ more permission flags)

### 3. API Call Features (~100+ binary features)

Binary flags for sensitive API usage:

- **api_sendTextMessage**: SMS sending API
- **api_getLastKnownLocation**: Location API
- **api_DexClassLoader**: Dynamic code loading
- **api_Runtime_exec**: Command execution
- **...**: (100+ more API flags)

### 4. Code Structure Features (~20 features)

- **num_classes**: Total number of classes
- **num_methods**: Total number of methods
- **num_strings**: Total number of strings
- **num_dex_files**: Number of DEX files
- **avg_class_name_length**: Average class name length
- **avg_method_name_length**: Average method name length
- **class_name_entropy**: Shannon entropy of class names
- **method_name_entropy**: Shannon entropy of method names
- **uses_reflection**: Uses reflection APIs
- **reflection_count**: Number of reflection API calls

### 5. Resource Features (~15 features)

- **num_assets**: Number of asset files
- **num_raw_resources**: Number of raw resources
- **num_drawable_resources**: Number of drawables
- **num_layout_resources**: Number of layouts
- **num_xml_resources**: Number of XML files
- **num_native_libs**: Number of native libraries
- **has_arm_libs**: Has ARM libraries
- **has_x86_libs**: Has x86 libraries
- **has_arm64_libs**: Has ARM64 libraries
- **has_x86_64_libs**: Has x86_64 libraries
- **total_files**: Total files in APK

### 6. Certificate Features (~10 features)

- **is_signed**: APK is signed
- **is_self_signed**: Certificate is self-signed
- **signature_algorithm**: Signing algorithm
- **validity_days**: Certificate validity period
- **is_expired**: Certificate has expired
- **issuer_hash**: Hash of issuer (privacy-preserving)
- **subject_hash**: Hash of subject
- **key_size**: Public key size in bits

### 7. Structural Features (~10 features)

- **apk_size_bytes**: APK size in bytes
- **apk_size_mb**: APK size in megabytes
- **dex_size_bytes**: Total DEX size
- **resources_size_bytes**: Total resources size
- **assets_size_bytes**: Total assets size
- **lib_size_bytes**: Total library size
- **compression_ratio**: Compression ratio
- **dex_to_apk_ratio**: DEX size / APK size
- **resources_to_apk_ratio**: Resources size / APK size

## Feature Usage

All features are designed for machine learning model training:

- **Deterministic**: Same APK always produces identical features
- **Type-safe**: All features have well-defined types (int, float, bool, str)
- **ML-ready**: Output in CSV, JSON, or Parquet formats
- **Documented**: Each feature has clear semantic meaning

## Output Formats

### CSV Format
Flat feature vector with one row per APK.

### JSON Format
Hierarchical structure preserving feature categories.

### Parquet Format
Efficient columnar storage for large datasets.

---

**Generated**: 2026-02-13
**Version**: 1.0.0
