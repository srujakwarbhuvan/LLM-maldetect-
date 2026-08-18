# Quick Start Guide

## 🚀 Getting Started

This guide will help you set up and use the APK Feature Extraction System in under 10 minutes.

## Prerequisites

- Python 3.10 or higher
- pip package manager
- ~500MB free disk space for dependencies

## Installation

### 1. Create Virtual Environment

```bash
# Navigate to project directory
cd d:\feature

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
# source venv/bin/activate
```

### 2. Install Dependencies

```bash
# Install the package in development mode
pip install -e .

# Or install from requirements.txt
pip install -r requirements.txt
```

### 3. Setup Directory Structure

```bash
# Run the setup script
python scripts/setup_directories.py
```

This creates:
- `data/input/` - Place your APK files here
- `data/output/` - Extracted features will be saved here
- `data/logs/` - Extraction logs
- `tests/fixtures/` - Test APKs

## Basic Usage

### Option 1: Command Line Interface (CLI)

#### Extract from Single APK

```bash
# Extract features and print to stdout
apk-extract single path/to/app.apk

# Save to JSON file
apk-extract single path/to/app.apk -o output.json

# Save to CSV
apk-extract single path/to/app.apk -o output.csv -f csv
```

#### Batch Extract from Directory

```bash
# Extract from all APKs in a directory
apk-extract batch data/input/ -o data/output/features.csv

# With logging to file
apk-extract batch data/input/ -o features.csv --log-file extraction.log

# With parallel processing (future feature)
apk-extract batch data/input/ -o features.parquet -f parquet -w 4
```

#### Generate Feature Catalog

```bash
# Print catalog to stdout
apk-extract catalog

# Save to markdown file
apk-extract catalog -o docs/feature_catalog.md
```

### Option 2: Python API

#### Single APK Extraction

```python
from pathlib import Path
from apk_extractor import APKFeatureExtractor

# Initialize extractor
extractor = APKFeatureExtractor(log_level="INFO")

# Extract features
features = extractor.extract(Path("path/to/app.apk"))

# Access features
print(f"Package: {features.manifest.package_name}")
print(f"Permissions: {features.permissions.total_permissions}")
print(f"API Calls: {features.api_calls.total_sensitive_api_calls}")

# Save to file
extractor.save_results([features], Path("output.csv"), "csv")
```

#### Batch Extraction

```python
from pathlib import Path
from apk_extractor import APKFeatureExtractor

# Initialize with logging
extractor = APKFeatureExtractor(
    log_level="INFO",
    log_file=Path("extraction.log")
)

# Batch extract
results = extractor.batch_extract(
    apk_dir=Path("data/input/"),
    output_file=Path("data/output/features.csv"),
    output_format="csv"
)

# Print summary
print(f"Processed {len(results)} APKs")
for result in results[:5]:  # First 5
    print(f"  {result.manifest.package_name}: {result.permissions.total_permissions} perms")
```

### Option 3: Example Scripts

We provide ready-to-use example scripts:

```bash
# Single APK extraction example
python scripts/example_single_apk.py

# Batch extraction example
python scripts/example_batch_extract.py
```

## Output Formats

### CSV Format (Recommended for ML)

```csv
apk_hash,package_name,version_code,perm_INTERNET,api_sendTextMessage,...
abc123,com.example.app,42,1,0,...
```

**Use case**: Machine learning model training, data analysis

### JSON Format (Recommended for Inspection)

```json
{
  "apk_hash": "abc123...",
  "manifest": {
    "package_name": "com.example.app",
    "version_code": 42
  },
  "permissions": {...},
  "api_calls": {...}
}
```

**Use case**: Detailed inspection, debugging, human-readable output

### Parquet Format (Recommended for Big Data)

Binary columnar format optimized for:
- Large datasets (>10,000 APKs)
- Fast querying
- Efficient storage (50-80% smaller than CSV)

## Understanding the Output

### Feature Categories

Each APK produces ~435 features across 7 categories:

1. **Manifest** (~30): Package info, SDK versions, components
2. **Permissions** (~70): Binary flags for each Android permission
3. **API Calls** (~100): Sensitive API usage patterns
4. **Code Structure** (~20): Classes, methods, obfuscation indicators
5. **Resources** (~15): Assets, native libraries
6. **Certificate** (~10): Signing information
7. **Structural** (~10): File sizes, compression metrics

### Sample Output (CSV)

```
apk_hash                        | abc123def456...
package_name                    | com.example.myapp
version_code                    | 42
manifest_min_sdk_version        | 21
manifest_target_sdk_version     | 33
perm_INTERNET                   | 1
perm_READ_SMS                   | 0
perm_CAMERA                     | 1
api_sendTextMessage             | 0
api_getLastKnownLocation        | 1
code_num_classes                | 2547
code_num_methods                | 18432
struct_apk_size_mb              | 45.3
cert_is_signed                  | true
```

## Common Workflows

### Workflow 1: Malware Dataset Creation

```bash
# 1. Collect APKs in data/input/
# 2. Run batch extraction
apk-extract batch data/input/ -o malware_features.csv

# 3. Load in Python for ML
import pandas as pd
df = pd.read_csv('malware_features.csv')

# 4. Train model
from sklearn.ensemble import RandomForestClassifier
# ... your ML code
```

### Workflow 2: Single APK Analysis

```bash
# Extract features
apk-extract single suspicious.apk -o analysis.json -f json

# Review in editor or with jq
cat analysis.json | jq '.permissions'
```

### Workflow 3: Comparative Analysis

```python
# Extract features from multiple APKs
extractor = APKFeatureExtractor()

app1 = extractor.extract(Path("app_v1.apk"))
app2 = extractor.extract(Path("app_v2.apk"))

# Compare
print(f"Permissions v1: {app1.permissions.total_permissions}")
print(f"Permissions v2: {app2.permissions.total_permissions}")
print(f"New APIs: {app2.api_calls.total_sensitive_api_calls - app1.api_calls.total_sensitive_api_calls}")
```

## Troubleshooting

### Issue: "androguard not found"

```bash
# Reinstall dependencies
pip install -r requirements.txt
```

### Issue: "APK validation failed"

- Ensure the file is a valid APK (ZIP archive)
- Check file is not corrupted
- Verify file size > 1KB

### Issue: "Extraction takes too long"

- Large APKs (>100MB) can take 30-60 seconds
- Use parallel processing (future feature)
- Enable only necessary extractors in config (future feature)

### Issue: "Memory error on large APKs"

- Increase available RAM
- Process APKs in smaller batches
- Use parquet format for output

## Next Steps

1. **Read the full documentation**: `docs/feature_catalog.md`
2. **Explore example scripts**: `scripts/example_*.py`
3. **Run tests**: `pytest tests/`
4. **Customize extractors**: Extend `BaseExtractor` class
5. **Integrate with ML pipeline**: Use CSV/Parquet output

## Support

- **Documentation**: See `docs/` directory
- **Examples**: See `scripts/` directory
- **Issues**: Open GitHub issue
- **Questions**: Check implementation plan (`IMPLEMENTATION_PLAN.md`)

## Tips for Best Results

1. **Determinism**: Always produces same features for same APK
2. **Quality**: Check `extraction_success` flag in output
3. **Logging**: Use `--log-level DEBUG` for detailed diagnostics
4. **Batch Size**: Process 100-1000 APKs per batch for optimal performance
5. **Output Format**: Use CSV for ML, JSON for inspection, Parquet for big data

---

**Ready to extract features? Start with:**

```bash
# Place an APK in data/input/
# Then run:
apk-extract batch data/input/ -o features.csv
```

Good luck! 🚀
