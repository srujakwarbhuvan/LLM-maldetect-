"""Command-line interface for APK Feature Extractor."""

import click
from pathlib import Path
from rich.console import Console
from rich.table import Table
from apk_extractor.pipeline import APKFeatureExtractor
from apk_extractor import __version__

console = Console()


@click.group()
@click.version_option(version=__version__)
def cli():
    """APK Static Feature Extraction System for Malware Detection."""
    pass


@cli.command()
@click.argument('apk_path', type=click.Path(exists=True))
@click.option('-o', '--output', type=click.Path(), help='Output file path')
@click.option('-f', '--format', type=click.Choice(['csv', 'json', 'parquet']), default='json', help='Output format')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']), default='INFO', help='Logging level')
def single(apk_path, output, format, log_level):
    """Extract features from a single APK file."""
    console.print(f"[bold blue]Extracting features from:[/bold blue] {apk_path}")
    
    # Initialize extractor
    extractor = APKFeatureExtractor(log_level=log_level)
    
    # Extract features
    features = extractor.extract(Path(apk_path))
    
    if not features:
        console.print("[bold red]✗ Extraction failed![/bold red]")
        return 1
    
    # Display summary
    console.print("[bold green]✓ Extraction successful![/bold green]")
    _display_feature_summary(features)
    
    # Save to file if specified
    if output:
        extractor.save_results([features], Path(output), format)
        console.print(f"[bold green]✓ Results saved to:[/bold green] {output}")
    else:
        # Print JSON to stdout
        import json
        console.print(json.dumps(features.model_dump(), indent=2, default=str))
    
    return 0


@cli.command()
@click.argument('apk_dir', type=click.Path(exists=True))
@click.option('-o', '--output', required=True, type=click.Path(), help='Output file path')
@click.option('-f', '--format', type=click.Choice(['csv', 'json', 'parquet']), default='csv', help='Output format')
@click.option('-w', '--workers', type=int, default=1, help='Number of parallel workers')
@click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']), default='INFO', help='Logging level')
@click.option('--log-file', type=click.Path(), help='Log file path')
def batch(apk_dir, output, format, workers, log_level, log_file):
    """Extract features from multiple APK files in a directory."""
    console.print(f"[bold blue]Batch extraction from:[/bold blue] {apk_dir}")
    
    # Initialize extractor
    log_file_path = Path(log_file) if log_file else None
    extractor = APKFeatureExtractor(log_level=log_level, log_file=log_file_path)
    
    # Batch extract
    results = extractor.batch_extract(
        apk_dir=Path(apk_dir),
        output_file=Path(output),
        output_format=format,
        workers=workers,
    )
    
    # Display summary
    console.print(f"\n[bold green]✓ Batch extraction completed![/bold green]")
    console.print(f"Total APKs processed: {len(results)}")
    console.print(f"Results saved to: {output}")
    
    return 0


@cli.command()
@click.option('-o', '--output', type=click.Path(), help='Output markdown file')
def catalog(output):
    """Generate feature catalog documentation."""
    console.print("[bold blue]Generating feature catalog...[/bold blue]")
    
    from apk_extractor.extractors import (
        ManifestExtractor,
        PermissionExtractor,
        APIExtractor,
    )
    
    # Create catalog content
    catalog_md = _generate_catalog_markdown()
    
    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(catalog_md)
        console.print(f"[bold green]✓ Catalog saved to:[/bold green] {output}")
    else:
        console.print(catalog_md)
    
    return 0


def _display_feature_summary(features):
    """Display a summary table of extracted features."""
    table = Table(title="Feature Summary")
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right", style="magenta")
    
    # Manifest features
    table.add_row("Manifest Features", "30+")
    table.add_row("  - Package", features.manifest.package_name)
    table.add_row("  - Version Code", str(features.manifest.version_code))
    table.add_row("  - Min SDK", str(features.manifest.min_sdk_version))
    table.add_row("  - Target SDK", str(features.manifest.target_sdk_version))
    
    # Permissions
    table.add_row("Permissions", str(features.permissions.total_permissions))
    table.add_row("  - Dangerous", str(features.permissions.dangerous_count))
    table.add_row("  - Normal", str(features.permissions.normal_count))
    
    # API calls
    table.add_row("Sensitive APIs", str(features.api_calls.total_sensitive_api_calls))
    
    # Code structure
    table.add_row("Code Structure", "")
    table.add_row("  - Classes", str(features.code_structure.num_classes))
    table.add_row("  - Methods", str(features.code_structure.num_methods))
    table.add_row("  - DEX Files", str(features.code_structure.num_dex_files))
    
    # Resources
    table.add_row("Resources", "")
    table.add_row("  - Native Libs", str(features.resources.num_native_libs))
    table.add_row("  - Total Files", str(features.resources.total_files))
    
    # Structural
    table.add_row("Structural", "")
    table.add_row("  - APK Size", f"{features.structural.apk_size_mb} MB")
    table.add_row("  - Compression", f"{features.structural.compression_ratio:.2%}")
    
    console.print(table)


def _generate_catalog_markdown():
    """Generate feature catalog markdown."""
    md = """# APK Feature Catalog

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
"""
    return md


if __name__ == '__main__':
    cli()
